# Multi-Firewall Traffic Path Discovery & Integration

## Overview

Yes, Nautobot + custom integrations can locate multiple firewalls along a traffic path and correlate rule impacts across the entire path. This document covers:

1. **Traffic path discovery mechanisms** (traceroute, NetFlow, topology mapping)
2. **Multi-device change correlation** (rule impact across firewall pairs)
3. **End-to-end rule analysis** (identify blocking points, policy gaps)
4. **Rule shadowing detection** (earlier rules preventing later rules from matching)
5. **Implementation patterns** (graph-based topology, change chaining)

---

## Part 1: Network Topology Discovery & Firewall Mapping

### 1.1 Architecture for Multi-Firewall Tracking

```
┌─────────────────────────────────────────────────────────────────┐
│                    Source Host                                   │
│                  (e.g., 10.1.1.100)                              │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│            Firewall 1 (Border/Egress)                            │
│  Management IP: 203.0.113.1                                      │
│  Interfaces: Gi0/0 (10.1.1.0/24), Gi0/1 (203.0.113.0/24)        │
│  Rules: Block RFC1918 egress, allow HTTPS only                  │
└─────────────────┬───────────────────────────────────────────────┘
                  │
     WAN (203.0.113.0/24) - Internet
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│            Firewall 2 (DMZ Boundary)                             │
│  Management IP: 192.168.1.1                                      │
│  Interfaces: Gi0/0 (203.0.113.0/24), Gi0/1 (192.168.100.0/24)   │
│  Rules: Allow HTTP/HTTPS to web servers, log all                │
└─────────────────┬───────────────────────────────────────────────┘
                  │
    DMZ (192.168.100.0/24)
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│            Destination Host                                       │
│         (e.g., 192.168.100.50 - Web Server)                     │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Device Topology Model in Nautobot

```python
# Extended models.py - Add topology relationships

from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from nautobot.core.models import BaseModel

class NetworkInterface(BaseModel):
    """Firewall interface tracking"""
    device = models.ForeignKey('FirewallDevice', on_delete=models.CASCADE, related_name='interfaces')
    name = models.CharField(max_length=50)  # Gi0/0, Eth0, etc.
    ip_address = models.GenericIPAddressField()
    cidr_prefix = models.IntegerField()  # /24, /25, etc.
    zone = models.CharField(
        max_length=50,
        choices=[
            ('untrust', 'Untrust/WAN'),
            ('trust', 'Trust/LAN'),
            ('dmz', 'DMZ'),
            ('management', 'Management'),
            ('guest', 'Guest'),
            ('backup', 'Backup'),
        ]
    )
    enabled = models.BooleanField(default=True)
    mtu = models.IntegerField(default=1500)
    
    class Meta:
        unique_together = ('device', 'name')
    
    def __str__(self):
        return f"{self.device.name}:{self.name} ({self.ip_address}/{self.cidr_prefix})"


class NetworkPath(BaseModel):
    """Define traffic path through network"""
    name = models.CharField(max_length=100)  # "Office->AWS", "Office->SaaS", etc.
    source_zone = models.CharField(max_length=50)
    destination_zone = models.CharField(max_length=50)
    source_network = models.CharField(max_length=100)  # CIDR or network object
    dest_network = models.CharField(max_length=100)
    
    class Meta:
        unique_together = ('source_zone', 'destination_zone', 'source_network', 'dest_network')
    
    def __str__(self):
        return f"{self.name} ({self.source_network} -> {self.dest_network})"


class PathFirewallStep(BaseModel):
    """Firewall along a traffic path (ordered)"""
    path = models.ForeignKey(NetworkPath, on_delete=models.CASCADE, related_name='firewall_steps')
    firewall_device = models.ForeignKey('FirewallDevice', on_delete=models.CASCADE)
    ingress_interface = models.ForeignKey(
        NetworkInterface,
        on_delete=models.SET_NULL,
        null=True,
        related_name='inbound_paths'
    )
    egress_interface = models.ForeignKey(
        NetworkInterface,
        on_delete=models.SET_NULL,
        null=True,
        related_name='outbound_paths'
    )
    order = models.IntegerField()  # 1st firewall, 2nd firewall, etc.
    
    class Meta:
        ordering = ['path', 'order']
        unique_together = ('path', 'order')
    
    def __str__(self):
        return f"{self.path.name} - Step {self.order}: {self.firewall_device.name}"


class ApplicableRule(BaseModel):
    """Link change to paths/zones it affects"""
    change = models.ForeignKey('FirewallChange', on_delete=models.CASCADE, related_name='applicable_rules')
    rule = models.ForeignKey('FirewallRule', on_delete=models.CASCADE)
    
    # Which paths does this rule affect?
    affected_paths = models.ManyToManyField(NetworkPath, blank=True)
    affected_zones = models.ManyToManyField('Zone', blank=True)
    
    # Impact assessment
    is_blocking = models.BooleanField(default=False)  # Does it deny traffic?
    is_permitting = models.BooleanField(default=False)  # Does it allow traffic?
    blocks_path = models.BooleanField(default=False)  # Does it completely block a path?
    
    class Meta:
        unique_together = ('change', 'rule')


class Zone(BaseModel):
    """Security zones (trust domains)"""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    security_level = models.IntegerField(
        choices=[(1, 'Untrust'), (2, 'Guest'), (3, 'DMZ'), (4, 'Trust')],
        default=1
    )
    
    def __str__(self):
        return self.name


class RuleTraversalAnalysis(BaseModel):
    """Results of analyzing traffic through multiple firewalls"""
    path = models.ForeignKey(NetworkPath, on_delete=models.CASCADE)
    analysis_timestamp = models.DateTimeField(auto_now_add=True)
    
    # Overall verdict
    traffic_allowed = models.BooleanField(null=True)  # True/False/None (indeterminate)
    blocking_firewall = models.ForeignKey(
        'FirewallDevice',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='blocking_analyses'
    )
    blocking_rule = models.ForeignKey(
        'FirewallRule',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    
    # Details
    analysis_report = models.JSONField()  # Full step-by-step analysis
    warnings = models.JSONField(default=list)  # Rule shadowing, conflicts, etc.
    
    def __str__(self):
        return f"{self.path.name} - {self.analysis_timestamp}"
```

---

## Part 2: Topology Discovery Methods

### 2.1 Automated Topology Discovery from Firewalls

```python
# topology_discoverer.py

import netaddr
from typing import Dict, List, Tuple
from .models import FirewallDevice, NetworkInterface, Zone, NetworkPath, PathFirewallStep
import logging

logger = logging.getLogger(__name__)

class TopologyDiscoverer:
    """Automatically map firewall topology from device configs"""
    
    def __init__(self):
        self.devices = {}
        self.zones = {}
        self.paths = {}
    
    def discover_all(self):
        """Discover topology from all enabled firewalls"""
        
        for device in FirewallDevice.objects.filter(enabled=True):
            self.discover_device_interfaces(device)
        
        self._map_interconnections()
        self._identify_traffic_paths()
    
    def discover_device_interfaces(self, device: FirewallDevice):
        """Extract interfaces and zones from device"""
        
        collector_class = self._get_collector(device.device_type)
        collector = collector_class({
            'management_ip': device.management_ip,
            'api_username': device.api_username,
            'api_password': device.api_password,
            'api_key': device.api_key,
        })
        
        if not collector.connect():
            logger.error(f"Failed to connect to {device.name}")
            return
        
        # Get interfaces (vendor-specific)
        interfaces = self._parse_interfaces(device, collector)
        zones = self._parse_zones(device, collector)
        
        for zone_name, zone_config in zones.items():
            zone_obj, _ = Zone.objects.get_or_create(name=zone_name)
            self.zones[zone_name] = zone_obj
        
        for iface in interfaces:
            NetworkInterface.objects.update_or_create(
                device=device,
                name=iface['name'],
                defaults={
                    'ip_address': iface['ip'],
                    'cidr_prefix': iface['prefix'],
                    'zone': iface['zone'],
                    'enabled': iface['enabled'],
                }
            )
        
        logger.info(f"✓ Discovered {len(interfaces)} interfaces on {device.name}")
    
    def _parse_interfaces(self, device: FirewallDevice, collector) -> List[Dict]:
        """Extract interfaces from device config"""
        
        if device.device_type == 'palo_alto':
            return self._parse_pan_interfaces(collector)
        elif device.device_type == 'cisco_asa':
            return self._parse_asa_interfaces(collector)
        elif device.device_type == 'cisco_nexus':
            return self._parse_nexus_interfaces(collector)
        else:
            return []
    
    def _parse_pan_interfaces(self, collector) -> List[Dict]:
        """Palo Alto interface parsing"""
        import xml.etree.ElementTree as ET
        
        config = collector.get_full_config()
        root = ET.fromstring(config)
        
        interfaces = []
        xpath = './/interface/ethernet/entry'
        
        for iface_elem in root.findall(xpath):
            iface_name = iface_elem.get('name')
            
            # Get IP config
            ip_elem = iface_elem.find('.//ip/entry')
            if ip_elem is not None:
                ip_str = ip_elem.get('name')  # "192.168.1.1/24"
                if ip_str:
                    try:
                        ip_net = netaddr.IPNetwork(ip_str)
                        interfaces.append({
                            'name': iface_name,
                            'ip': str(ip_net.ip),
                            'prefix': ip_net.prefixlen,
                            'zone': self._infer_zone_from_name(iface_name),
                            'enabled': True,
                        })
                    except:
                        pass
        
        return interfaces
    
    def _parse_asa_interfaces(self, collector) -> List[Dict]:
        """Cisco ASA interface parsing"""
        
        config = collector.get_full_config()
        interfaces = []
        
        for line in config.split('\n'):
            if line.startswith('interface '):
                iface_name = line.split()[1]
                
                # Find IP address in next lines
                for next_line in config.split('\n')[config.split('\n').index(line):]:
                    if 'ip address' in next_line:
                        parts = next_line.strip().split()
                        if len(parts) >= 4:
                            ip = parts[2]
                            netmask = parts[3]
                            prefix = netaddr.IPAddress(netmask).netmask_bits()
                            
                            interfaces.append({
                                'name': iface_name,
                                'ip': ip,
                                'prefix': prefix,
                                'zone': self._infer_zone_from_name(iface_name),
                                'enabled': True,
                            })
                        break
        
        return interfaces
    
    def _parse_zones(self, device: FirewallDevice, collector) -> Dict[str, Dict]:
        """Extract security zones from device"""
        
        if device.device_type == 'palo_alto':
            return self._parse_pan_zones(collector)
        else:
            # For devices without explicit zones, infer from interfaces
            return self._infer_zones()
    
    def _parse_pan_zones(self, collector) -> Dict:
        """Palo Alto zone extraction"""
        import xml.etree.ElementTree as ET
        
        config = collector.get_full_config()
        root = ET.fromstring(config)
        
        zones = {}
        xpath = './/zone/entry'
        
        for zone_elem in root.findall(xpath):
            zone_name = zone_elem.get('name')
            zone_type = zone_elem.findtext('.//type')
            
            zones[zone_name] = {
                'type': zone_type,
                'description': zone_elem.findtext('.//description', ''),
            }
        
        return zones
    
    def _infer_zone_from_name(self, interface_name: str) -> str:
        """Guess zone from interface name/config"""
        
        name_lower = interface_name.lower()
        
        if any(x in name_lower for x in ['wan', 'public', 'internet', 'outside']):
            return 'untrust'
        elif any(x in name_lower for x in ['lan', 'inside', 'trust', 'internal']):
            return 'trust'
        elif 'dmz' in name_lower:
            return 'dmz'
        elif 'guest' in name_lower:
            return 'guest'
        else:
            return 'trust'
    
    def _infer_zones(self) -> Dict:
        """Create zones if not explicitly defined"""
        return {
            'untrust': {'type': 'external', 'description': 'Untrusted'},
            'trust': {'type': 'internal', 'description': 'Trusted'},
            'dmz': {'type': 'internal', 'description': 'DMZ'},
        }
    
    def _map_interconnections(self):
        """Identify which firewalls are connected (same subnets)"""
        
        from django.db.models import Q
        
        # Find interfaces with overlapping IP ranges
        all_interfaces = NetworkInterface.objects.all()
        
        for iface1 in all_interfaces:
            net1 = netaddr.IPNetwork(f"{iface1.ip_address}/{iface1.cidr_prefix}")
            
            for iface2 in all_interfaces:
                if iface1.device == iface2.device:
                    continue
                
                net2 = netaddr.IPNetwork(f"{iface2.ip_address}/{iface2.cidr_prefix}")
                
                # Same subnet = connected
                if net1.network == net2.network:
                    logger.info(f"Found connection: {iface1.device.name} <-> {iface2.device.name}")
    
    def _identify_traffic_paths(self):
        """Automatically identify traffic paths through firewalls"""
        
        # Simple heuristic: Create paths for common scenarios
        # In production, you'd scan for actual traffic or use manual input
        
        devices = list(FirewallDevice.objects.all())
        
        if len(devices) >= 2:
            # Create path: Trust -> Untrust (typical outbound)
            self._create_path_between_zones('trust', 'untrust', 'Office_to_Internet')
            
            # Create path: Untrust -> DMZ (typical inbound)
            self._create_path_between_zones('untrust', 'dmz', 'Internet_to_DMZ')
            
            # Create path: Trust -> DMZ
            self._create_path_between_zones('trust', 'dmz', 'Office_to_DMZ')
    
    def _create_path_between_zones(self, source_zone: str, dest_zone: str, path_name: str):
        """Create a NetworkPath between zones"""
        
        # Find devices handling each zone
        source_devices = NetworkInterface.objects.filter(zone=source_zone).values_list('device', flat=True).distinct()
        dest_devices = NetworkInterface.objects.filter(zone=dest_zone).values_list('device', flat=True).distinct()
        
        if source_devices and dest_devices:
            path, created = NetworkPath.objects.get_or_create(
                name=path_name,
                source_zone=source_zone,
                destination_zone=dest_zone,
                source_network='0.0.0.0/0',  # Generic
                dest_network='0.0.0.0/0',
            )
            
            if created:
                logger.info(f"Created path: {path_name}")
```

---

## Part 3: Multi-Firewall Rule Analysis

### 3.1 Rule Traversal Engine

```python
# rule_traversal.py

from typing import List, Dict, Tuple, Optional
from netaddr import IPNetwork, IPAddress
from .models import (
    FirewallDevice, FirewallRule, NetworkPath, PathFirewallStep,
    RuleTraversalAnalysis, ApplicableRule
)
import logging

logger = logging.getLogger(__name__)

class RuleTraversalAnalyzer:
    """Analyze traffic through multiple firewalls"""
    
    def __init__(self, path: NetworkPath):
        self.path = path
        self.firewall_steps = PathFirewallStep.objects.filter(path=path).order_by('order')
        self.analysis_report = {
            'path': path.name,
            'steps': [],
            'overall_result': None,
        }
    
    def analyze(self) -> RuleTraversalAnalysis:
        """Perform end-to-end rule traversal"""
        
        logger.info(f"Analyzing path: {self.path.name}")
        
        # Extract source and destination networks
        src_net = IPNetwork(self.path.source_network)
        dst_net = IPNetwork(self.path.dest_network)
        
        blocked = False
        blocking_device = None
        blocking_rule = None
        
        # Traverse each firewall in order
        for step in self.firewall_steps:
            step_analysis = self._analyze_firewall_step(
                step, src_net, dst_net, blocked
            )
            
            self.analysis_report['steps'].append(step_analysis)
            
            if step_analysis['verdict'] == 'BLOCKED':
                blocked = True
                blocking_device = step.firewall_device
                blocking_rule = self._find_blocking_rule(step.firewall_device, step_analysis)
                
                logger.warning(
                    f"Traffic blocked at {step.firewall_device.name}: "
                    f"Rule '{step_analysis['blocking_rule']}'"
                )
            
            elif step_analysis['verdict'] == 'ALLOWED':
                logger.info(f"Traffic allowed by {step.firewall_device.name}")
        
        # Determine overall result
        self.analysis_report['overall_result'] = 'BLOCKED' if blocked else 'ALLOWED'
        
        # Store analysis in database
        analysis = RuleTraversalAnalysis.objects.create(
            path=self.path,
            traffic_allowed=not blocked,
            blocking_firewall=blocking_device,
            blocking_rule=blocking_rule,
            analysis_report=self.analysis_report,
            warnings=self._detect_warnings(),
        )
        
        logger.info(f"Analysis complete: {self.analysis_report['overall_result']}")
        return analysis
    
    def _analyze_firewall_step(
        self, step: PathFirewallStep, src_net: IPNetwork, dst_net: IPNetwork, already_blocked: bool
    ) -> Dict:
        """Analyze rules on a single firewall for this traffic"""
        
        device = step.firewall_device
        
        step_report = {
            'device': device.name,
            'rules_evaluated': [],
            'verdict': 'INDETERMINATE',
            'blocking_rule': None,
        }
        
        # Get all security rules for this firewall
        rules = FirewallRule.objects.filter(
            device=device
        ).order_by('sequence_number')
        
        # Evaluate rules in order (until we hit an explicit deny or allow)
        for rule in rules:
            if rule.disabled:
                step_report['rules_evaluated'].append({
                    'rule_id': rule.rule_id,
                    'name': rule.rule_name,
                    'status': 'DISABLED',
                })
                continue
            
            # Check if traffic matches rule
            is_match = self._rule_matches_traffic(rule, src_net, dst_net)
            
            step_report['rules_evaluated'].append({
                'rule_id': rule.rule_id,
                'name': rule.rule_name,
                'matches': is_match,
                'action': rule.action,
                'logging': rule.logging_enabled,
            })
            
            if is_match:
                if rule.action in ['deny', 'drop', 'reject']:
                    step_report['verdict'] = 'BLOCKED'
                    step_report['blocking_rule'] = rule.rule_name
                    logger.info(f"  ✗ Rule '{rule.rule_name}' blocks traffic")
                    break
                
                elif rule.action == 'allow':
                    step_report['verdict'] = 'ALLOWED'
                    step_report['allowing_rule'] = rule.rule_name
                    logger.info(f"  ✓ Rule '{rule.rule_name}' allows traffic")
                    break
        
        # Default action if no explicit rule matched
        if step_report['verdict'] == 'INDETERMINATE':
            default_action = device.default_action if hasattr(device, 'default_action') else 'deny'
            step_report['verdict'] = 'ALLOWED' if default_action == 'allow' else 'BLOCKED'
            step_report['blocking_rule'] = f"Default action: {default_action}"
        
        return step_report
    
    def _rule_matches_traffic(self, rule: FirewallRule, src_net: IPNetwork, dst_net: IPNetwork) -> bool:
        """Determine if traffic matches rule"""
        
        # Check source
        if rule.source_ips:
            src_match = any(
                self._ip_in_range(src_net.ip, src_range)
                for src_range in rule.source_ips
            )
            if not src_match:
                return False
        
        # Check destination
        if rule.dest_ips:
            dst_match = any(
                self._ip_in_range(dst_net.ip, dst_range)
                for dst_range in rule.dest_ips
            )
            if not dst_match:
                return False
        
        # Check zones (if available)
        if rule.source_zones and rule.dest_zones:
            # Would need to map zones - simplified here
            pass
        
        return True
    
    def _ip_in_range(self, ip: IPAddress, cidr_string: str) -> bool:
        """Check if IP is in CIDR range"""
        
        try:
            if cidr_string == 'any':
                return True
            
            network = IPNetwork(cidr_string)
            return IPAddress(ip) in network
        except:
            return False
    
    def _find_blocking_rule(self, device: FirewallDevice, step_analysis: Dict) -> Optional[FirewallRule]:
        """Find the actual rule object that blocks traffic"""
        
        rule_name = step_analysis.get('blocking_rule')
        if not rule_name:
            return None
        
        return FirewallRule.objects.filter(
            device=device,
            rule_name=rule_name
        ).first()
    
    def _detect_warnings(self) -> List[str]:
        """Detect rule shadowing, conflicts, etc."""
        
        warnings = []
        
        # Check for rule shadowing (earlier rule prevents later rule from matching)
        for step in self.firewall_steps:
            shadowing = self._check_rule_shadowing(step.firewall_device)
            warnings.extend(shadowing)
        
        # Check for redundant rules
        for step in self.firewall_steps:
            redundancy = self._check_redundant_rules(step.firewall_device)
            warnings.extend(redundancy)
        
        return warnings
    
    def _check_rule_shadowing(self, device: FirewallDevice) -> List[str]:
        """Detect if rules shadow (make unreachable) later rules"""
        
        warnings = []
        rules = FirewallRule.objects.filter(device=device).order_by('sequence_number')
        
        for i, rule1 in enumerate(rules):
            if rule1.action != 'allow':
                continue
            
            # Check if any earlier rule with allow action covers same traffic
            for rule2 in rules[:i]:
                if rule2.action == 'allow':
                    if self._rules_overlap(rule1, rule2):
                        warnings.append(
                            f"Rule shadowing on {device.name}: "
                            f"'{rule2.rule_name}' makes '{rule1.rule_name}' unreachable"
                        )
        
        return warnings
    
    def _check_redundant_rules(self, device: FirewallDevice) -> List[str]:
        """Detect duplicate or redundant rules"""
        
        warnings = []
        rules = FirewallRule.objects.filter(device=device)
        
        seen = {}
        for rule in rules:
            rule_key = (
                tuple(sorted(rule.source_ips)),
                tuple(sorted(rule.dest_ips)),
                tuple(sorted(rule.services)),
                rule.action,
            )
            
            if rule_key in seen:
                warnings.append(
                    f"Redundant rule on {device.name}: "
                    f"'{rule.rule_name}' duplicates '{seen[rule_key]}'"
                )
            else:
                seen[rule_key] = rule.rule_name
        
        return warnings
    
    def _rules_overlap(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if two rules cover overlapping traffic"""
        
        # Simplified check: if all conditions overlap, rules overlap
        src_overlap = self._ranges_overlap(rule1.source_ips, rule2.source_ips)
        dst_overlap = self._ranges_overlap(rule1.dest_ips, rule2.dest_ips)
        
        return src_overlap and dst_overlap
    
    def _ranges_overlap(self, ranges1: List[str], ranges2: List[str]) -> bool:
        """Check if IP ranges overlap"""
        
        if not ranges1 or not ranges2:
            return True  # Any matches Any
        
        for r1 in ranges1:
            net1 = IPNetwork(r1)
            for r2 in ranges2:
                net2 = IPNetwork(r2)
                if net1.overlaps(net2):
                    return True
        
        return False
```

---

## Part 4: Change Impact Across Multiple Firewalls

### 4.1 Multi-Firewall Change Correlation

```python
# multi_firewall_impact.py

from typing import List, Dict
from django.db.models import Q
from .models import (
    FirewallChange, FirewallDevice, NetworkPath, PathFirewallStep,
    RuleTraversalAnalysis, ApplicableRule
)
from .rule_traversal import RuleTraversalAnalyzer
import logging

logger = logging.getLogger(__name__)

class MultiFirewallImpactAnalyzer:
    """Analyze change impact across multiple firewalls"""
    
    def __init__(self, change: FirewallChange):
        self.change = change
        self.device = change.device
        self.affected_paths = []
        self.impact_summary = {
            'device': self.device.name,
            'change': {
                'type': change.get_change_type_display(),
                'rule': change.rule_name,
                'severity': change.severity,
            },
            'paths_affected': [],
            'blocking_chains': [],
            'policy_gaps': [],
            'recommendations': [],
        }
    
    def analyze(self) -> Dict:
        """Analyze impact of change across all paths"""
        
        logger.info(f"Analyzing impact of change on {self.device.name}")
        
        # Find all paths that traverse this device
        affected_paths = self._find_affected_paths()
        
        for path in affected_paths:
            # Re-analyze path with new change
            analyzer = RuleTraversalAnalyzer(path)
            old_analysis = self._get_last_analysis(path)
            new_analysis = analyzer.analyze()
            
            path_impact = {
                'path': path.name,
                'old_verdict': old_analysis.traffic_allowed if old_analysis else None,
                'new_verdict': new_analysis.traffic_allowed,
                'verdict_changed': old_analysis and (old_analysis.traffic_allowed != new_analysis.traffic_allowed),
                'warnings': new_analysis.warnings,
            }
            
            self.impact_summary['paths_affected'].append(path_impact)
            
            # Identify what changed
            if path_impact['verdict_changed']:
                if new_analysis.traffic_allowed:
                    logger.warning(f"⚠️  CHANGE OPENED PATH: {path.name}")
                else:
                    logger.info(f"✓ Change blocked path: {path.name}")
        
        # Detect chaining impact (e.g., rule1 on FW1 blocks, rule2 on FW2 allows)
        self._analyze_blocking_chains()
        
        # Detect policy gaps
        self._detect_policy_gaps()
        
        # Generate recommendations
        self._generate_recommendations()
        
        return self.impact_summary
    
    def _find_affected_paths(self) -> List[NetworkPath]:
        """Find all NetworkPaths that traverse this device"""
        
        affected = NetworkPath.objects.filter(
            firewall_steps__firewall_device=self.device
        ).distinct()
        
        logger.info(f"Found {affected.count()} paths traversing {self.device.name}")
        return affected
    
    def _get_last_analysis(self, path: NetworkPath) -> Optional[RuleTraversalAnalysis]:
        """Get most recent traversal analysis for path"""
        
        return RuleTraversalAnalysis.objects.filter(
            path=path
        ).order_by('-analysis_timestamp').first()
    
    def _analyze_blocking_chains(self):
        """Detect multi-firewall blocking chains (A blocks, B allows, etc.)"""
        
        for path_impact in self.impact_summary['paths_affected']:
            path = NetworkPath.objects.get(name=path_impact['path'])
            steps = PathFirewallStep.objects.filter(path=path).order_by('order')
            
            blocking_devices = []
            allowing_devices = []
            
            for step in steps:
                rules = FirewallRule.objects.filter(device=step.firewall_device)
                
                # Simplified: check if any rule blocks this path
                if any(rule.action in ['deny', 'drop'] for rule in rules):
                    blocking_devices.append(step.firewall_device.name)
                else:
                    allowing_devices.append(step.firewall_device.name)
            
            if blocking_devices and allowing_devices:
                self.impact_summary['blocking_chains'].append({
                    'path': path_impact['path'],
                    'blocks': blocking_devices,
                    'allows': allowing_devices,
                    'note': 'Traffic may be blocked before it reaches permitting rules on downstream firewalls',
                })
    
    def _detect_policy_gaps(self):
        """Detect policy inconsistencies across firewalls"""
        
        for path_impact in self.impact_summary['paths_affected']:
            path = NetworkPath.objects.get(name=path_impact['path'])
            steps = PathFirewallStep.objects.filter(path=path).order_by('order')
            
            rule_sequences = []
            for step in steps:
                rules = FirewallRule.objects.filter(
                    device=step.firewall_device
                ).order_by('sequence_number')
                
                rule_sequences.append({
                    'device': step.firewall_device.name,
                    'rule_count': rules.count(),
                    'logging_enabled': rules.filter(logging_enabled=True).count(),
                })
            
            # Detect policy gaps
            if len(rule_sequences) > 1:
                # All firewalls should log same paths
                log_rates = [r['logging_enabled'] / max(r['rule_count'], 1) for r in rule_sequences]
                
                if max(log_rates) - min(log_rates) > 0.2:  # >20% difference
                    self.impact_summary['policy_gaps'].append({
                        'path': path_impact['path'],
                        'issue': 'Inconsistent logging across firewalls',
                        'details': rule_sequences,
                    })
    
    def _generate_recommendations(self):
        """Generate remediation recommendations"""
        
        # Check for rules without approval
        if self.change.approval_status == 'unknown':
            self.impact_summary['recommendations'].append({
                'severity': 'high',
                'message': 'Change has no associated change ticket - obtain approval before deploying',
            })
        
        # Check for critical severity
        if self.change.severity == 'critical':
            self.impact_summary['recommendations'].append({
                'severity': 'critical',
                'message': 'This is a critical change - notify security team immediately',
            })
        
        # Check if rule opens broad access
        if self.change.after_state.get('action') == 'allow':
            src_ips = self.change.after_state.get('source_ips', [])
            dst_ips = self.change.after_state.get('dest_ips', [])
            
            if '0.0.0.0/0' in src_ips or '0.0.0.0/0' in dst_ips:
                self.impact_summary['recommendations'].append({
                    'severity': 'high',
                    'message': 'Rule allows broad "any" traffic - restrict to specific IPs/subnets',
                })
        
        # Check for lack of logging
        if not self.change.after_state.get('logging_enabled'):
            self.impact_summary['recommendations'].append({
                'severity': 'medium',
                'message': 'Enable logging on this rule to track usage and detect misuse',
            })
```

---

## Part 5: Enhanced Django Job for Multi-Firewall Analysis

### 5.1 Scheduled Multi-Firewall Correlation Job

```python
# jobs.py - Add new job class

class AnalyzeMultiFirewallPaths(Job):
    """Analyze firewall changes across entire traffic paths"""
    description = "Analyze impact of changes on multi-firewall paths"
    
    path = StringVar(
        description="Network path (or 'all' for all paths)",
        default="all"
    )
    
    def execute(self):
        from .topology_discoverer import TopologyDiscoverer
        from .rule_traversal import RuleTraversalAnalyzer
        from .multi_firewall_impact import MultiFirewallImpactAnalyzer
        
        # Refresh topology
        self.log_info("Refreshing network topology...")
        discoverer = TopologyDiscoverer()
        discoverer.discover_all()
        
        # Analyze all paths
        if self.path == "all":
            paths = NetworkPath.objects.all()
        else:
            paths = NetworkPath.objects.filter(name=self.path)
        
        for path in paths:
            self.log_info(f"Analyzing path: {path.name}")
            
            analyzer = RuleTraversalAnalyzer(path)
            analysis = analyzer.analyze()
            
            if analysis.traffic_allowed:
                self.log_success(f"✓ Traffic allowed: {path.name}")
            else:
                self.log_warning(f"✗ Traffic blocked: {path.name} at {analysis.blocking_firewall.name}")
        
        # Analyze recent changes for multi-FW impact
        from datetime import timedelta
        from django.utils import timezone
        
        recent_changes = FirewallChange.objects.filter(
            detected_at__gte=timezone.now() - timedelta(hours=24)
        )
        
        self.log_info(f"Analyzing impact of {recent_changes.count()} recent changes...")
        
        for change in recent_changes:
            impact_analyzer = MultiFirewallImpactAnalyzer(change)
            impact = impact_analyzer.analyze()
            
            change.analysis_notes = str(impact)
            change.save()
            
            # Alert if change opens critical paths
            for path_impact in impact['paths_affected']:
                if path_impact.get('verdict_changed') and path_impact.get('new_verdict'):
                    self.log_warning(
                        f"⚠️  Change '{change.rule_name}' OPENED path: {path_impact['path']}"
                    )
                    self._create_alert(change, path_impact)
    
    def _create_alert(self, change, path_impact):
        """Create alert for policy-opening changes"""
        from .models import ChangeAlert
        
        ChangeAlert.objects.create(
            change=change,
            alert_type='policy_opening',
            sent_to='slack://webhook-url',
            status='pending'
        )
```

---

## Part 6: UI Dashboard for Multi-Firewall Analysis

### 6.1 Path Analysis View

```python
# views.py - Add path analysis

from django.shortcuts import render, get_object_or_404
from .models import NetworkPath, RuleTraversalAnalysis

def path_analysis_view(request, path_id):
    """Display detailed analysis of a traffic path"""
    
    path = get_object_or_404(NetworkPath, id=path_id)
    analyses = RuleTraversalAnalysis.objects.filter(path=path).order_by('-analysis_timestamp')[:10]
    
    # Get all firewalls in path
    firewall_steps = PathFirewallStep.objects.filter(path=path).order_by('order')
    
    # Get changes affecting this path
    affected_changes = FirewallChange.objects.filter(
        applicable_rules__affected_paths=path
    ).distinct()[:20]
    
    context = {
        'path': path,
        'firewall_steps': firewall_steps,
        'analyses': analyses,
        'affected_changes': affected_changes,
        'current_verdict': analyses.first().traffic_allowed if analyses else None,
        'blocking_firewall': analyses.first().blocking_firewall if analyses else None,
    }
    
    return render(request, 'nautobot_firewall_changes/path_analysis.html', context)


def impact_report_view(request, change_id):
    """Display multi-firewall impact of a change"""
    
    change = get_object_or_404(FirewallChange, id=change_id)
    
    # Re-analyze if needed
    if not change.analysis_notes:
        from .multi_firewall_impact import MultiFirewallImpactAnalyzer
        analyzer = MultiFirewallImpactAnalyzer(change)
        impact = analyzer.analyze()
    else:
        impact = eval(change.analysis_notes)  # Simplified - use JSON in production
    
    # Get related rules on downstream firewalls
    related_rules = FirewallRule.objects.filter(
        applicable_rules__change=change
    ).select_related('device').order_by('device', 'sequence_number')
    
    context = {
        'change': change,
        'impact': impact,
        'related_rules': related_rules,
    }
    
    return render(request, 'nautobot_firewall_changes/impact_report.html', context)
```

### 6.2 HTML Template for Path Analysis

```html
<!-- templates/nautobot_firewall_changes/path_analysis.html -->
{% extends "base.html" %}

{% block title %}Path Analysis: {{ path.name }}{% endblock %}

{% block content %}
<div class="container-fluid">
    <h1>Traffic Path Analysis</h1>
    
    <div class="alert alert-info">
        <strong>{{ path.name }}</strong><br>
        Source: {{ path.source_network }} ({{ path.source_zone }})<br>
        Destination: {{ path.dest_network }} ({{ path.destination_zone }})
    </div>
    
    <!-- Current Verdict -->
    {% if current_verdict %}
        <div class="alert alert-success">
            <h4>✓ Traffic is currently ALLOWED</h4>
            <p>Traffic can traverse the path without being blocked.</p>
        </div>
    {% elif current_verdict == False %}
        <div class="alert alert-danger">
            <h4>✗ Traffic is BLOCKED</h4>
            {% if blocking_firewall %}
                <p>Blocked at: <strong>{{ blocking_firewall.name }}</strong></p>
            {% endif %}
        </div>
    {% else %}
        <div class="alert alert-warning">
            <h4>? Verdict Indeterminate</h4>
            <p>Unable to determine traffic flow - may require manual review.</p>
        </div>
    {% endif %}
    
    <!-- Firewall Chain -->
    <h2>Firewall Chain</h2>
    <div class="row">
        {% for step in firewall_steps %}
        <div class="col-md-2 text-center">
            <div class="card">
                <div class="card-body">
                    <h5>{{ step.order }}</h5>
                    <p><strong>{{ step.firewall_device.name }}</strong></p>
                    {% if step.ingress_interface %}
                        <small>In: {{ step.ingress_interface.name }}</small><br>
                    {% endif %}
                    {% if step.egress_interface %}
                        <small>Out: {{ step.egress_interface.name }}</small>
                    {% endif %}
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
    
    <!-- Recent Analyses -->
    <h2>Analysis History</h2>
    <table class="table table-striped">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Verdict</th>
                <th>Blocking Point</th>
                <th>Warnings</th>
            </tr>
        </thead>
        <tbody>
            {% for analysis in analyses %}
            <tr>
                <td>{{ analysis.analysis_timestamp|date:"Y-m-d H:i" }}</td>
                <td>
                    {% if analysis.traffic_allowed %}
                        <span class="badge badge-success">ALLOWED</span>
                    {% else %}
                        <span class="badge badge-danger">BLOCKED</span>
                    {% endif %}
                </td>
                <td>
                    {% if analysis.blocking_firewall %}
                        {{ analysis.blocking_firewall.name }}
                        {% if analysis.blocking_rule %}
                            <br><small>Rule: {{ analysis.blocking_rule.rule_name }}</small>
                        {% endif %}
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td>
                    {% if analysis.warnings %}
                        <small>{{ analysis.warnings|length }} warning(s)</small>
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <!-- Affected Changes -->
    <h2>Recent Changes Affecting This Path</h2>
    {% if affected_changes %}
    <table class="table table-striped table-sm">
        <thead>
            <tr>
                <th>Device</th>
                <th>Rule</th>
                <th>Type</th>
                <th>Detected</th>
                <th>Impact</th>
            </tr>
        </thead>
        <tbody>
            {% for change in affected_changes %}
            <tr>
                <td>{{ change.device.name }}</td>
                <td>{{ change.rule_name }}</td>
                <td>{{ change.get_change_type_display }}</td>
                <td>{{ change.detected_at|naturaltime }}</td>
                <td>
                    <a href="{% url 'impact-report' change.id %}" class="btn btn-sm btn-info">
                        View Impact
                    </a>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No recent changes affecting this path.</p>
    {% endif %}
    
</div>
{% endblock %}
```

---

## Part 7: Real-World Scenario Example

### 7.1 Multi-Firewall Change Scenario

```
SCENARIO: Office User Cannot Access Cloud Application

Timeline:
12:00 PM - Change made on Firewall #1 (Border): Rule added to restrict outbound HTTPS
12:05 PM - Application team receives complaints
12:10 PM - Network team investigates

Investigation Process:
1. Query Nautobot for recent changes
   → Find rule change on FW1 at 12:00 PM

2. Identify traffic path
   → Office (192.168.1.0/24) → Internet → Cloud App (52.1.2.3)

3. Run multi-firewall traversal analysis:
   
   FW1 (Border):
   ✓ Source 192.168.1.0/24 matches rule
   ✗ Destination IP 52.1.2.3 NOW BLOCKED by new rule
      (Rule 250: Deny any HTTPS to cloud providers)
   
   → VERDICT: BLOCKED AT FW1
   
4. View change details:
   Before: Allow HTTPS to any
   After:  Deny HTTPS to cloud apps (52.0.0.0/8, 10.0.0.0/8, etc.)
   
5. Correlation:
   - Change ticket: CHG001234 (Missing approval - marked UNAUTHORIZED)
   - Changed by: jr_admin@corp.com
   - No change management process followed

Resolution:
1. Identify blocking rule: "Deny-Cloud-HTTPS" (rule 250)
2. Rollback via Git: Revert to previous config snapshot (11:50 AM)
3. Re-run multi-firewall analysis
   → VERDICT: ALLOWED (all firewalls)
4. Notify teams
5. Investigate why change was made without approval
6. Enforce change management workflow

Nautobot Dashboard shows:
- Path Analysis: Office → Cloud app
  • 12:00 PM: Verdict changed from ALLOWED → BLOCKED
  • Blocking firewall: FW1
  • Blocking rule: "Deny-Cloud-HTTPS"
  
- Impact Report: Rule #250 change
  • Affected paths: 3 (Office→AWS, Office→SaaS, Office→GitHub)
  • Paths opened: 0
  • Paths closed: 3
  • Approval status: UNAUTHORIZED
  • Remediation: Rollback executed
```

---

## Part 8: API Endpoints for Multi-Firewall Queries

```python
# api.py - REST API for external tools

from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import NetworkPath, RuleTraversalAnalysis, FirewallChange

class NetworkPathSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkPath
        fields = '__all__'


class RuleTraversalAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleTraversalAnalysis
        fields = '__all__'


class NetworkPathViewSet(viewsets.ModelViewSet):
    """API for traffic paths"""
    queryset = NetworkPath.objects.all()
    serializer_class = NetworkPathSerializer
    
    @action(detail=True, methods=['get'])
    def analyze(self, request, pk=None):
        """GET /api/paths/{id}/analyze/
        
        Returns current analysis of path, including verdict and blocking points.
        Example:
        {
            "path": "Office_to_Internet",
            "verdict": "BLOCKED",
            "blocking_firewall": "fw-border-1",
            "blocking_rule": "Block-RFC1918-Egress",
            "steps": [
                {
                    "device": "fw-border-1",
                    "rules_evaluated": 45,
                    "verdict": "BLOCKED"
                }
            ]
        }
        """
        from .rule_traversal import RuleTraversalAnalyzer
        
        path = self.get_object()
        analyzer = RuleTraversalAnalyzer(path)
        analysis = analyzer.analyze()
        
        return Response({
            'path': path.name,
            'verdict': 'ALLOWED' if analysis.traffic_allowed else 'BLOCKED',
            'blocking_firewall': analysis.blocking_firewall.name if analysis.blocking_firewall else None,
            'blocking_rule': analysis.blocking_rule.rule_name if analysis.blocking_rule else None,
            'analysis': analysis.analysis_report,
            'warnings': analysis.warnings,
        })
    
    @action(detail=True, methods=['post'])
    def simulate_change(self, request, pk=None):
        """POST /api/paths/{id}/simulate_change/
        
        Simulate how a rule change would affect this path.
        Body: {
            "rule_id": "250",
            "action": "deny",
            "source": "192.168.1.0/24",
            "dest": "52.0.0.0/8"
        }
        """
        path = self.get_object()
        
        # Would implement rule simulation here
        return Response({'message': 'Simulation not yet implemented'})


class FirewallChangeViewSet(viewsets.ModelViewSet):
    """API for firewall changes"""
    queryset = FirewallChange.objects.all()
    
    @action(detail=True, methods=['get'])
    def multi_fw_impact(self, request, pk=None):
        """GET /api/changes/{id}/multi_fw_impact/
        
        Returns impact of change across all firewalls and traffic paths.
        Example:
        {
            "change": "Rule #250 added",
            "device": "fw-border-1",
            "paths_affected": [
                {
                    "path": "Office_to_Internet",
                    "old_verdict": "ALLOWED",
                    "new_verdict": "BLOCKED",
                    "blocking_device": "fw-border-1"
                },
                {
                    "path": "Office_to_AWS",
                    "old_verdict": "ALLOWED",
                    "new_verdict": "BLOCKED",
                    "blocking_device": "fw-border-1"
                }
            ],
            "recommendations": [
                "Change blocks 2 critical paths",
                "Requires approval before deployment"
            ]
        }
        """
        from .multi_firewall_impact import MultiFirewallImpactAnalyzer
        
        change = self.get_object()
        analyzer = MultiFirewallImpactAnalyzer(change)
        impact = analyzer.analyze()
        
        return Response(impact)
```

---

## Part 9: Implementation Checklist

```
MULTI-FIREWALL TOPOLOGY
☐ Document all firewall devices and their connectivity
☐ Identify security zones (trust, untrust, dmz, etc.)
☐ Map interfaces and IP addresses for each device
☐ Identify traffic paths (Office→Internet, Office→Cloud, etc.)
☐ Load topology into Nautobot models

AUTOMATIC DISCOVERY
☐ Enable API access on all firewalls
☐ Deploy TopologyDiscoverer job
☐ Verify discovered interfaces match documentation
☐ Verify discovered paths match business flows
☐ Schedule discovery job (hourly or daily)

RULE ANALYSIS
☐ Deploy RuleTraversalAnalyzer
☐ Test on sample paths (known to work)
☐ Verify detection of blocking rules
☐ Test shadowing detection
☐ Run analysis on all paths as baseline

CHANGE CORRELATION
☐ Deploy MultiFirewallImpactAnalyzer
☐ Test on recent real changes
☐ Verify path verdict changes are detected
☐ Verify recommendations are accurate
☐ Generate alerts for critical impacts

INTEGRATION
☐ Add path analysis to Django dashboard
☐ Build REST API for path queries
☐ Integrate with incident management system
☐ Create runbooks for common scenarios
☐ Train support teams on multi-FW analysis

TESTING
☐ Test path verdict changes (allow→block, block→allow)
☐ Test with rule additions, deletions, modifications
☐ Verify chain impact detection (FW1 blocks, FW2 allows)
☐ Test with disabled rules
☐ Test with overlapping rules
☐ Validate against manual network policy review
```

---

## Part 10: Advantages Over Single-Device Tracking

| Feature | Single-FW Tool | Nautobot Multi-FW |
|---------|---|---|
| **Single Firewall Changes** | ✓ | ✓ |
| **Rule Traversal Analysis** | ✗ | ✓ |
| **Path Blocking Detection** | ✗ | ✓ |
| **End-to-End Verdict** | ✗ | ✓ |
| **Rule Shadowing Detection** | ✗ | ✓ |
| **Change Impact on Paths** | ✗ | ✓ |
| **Multi-Vendor Support** | Limited | ✓ (All vendors) |
| **Compliance Reports** | ✗ | ✓ |
| **Version Control** | ✗ | ✓ (Git) |
| **Custom Workflows** | ✗ | ✓ (Fully extensible) |
| **Cost** | $50K-500K/yr | < $10K (open-source) |

---

## Key Takeaways

1. **Yes, Nautobot can locate multiple firewalls** – Through topology discovery and explicit path configuration

2. **Can correlate changes** – Multi-firewall impact analysis shows how changes on one firewall affect traffic through the entire path

3. **Can detect blocking chains** – Identify if traffic is blocked at FW1, allowed at FW2, blocked again at FW3

4. **Can analyze end-to-end flow** – Determine if traffic will reach its destination through all firewalls

5. **Can detect policy gaps** – Identify inconsistencies in logging, rule counting, or allow/deny policies across firewalls

6. **Fully extensible** – Custom collectors for any firewall vendor, custom impact analysis rules, custom alerting

7. **Highly automatable** – All analysis runs on schedule; alerts integrate with Slack, ServiceNow, etc.

This approach provides the "forensic" capability that Tufin and other commercial tools offer, but with complete customization and no licensing costs.
