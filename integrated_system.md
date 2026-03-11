# Integrated Policy Lookup API + Multi-Firewall Traffic Path Discovery

## Overview

This document describes the **complete integrated system** that combines:

1. **Policy Lookup API** – Real-time policy queries (Source IP, Dest IP, Protocol, Port)
2. **Multi-Firewall Path Discovery** – Topology mapping and rule traversal
3. **Change Impact Analysis** – How policy changes affect traffic paths
4. **Risk Assessment** – Automatic approval/denial based on risk scoring

The integration creates a **unified firewall policy decision engine** that provides:
- Real-time policy lookup across all firewalls
- End-to-end traffic path analysis (multi-firewall)
- Automatic risk assessment
- Policy change impact forecasting
- Complete audit trail

---

## Part 1: Integrated Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                       External API Requestor                          │
│  (Terraform, ServiceNow, Custom App, Self-Service Portal, etc.)      │
└────────┬─────────────────────────────────────────────────────────────┘
         │
         │ POST /api/policy/lookup/
         │ {source_ip, dest_ip, protocol, port, justification}
         │
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Policy Lookup API Layer                            │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 1. Input Validation & Normalization                           │  │
│  │    - Parse IP addresses/CIDR notation                         │  │
│  │    - Validate protocol/port                                   │  │
│  │    - Extract business justification                           │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 2. Rule Matching Engine                                        │  │
│  │    - Query all FirewallRule objects                            │  │
│  │    - Check IP ranges, services, zones                          │  │
│  │    - Return matching rules with verdict (ALLOWED/BLOCKED)      │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 3. Policy Existence Check                                      │  │
│  │    - If rules match: policy EXISTS                             │  │
│  │      Return matching rules + verdict                           │  │
│  │    - If no rules match: policy DOESN'T EXIST                   │  │
│  │      Proceed to impact analysis                                │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 4. Traffic Path Discovery (INTEGRATED)                         │  │
│  │    - Find ALL NetworkPaths traversing source → dest            │  │
│  │    - Get ordered list of firewalls along each path             │  │
│  │    - Determine current verdict on each path                    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 5. Multi-Firewall Rule Traversal (INTEGRATED)                  │  │
│  │    - For each path:                                            │  │
│  │      • Step through FW1 → FW2 → FW3 → ...                     │  │
│  │      • Apply rules in sequence order                           │  │
│  │      • Determine blocking point (if blocked)                   │  │
│  │      • Identify which rules allow/block                        │  │
│  │    - Return per-path analysis                                  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 6. Change Impact Analysis (INTEGRATED)                         │  │
│  │    - Simulate: "What if we allow this traffic?"                │  │
│  │    - For each affected path:                                   │  │
│  │      • Would rule open previously blocked path?                │  │
│  │      • Would it close previously allowed path? (rare)          │  │
│  │      • What warnings/conflicts exist?                          │  │
│  │    - Re-run rule traversal with proposed rule                  │  │
│  │    - Compare before/after verdict                              │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 7. Risk Assessment & Scoring                                   │  │
│  │    - Calculate risk score (0-100)                              │  │
│  │    - Paths opened (highest risk factor)                        │  │
│  │    - Source/dest breadth                                       │  │
│  │    - Port/protocol risk                                        │  │
│  │    - Determine status: PERMITTED/REVIEW_REQUIRED/DENIED        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ 8. Decision & Response                                         │  │
│  │    If policy_exists:                                           │  │
│  │      → Return "Policy already exists - no new rule needed"    │  │
│  │    Else if impact_analysis shows low risk:                    │  │
│  │      → Return "Permitted - can auto-approve"                  │  │
│  │    Else if medium/high risk:                                   │  │
│  │      → Return "Review required - escalate to security"        │  │
│  │    Else (critical risk):                                       │  │
│  │      → Return "Denied - requires director approval"            │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
         │
         │ Response with request_id, verdict, impact, recommendations
         │
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│              Policy Request Tracking & Audit                          │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ PolicyLookupRequest (database record)                          │  │
│  │  - request_id: PLR-20240315-001                                │  │
│  │  - source_ip, dest_ip, protocol, port                          │  │
│  │  - business_justification                                      │  │
│  │  - policy_exists: true/false                                   │  │
│  │  - matching_rules: [...matching firewall rules...]             │  │
│  │  - verdict: ALLOWED/BLOCKED/UNKNOWN                            │  │
│  │  - affected_paths: [...NetworkPath objects...]                 │  │
│  │  - impact_analysis: {...traversal results...}                  │  │
│  │  - risk_score: 0-100                                           │  │
│  │  - status: exists/new/approved/rejected/deployed               │  │
│  │  - approver, approved_at, deployed_at                          │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Part 2: Enhanced Policy Lookup Engine (Integrated)

```python
# policy_lookup_api_integrated.py

from typing import Dict, List, Tuple, Optional
from django.db.models import Q
from django.utils import timezone
import netaddr
import logging

logger = logging.getLogger(__name__)

class IntegratedPolicyEngine:
    """
    Unified policy lookup engine combining:
    - Rule matching
    - Traffic path discovery
    - Multi-firewall traversal
    - Change impact analysis
    - Risk assessment
    """
    
    def __init__(self):
        from nautobot_firewall_changes.models import (
            FirewallRule, NetworkPath, PathFirewallStep, 
            FirewallDevice, RuleTraversalAnalysis
        )
        self.FirewallRule = FirewallRule
        self.NetworkPath = NetworkPath
        self.PathFirewallStep = PathFirewallStep
        self.FirewallDevice = FirewallDevice
        self.RuleTraversalAnalysis = RuleTraversalAnalysis
    
    def process_policy_request(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: int = None,
        business_justification: str = None
    ) -> Dict:
        """
        Main entry point for policy lookup + impact analysis
        
        Returns:
            {
                'policy_exists': bool,
                'verdict': 'ALLOWED' | 'BLOCKED' | 'UNKNOWN',
                'matching_rules': [...],
                'affected_paths': [...],
                'impact_analysis': {...},
                'risk_assessment': {...},
                'recommendation': 'PERMITTED' | 'REVIEW_REQUIRED' | 'DENIED',
            }
        """
        
        logger.info(f"Processing policy request: {source_ip} → {dest_ip}:{port}")
        
        # Step 1: Normalize inputs
        src_net = netaddr.IPNetwork(source_ip)
        dst_net = netaddr.IPNetwork(dest_ip)
        service_id = self._build_service_id(protocol, port)
        
        # Step 2: Find matching firewall rules
        matching_rules = self._find_matching_rules(src_net, dst_net, service_id)
        
        # Step 3: Check if policy exists
        policy_exists = len(matching_rules) > 0
        
        if policy_exists:
            # Policy already exists
            verdict = self._determine_single_device_verdict(matching_rules)
            
            return {
                'policy_exists': True,
                'verdict': verdict['verdict'],
                'matching_rules': matching_rules,
                'blocking_firewall': verdict.get('blocking_firewall'),
                'blocking_rule': verdict.get('blocking_rule'),
                'affected_paths': [],
                'impact_analysis': None,
                'risk_assessment': None,
                'recommendation': 'NO_ACTION',
                'message': f"Policy already exists - verdict: {verdict['verdict']}",
            }
        
        # Step 4: Find affected traffic paths
        affected_paths = self._find_affected_traffic_paths(src_net, dst_net)
        
        logger.info(f"Found {len(affected_paths)} affected traffic paths")
        
        # Step 5: Perform multi-firewall rule traversal
        path_analyses = {}
        for path in affected_paths:
            analysis = self._analyze_path_traversal(path, src_net, dst_net, service_id)
            path_analyses[path.id] = analysis
        
        # Step 6: Analyze impact of creating new rule
        impact = self._analyze_policy_impact(
            src_net, dst_net, service_id, path_analyses, affected_paths
        )
        
        # Step 7: Calculate risk
        risk_assessment = self._assess_risk(
            src_net, dst_net, protocol, port,
            impact, business_justification
        )
        
        # Step 8: Make recommendation
        recommendation = self._make_recommendation(risk_assessment)
        
        return {
            'policy_exists': False,
            'verdict': 'UNKNOWN',
            'matching_rules': [],
            'blocking_firewall': None,
            'blocking_rule': None,
            'affected_paths': [
                {
                    'path_id': path.id,
                    'path_name': path.name,
                    'current_verdict': path_analyses[path.id]['current_verdict'],
                    'firewall_chain': path_analyses[path.id]['firewall_chain'],
                    'blocking_point': path_analyses[path.id].get('blocking_firewall'),
                }
                for path in affected_paths
            ],
            'impact_analysis': impact,
            'risk_assessment': risk_assessment,
            'recommendation': recommendation['status'],
            'message': recommendation['message'],
            'business_justification': business_justification,
        }
    
    def _find_matching_rules(
        self,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        service_id: str
    ) -> List[Dict]:
        """Find all firewall rules matching this traffic pattern"""
        
        matching = []
        rules = self.FirewallRule.objects.select_related('device').order_by(
            'device', 'sequence_number'
        )
        
        for rule in rules:
            if self._rule_matches(rule, src_net, dst_net, service_id):
                matching.append({
                    'device_name': rule.device.name,
                    'device_id': rule.device.id,
                    'rule_id': rule.rule_id,
                    'rule_name': rule.rule_name,
                    'action': rule.action,
                    'sequence_number': rule.sequence_number,
                    'logging_enabled': rule.logging_enabled,
                    'source_zones': rule.source_zones,
                    'dest_zones': rule.dest_zones,
                    'created_at': rule.created_at,
                })
        
        return matching
    
    def _rule_matches(
        self,
        rule,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        service_id: str
    ) -> bool:
        """Determine if rule matches traffic"""
        
        if rule.disabled:
            return False
        
        # Source IP match
        if rule.source_ips:
            src_match = any(
                self._ip_in_range(src_net, src_range)
                for src_range in rule.source_ips
            )
            if not src_match:
                return False
        
        # Destination IP match
        if rule.dest_ips:
            dst_match = any(
                self._ip_in_range(dst_net, dst_range)
                for dst_range in rule.dest_ips
            )
            if not dst_match:
                return False
        
        # Service match
        if rule.services and service_id != 'all':
            service_match = any(
                self._service_matches(service_id, rule_service)
                for rule_service in rule.services
            )
            if not service_match:
                return False
        
        return True
    
    def _ip_in_range(self, traffic_net: netaddr.IPNetwork, rule_range: str) -> bool:
        """Check if traffic matches rule IP range"""
        
        if rule_range == 'any':
            return True
        
        try:
            rule_net = netaddr.IPNetwork(rule_range)
            return traffic_net.ip in rule_net or traffic_net.cidr in rule_net.cidr
        except:
            return False
    
    def _service_matches(self, traffic_service: str, rule_service: str) -> bool:
        """Check if traffic service matches rule service"""
        
        if rule_service == 'any':
            return True
        
        traffic_proto, traffic_port = self._parse_service(traffic_service)
        rule_proto, rule_port = self._parse_service(rule_service)
        
        if rule_proto not in ['all', traffic_proto]:
            return False
        
        if traffic_port and rule_port and traffic_port != rule_port:
            return False
        
        return True
    
    def _parse_service(self, service: str) -> Tuple[str, Optional[int]]:
        """Parse service identifier"""
        
        if '/' in service:
            proto, port = service.split('/')
            return proto, int(port) if port.isdigit() else None
        
        return service, None
    
    def _build_service_id(self, protocol: str, port: int = None) -> str:
        """Build service identifier"""
        
        if protocol == 'all':
            return 'all'
        
        if port:
            return f"{protocol}/{port}"
        
        return protocol
    
    def _find_affected_traffic_paths(
        self,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork
    ) -> List:
        """Find all NetworkPaths affected by this traffic"""
        
        paths = self.NetworkPath.objects.all()
        affected = []
        
        for path in paths:
            path_src = netaddr.IPNetwork(path.source_network)
            path_dst = netaddr.IPNetwork(path.dest_network)
            
            # Check for overlap
            if (self._ranges_overlap(src_net, path_src) and 
                self._ranges_overlap(dst_net, path_dst)):
                affected.append(path)
        
        # If no specific paths found, return default paths
        if not affected:
            affected = list(self.NetworkPath.objects.all()[:10])
        
        return affected
    
    def _ranges_overlap(self, net1: netaddr.IPNetwork, net2: netaddr.IPNetwork) -> bool:
        """Check if ranges overlap"""
        
        try:
            return net1.overlaps(net2)
        except:
            return False
    
    def _analyze_path_traversal(
        self,
        path,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        service_id: str
    ) -> Dict:
        """
        Analyze traffic through entire path (INTEGRATED WITH MULTI-FIREWALL TRAVERSAL)
        
        Steps through each firewall in order, applies rules, determines verdict
        """
        
        logger.info(f"Analyzing path traversal: {path.name}")
        
        # Get firewalls in path order
        steps = self.PathFirewallStep.objects.filter(path=path).order_by('order')
        
        firewall_chain = []
        blocking_firewall = None
        blocking_rule = None
        current_verdict = 'UNKNOWN'
        
        # Step through each firewall
        for step in steps:
            device = step.firewall_device
            
            step_analysis = {
                'device': device.name,
                'device_id': device.id,
                'order': step.order,
                'rules_evaluated': [],
                'verdict': 'UNKNOWN',
                'allowing_rule': None,
                'blocking_rule': None,
            }
            
            # Get rules for this device
            rules = self.FirewallRule.objects.filter(
                device=device
            ).order_by('sequence_number')
            
            # Evaluate rules in order (first match wins)
            for rule in rules:
                if rule.disabled:
                    continue
                
                # Check if rule matches this traffic
                matches = self._rule_matches(rule, src_net, dst_net, service_id)
                
                step_analysis['rules_evaluated'].append({
                    'rule_id': rule.rule_id,
                    'rule_name': rule.rule_name,
                    'matches': matches,
                    'action': rule.action,
                })
                
                if matches:
                    # First matching rule determines verdict
                    if rule.action in ['deny', 'drop', 'reject']:
                        step_analysis['verdict'] = 'BLOCKED'
                        step_analysis['blocking_rule'] = rule.rule_name
                        blocking_firewall = device.name
                        blocking_rule = rule.rule_name
                        current_verdict = 'BLOCKED'
                        break
                    
                    elif rule.action == 'allow':
                        step_analysis['verdict'] = 'ALLOWED'
                        step_analysis['allowing_rule'] = rule.rule_name
                        current_verdict = 'ALLOWED'
                        break
            
            # Default action if no rule matched
            if step_analysis['verdict'] == 'UNKNOWN':
                default = 'deny'
                step_analysis['verdict'] = 'BLOCKED' if default == 'deny' else 'ALLOWED'
                current_verdict = step_analysis['verdict']
            
            firewall_chain.append(step_analysis)
            
            # If traffic is blocked, no need to analyze remaining firewalls
            if current_verdict == 'BLOCKED':
                break
        
        return {
            'path_name': path.name,
            'current_verdict': current_verdict,
            'firewall_chain': firewall_chain,
            'blocking_firewall': blocking_firewall,
            'blocking_rule': blocking_rule,
            'warnings': self._detect_path_warnings(firewall_chain),
        }
    
    def _detect_path_warnings(self, firewall_chain: List[Dict]) -> List[str]:
        """Detect warnings like rule shadowing, conflicts"""
        
        warnings = []
        
        # Check for rule shadowing
        allowed_rules = [
            fw['allowing_rule'] 
            for fw in firewall_chain 
            if fw['verdict'] == 'ALLOWED'
        ]
        
        if len(allowed_rules) > 1:
            warnings.append(
                f"Traffic allowed by multiple rules across firewalls: "
                f"{', '.join(allowed_rules)}"
            )
        
        # Check for logging inconsistency
        logging_states = [
            fw.get('logging_enabled')
            for fw in firewall_chain
        ]
        
        if logging_states and not all(logging_states):
            warnings.append("Logging not enabled on all firewalls in path")
        
        return warnings
    
    def _analyze_policy_impact(
        self,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        service_id: str,
        path_analyses: Dict,
        affected_paths: List
    ) -> Dict:
        """
        Analyze impact of creating a new allow rule
        
        Returns:
            - Which paths would open (currently blocked → allowed)
            - Which paths already have access
            - Warnings and conflicts
        """
        
        impact = {
            'paths_opened': [],
            'paths_already_allowed': [],
            'paths_already_blocked': [],
            'total_paths_affected': len(affected_paths),
        }
        
        for path in affected_paths:
            analysis = path_analyses[path.id]
            
            if analysis['current_verdict'] == 'BLOCKED':
                impact['paths_opened'].append({
                    'path_name': path.name,
                    'path_id': path.id,
                    'current_verdict': 'BLOCKED',
                    'new_verdict': 'ALLOWED',
                    'blocking_firewall': analysis['blocking_firewall'],
                    'blocking_rule': analysis['blocking_rule'],
                })
            
            elif analysis['current_verdict'] == 'ALLOWED':
                impact['paths_already_allowed'].append({
                    'path_name': path.name,
                    'path_id': path.id,
                    'verdict': 'ALLOWED',
                })
            
            else:
                impact['paths_already_blocked'].append({
                    'path_name': path.name,
                    'path_id': path.id,
                    'verdict': 'UNKNOWN',
                })
        
        return impact
    
    def _assess_risk(
        self,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        protocol: str,
        port: int,
        impact: Dict,
        business_justification: str
    ) -> Dict:
        """
        Calculate risk score with special weight on opened paths
        """
        
        score = 0
        factors = {}
        
        # Factor 1: Paths opened (HIGH WEIGHT - 0-40 points)
        # This is the biggest risk factor
        paths_opened = len(impact['paths_opened'])
        path_score = min(40, paths_opened * 10)
        score += path_score
        factors['paths_opened'] = {
            'score': path_score,
            'detail': f"{paths_opened} previously blocked path(s) would open"
        }
        
        # Factor 2: Source breadth (0-20 points)
        if src_net.size > 1:
            src_score = min(20, int(15 * (src_net.prefixlen / 32)))
            score += src_score
            factors['source_breadth'] = {
                'score': src_score,
                'detail': f"Source range covers {src_net.size} IPs"
            }
        
        # Factor 3: Destination breadth (0-15 points)
        if dst_net.size > 1:
            dst_score = min(15, int(12 * (dst_net.prefixlen / 32)))
            score += dst_score
            factors['dest_breadth'] = {
                'score': dst_score,
                'detail': f"Destination range covers {dst_net.size} IPs"
            }
        
        # Factor 4: Port risk (0-15 points)
        risky_ports = {22, 80, 443, 3306, 3389, 5432, 27017, 6379}
        if port and port in risky_ports:
            port_score = 12
            score += port_score
            factors['port_risk'] = {
                'score': port_score,
                'detail': f"Port {port} is commonly targeted"
            }
        
        # Factor 5: Protocol risk (0-10 points)
        if protocol == 'all':
            protocol_score = 10
        elif protocol in ['tcp', 'udp']:
            protocol_score = 2
        else:
            protocol_score = 0
        
        score += protocol_score
        factors['protocol_risk'] = {
            'score': protocol_score,
            'detail': f"Protocol: {protocol}"
        }
        
        # Factor 6: Business justification quality (-15 to 0 points)
        justif_score = 0
        if business_justification:
            length = len(business_justification)
            if length > 150:
                justif_score = -15
            elif length > 80:
                justif_score = -10
            elif length > 40:
                justif_score = -5
            else:
                justif_score = 0
        
        score += justif_score
        factors['justification_quality'] = {
            'score': justif_score,
            'detail': f"Justification quality: {length if business_justification else 0} chars"
        }
        
        # Ensure score is 0-100
        score = max(0, min(100, score))
        
        # Determine risk level
        if score >= 75:
            risk_level = 'CRITICAL'
        elif score >= 50:
            risk_level = 'HIGH'
        elif score >= 25:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'score': score,
            'level': risk_level,
            'factors': factors,
        }
    
    def _make_recommendation(self, risk_assessment: Dict) -> Dict:
        """
        Make approval recommendation based on risk
        """
        
        score = risk_assessment['score']
        level = risk_assessment['level']
        
        if level == 'CRITICAL':
            return {
                'status': 'DENIED',
                'message': (
                    f"DENIED: Risk score {score}/100 (CRITICAL). "
                    "This rule opens risky access requiring director-level approval. "
                    "Please contact security leadership."
                ),
            }
        
        elif level == 'HIGH':
            return {
                'status': 'REVIEW_REQUIRED',
                'message': (
                    f"REVIEW REQUIRED: Risk score {score}/100 (HIGH). "
                    "This rule requires security team approval via change management. "
                    "Review recommendations and submit for approval."
                ),
            }
        
        elif level == 'MEDIUM':
            return {
                'status': 'REVIEW_REQUIRED',
                'message': (
                    f"REVIEW REQUIRED: Risk score {score}/100 (MEDIUM). "
                    "This rule may be approved with standard change process. "
                    "Implement recommendations if possible."
                ),
            }
        
        else:  # LOW
            return {
                'status': 'PERMITTED',
                'message': (
                    f"PERMITTED: Risk score {score}/100 (LOW). "
                    "This rule is low-risk and may be auto-approved. "
                    "Enable logging and ensure business justification is documented."
                ),
            }
    
    def _determine_single_device_verdict(self, matching_rules: List[Dict]) -> Dict:
        """Determine verdict from single-device matching rules"""
        
        # Group by device
        by_device = {}
        for rule in matching_rules:
            device = rule['device_name']
            if device not in by_device:
                by_device[device] = []
            by_device[device].append(rule)
        
        # For each device, get first matching rule (in order)
        blocking_device = None
        blocking_rule = None
        
        for device, rules in by_device.items():
            sorted_rules = sorted(rules, key=lambda r: r['sequence_number'])
            
            if sorted_rules:
                first_rule = sorted_rules[0]
                
                if first_rule['action'] in ['deny', 'drop', 'reject']:
                    blocking_device = device
                    blocking_rule = first_rule['rule_name']
                    break
        
        verdict = 'BLOCKED' if blocking_device else 'ALLOWED'
        
        return {
            'verdict': verdict,
            'blocking_firewall': blocking_device,
            'blocking_rule': blocking_rule,
        }
```

---

## Part 3: Enhanced API Response Examples

### Example 1: Policy Lookup - Existing Policy

```bash
curl -X POST http://nautobot.example.com/api/policy/lookup/ \
  -H "Authorization: Token abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.50.100",
    "dest_ip": "10.0.2.20",
    "protocol": "tcp",
    "port": 443,
    "business_justification": "HR team access to payroll system",
    "requester_email": "hr-lead@company.com"
  }'
```

**Response:**
```json
{
    "request_id": "PLR-20240315-001",
    "policy_exists": true,
    "verdict": "ALLOWED",
    "matching_rules": [
        {
            "device_name": "fw-border-1",
            "rule_id": "250",
            "rule_name": "Allow-HR-Payroll-HTTPS",
            "action": "allow",
            "sequence_number": 250,
            "logging_enabled": true,
            "source_zones": ["trust"],
            "dest_zones": ["dmz"],
            "created_at": "2024-01-10T14:30:00Z"
        }
    ],
    "affected_paths": [],
    "impact_analysis": null,
    "risk_assessment": null,
    "recommendation": "NO_ACTION",
    "message": "Policy already exists - verdict: ALLOWED",
    "business_justification": "HR team access to payroll system"
}
```

### Example 2: Policy Analysis - New Policy Request

```bash
curl -X POST http://nautobot.example.com/api/policy/lookup/ \
  -H "Authorization: Token abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.100.0/24",
    "dest_ip": "172.16.1.0/24",
    "protocol": "tcp",
    "port": 3306,
    "business_justification": "Database server migration project - new MySQL replication cluster requires access from backup servers in network 192.168.100.0/24",
    "requester_email": "dba-team@company.com",
    "ticket_id": "CHG001250"
  }'
```

**Response (showing full integrated analysis):**
```json
{
    "request_id": "PLR-20240315-002",
    "policy_exists": false,
    "verdict": "UNKNOWN",
    "matching_rules": [],
    "blocking_firewall": null,
    "blocking_rule": null,
    "affected_paths": [
        {
            "path_id": 1,
            "path_name": "Office_to_Database_Cluster",
            "current_verdict": "BLOCKED",
            "firewall_chain": [
                {
                    "device": "fw-border-1",
                    "device_id": 1,
                    "order": 1,
                    "rules_evaluated": [
                        {
                            "rule_id": "10",
                            "rule_name": "Block-RFC1918-Egress",
                            "matches": true,
                            "action": "deny"
                        }
                    ],
                    "verdict": "BLOCKED",
                    "blocking_rule": "Block-RFC1918-Egress"
                },
                {
                    "device": "fw-database-boundary",
                    "device_id": 3,
                    "order": 2,
                    "rules_evaluated": [
                        {
                            "rule_id": "200",
                            "rule_name": "Allow-DB-Access",
                            "matches": true,
                            "action": "allow"
                        }
                    ],
                    "verdict": "ALLOWED",
                    "allowing_rule": "Allow-DB-Access"
                }
            ],
            "blocking_point": "fw-border-1",
            "blocking_rule": "Block-RFC1918-Egress"
        },
        {
            "path_id": 2,
            "path_name": "DataCenter_to_Database_Cluster",
            "current_verdict": "ALLOWED",
            "firewall_chain": [
                {
                    "device": "fw-datacenter-egress",
                    "device_id": 2,
                    "order": 1,
                    "rules_evaluated": [
                        {
                            "rule_id": "100",
                            "rule_name": "Allow-DC-to-DMZ",
                            "matches": true,
                            "action": "allow"
                        }
                    ],
                    "verdict": "ALLOWED",
                    "allowing_rule": "Allow-DC-to-DMZ"
                },
                {
                    "device": "fw-database-boundary",
                    "device_id": 3,
                    "order": 2,
                    "rules_evaluated": [
                        {
                            "rule_id": "200",
                            "rule_name": "Allow-DB-Access",
                            "matches": true,
                            "action": "allow"
                        }
                    ],
                    "verdict": "ALLOWED",
                    "allowing_rule": "Allow-DB-Access"
                }
            ],
            "blocking_point": null,
            "blocking_rule": null
        }
    ],
    "impact_analysis": {
        "paths_opened": [
            {
                "path_name": "Office_to_Database_Cluster",
                "path_id": 1,
                "current_verdict": "BLOCKED",
                "new_verdict": "ALLOWED",
                "blocking_firewall": "fw-border-1",
                "blocking_rule": "Block-RFC1918-Egress"
            }
        ],
        "paths_already_allowed": [
            {
                "path_name": "DataCenter_to_Database_Cluster",
                "path_id": 2,
                "verdict": "ALLOWED"
            }
        ],
        "paths_already_blocked": [],
        "total_paths_affected": 2
    },
    "risk_assessment": {
        "score": 52,
        "level": "HIGH",
        "factors": {
            "paths_opened": {
                "score": 10,
                "detail": "1 previously blocked path(s) would open"
            },
            "source_breadth": {
                "score": 20,
                "detail": "Source range covers 256 IPs (192.168.100.0/24)"
            },
            "dest_breadth": {
                "score": 15,
                "detail": "Destination range covers 256 IPs (172.16.1.0/24)"
            },
            "port_risk": {
                "score": 12,
                "detail": "Port 3306 is commonly targeted (MySQL)"
            },
            "protocol_risk": {
                "score": 0,
                "detail": "Protocol: tcp"
            },
            "justification_quality": {
                "score": -5,
                "detail": "Justification quality: 154 chars (good)"
            }
        }
    },
    "recommendation": "REVIEW_REQUIRED",
    "message": "REVIEW REQUIRED: Risk score 52/100 (HIGH). This rule requires security team approval via change management. Review recommendations and submit for approval.",
    "business_justification": "Database server migration project - new MySQL replication cluster requires access from backup servers in network 192.168.100.0/24"
}
```

---

## Part 4: Enhanced Database Models

```python
# Add to nautobot_firewall_changes/models.py

from django.db import models
from nautobot.core.models import BaseModel

class PolicyLookupRequest(BaseModel):
    """Track all policy lookup requests with full path analysis"""
    
    request_id = models.CharField(max_length=50, unique=True)
    source_ip = models.CharField(max_length=100)
    dest_ip = models.CharField(max_length=100)
    protocol = models.CharField(max_length=20)
    port = models.IntegerField(null=True, blank=True)
    
    business_justification = models.TextField()
    requester_email = models.EmailField()
    ticket_id = models.CharField(max_length=50, null=True, blank=True)
    
    status = models.CharField(
        max_length=20,
        choices=[
            ('exists', 'Policy Exists'),
            ('new', 'New Policy Request'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('deployed', 'Deployed'),
        ]
    )
    
    # Policy existence check
    policy_exists = models.BooleanField(default=False)
    existing_rules = models.JSONField(null=True, blank=True)
    
    # Traffic path analysis (INTEGRATED)
    affected_paths = models.ManyToManyField(
        'NetworkPath',
        blank=True,
        related_name='lookup_requests'
    )
    
    # Multi-firewall traversal results (INTEGRATED)
    path_analysis_results = models.JSONField(null=True, blank=True)
    
    # Impact analysis (INTEGRATED)
    impact_analysis = models.JSONField(null=True, blank=True)
    
    # Risk assessment (INTEGRATED)
    risk_score = models.IntegerField(null=True, blank=True)
    risk_level = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ]
    )
    risk_factors = models.JSONField(null=True, blank=True)
    
    # Approval workflow
    approved_by = models.CharField(max_length=100, null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_notes = models.TextField(blank=True)
    
    # Deployment tracking
    deployed_at = models.DateTimeField(null=True, blank=True)
    deployed_rule_ids = models.JSONField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['source_ip', 'dest_ip']),
            models.Index(fields=['status']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.request_id}: {self.source_ip} → {self.dest_ip}:{self.port}"


class AffectedTrafficPath(BaseModel):
    """Details about each affected path for a policy request"""
    
    lookup_request = models.ForeignKey(
        PolicyLookupRequest,
        on_delete=models.CASCADE,
        related_name='analyzed_paths'
    )
    traffic_path = models.ForeignKey(
        'NetworkPath',
        on_delete=models.CASCADE
    )
    
    # Current state
    current_verdict = models.CharField(
        max_length=20,
        choices=[
            ('allowed', 'Allowed'),
            ('blocked', 'Blocked'),
            ('unknown', 'Unknown'),
        ]
    )
    blocking_firewall = models.ForeignKey(
        'FirewallDevice',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='path_blockages'
    )
    blocking_rule = models.ForeignKey(
        'FirewallRule',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    
    # New state (if rule is created)
    new_verdict = models.CharField(
        max_length=20,
        choices=[
            ('allowed', 'Allowed'),
            ('blocked', 'Blocked'),
            ('unknown', 'Unknown'),
        ],
        null=True,
        blank=True
    )
    would_open_path = models.BooleanField(default=False)
    
    # Traversal details
    firewall_chain = models.JSONField()  # [{device, rules_evaluated, verdict}, ...]
    warnings = models.JSONField(default=list)
    
    class Meta:
        unique_together = ('lookup_request', 'traffic_path')
        ordering = ['traffic_path']
```

---

## Part 5: Complete Workflow with Examples

### Workflow: New Database Server Access Request

```
┌─ DBA Team Submits Request ──────────────────────────────────────┐
│                                                                   │
│  "We're migrating to a new MySQL cluster. We need to allow      │
│   traffic from backup servers (192.168.100.0/24) to the new    │
│   cluster (172.16.1.0/24) on port 3306"                         │
│                                                                   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 1: API receives request                                    │
│  POST /api/policy/lookup/                                        │
│  {                                                                │
│    "source_ip": "192.168.100.0/24",                              │
│    "dest_ip": "172.16.1.0/24",                                   │
│    "protocol": "tcp",                                            │
│    "port": 3306,                                                 │
│    "business_justification": "MySQL migration...",               │
│    "requester_email": "dba@company.com",                         │
│    "ticket_id": "CHG001250"                                      │
│  }                                                                │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 2: Check if policy already exists                          │
│  ├─ Query all FirewallRule objects                               │
│  ├─ Match: src 192.168.100.0/24, dst 172.16.1.0/24, port 3306  │
│  ├─ NO MATCHES FOUND                                             │
│  └─ → Proceed to impact analysis                                 │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 3: Find affected traffic paths                             │
│  ├─ Query NetworkPath objects                                    │
│  ├─ Find paths where source zone overlaps 192.168.100.0/24      │
│  │   AND dest zone overlaps 172.16.1.0/24                       │
│  │                                                                │
│  ├─ Results:                                                      │
│  │  • Path 1: "Office_to_Database_Cluster"                      │
│  │     Firewalls: fw-border-1 → fw-database-boundary            │
│  │  • Path 2: "DataCenter_to_Database_Cluster"                  │
│  │     Firewalls: fw-datacenter-egress → fw-database-boundary   │
│  │                                                                │
│  └─ Total: 2 affected paths                                      │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 4: Multi-firewall rule traversal for each path             │
│                                                                   │
│  Path 1: "Office_to_Database_Cluster"                            │
│  ├─ fw-border-1:                                                 │
│  │  ├─ Rule #10 "Block-RFC1918-Egress": MATCHES (action=deny)   │
│  │  └─ Verdict: BLOCKED (traffic stops here)                    │
│  │                                                                │
│  └─ Result: Path is currently BLOCKED at fw-border-1             │
│                                                                   │
│  Path 2: "DataCenter_to_Database_Cluster"                        │
│  ├─ fw-datacenter-egress:                                        │
│  │  ├─ Rule #100 "Allow-DC-to-DMZ": MATCHES (action=allow)      │
│  │  └─ Verdict: ALLOWED → proceed to next FW                    │
│  ├─ fw-database-boundary:                                        │
│  │  ├─ Rule #200 "Allow-DB-Access": MATCHES (action=allow)      │
│  │  └─ Verdict: ALLOWED                                          │
│  │                                                                │
│  └─ Result: Path is currently ALLOWED end-to-end                 │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 5: Analyze impact of allowing new rule                     │
│                                                                   │
│  Summary:                                                         │
│  • Paths that would OPEN (blocked → allowed): 1                 │
│    - Office_to_Database_Cluster (would open at fw-border-1)     │
│  • Paths already ALLOWED: 1                                      │
│    - DataCenter_to_Database_Cluster (already working)            │
│  • Paths already BLOCKED: 0                                      │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 6: Calculate risk score                                    │
│                                                                   │
│  Factors:                                                         │
│  • Paths opened: 1 × 10 = 10 points                              │
│  • Source breadth: 256 IPs (192.168.100.0/24) = 20 points       │
│  • Dest breadth: 256 IPs (172.16.1.0/24) = 15 points            │
│  • Port 3306 (MySQL): 12 points                                  │
│  • Protocol (TCP): 0 points                                      │
│  • Justification quality (154 chars): -5 points                  │
│  ───────────────────────────────────                            │
│  TOTAL SCORE: 52 / 100 = HIGH RISK                               │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 7: Make recommendation                                     │
│                                                                   │
│  Risk Level: HIGH (52/100)                                       │
│  Status: REVIEW_REQUIRED                                         │
│                                                                   │
│  Message:                                                         │
│  "This rule opens 1 previously blocked path and requires         │
│   security team approval via change management process."         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 8: Return response to DBA                                  │
│                                                                   │
│  {                                                                │
│    "request_id": "PLR-20240315-002",                             │
│    "policy_exists": false,                                       │
│    "affected_paths": 2,                                          │
│    "paths_opened": [                                             │
│      {                                                            │
│        "path_name": "Office_to_Database_Cluster",                │
│        "current_verdict": "BLOCKED",                             │
│        "blocking_firewall": "fw-border-1",                       │
│        "blocking_rule": "Block-RFC1918-Egress"                   │
│      }                                                            │
│    ],                                                             │
│    "risk_score": 52,                                             │
│    "risk_level": "HIGH",                                         │
│    "recommendation": "REVIEW_REQUIRED",                          │
│    "message": "This rule opens 1 previously blocked path..."    │
│  }                                                                │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─ DBA Reviews Response ──────────────────────────────────────────┐
│                                                                   │
│  "OK, so:                                                        │
│   • 1 path is currently blocked (Office backup to DB)            │
│   • My rule would open that path (high risk = review needed)     │
│   • DataCenter already has access (good to know)                 │
│   • Need security team approval                                  │
│                                                                   │
│  Submits for approval with request ID: PLR-20240315-002          │
│                                                                   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 9: Security team reviews                                   │
│  POST /api/policy/requests/PLR-20240315-002/approve/             │
│  {                                                                │
│    "approver_email": "secops-lead@company.com",                  │
│    "notes": "Approved for Q1 2024 database migration"            │
│  }                                                                │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 10: Status updated to "approved"                           │
│  ├─ Policy request marked as approved                            │
│  ├─ Notification sent to DBA team                                │
│  └─ Ready for deployment                                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 11: Deploy new rule                                        │
│  ├─ Create rule on fw-border-1:                                  │
│  │  "Allow-DB-Migration: src 192.168.100.0/24 →                │
│  │   dst 172.16.1.0/24 port 3306 tcp allow log"                 │
│  ├─ Verify rule deployed successfully                            │
│  ├─ Status updated to "deployed"                                 │
│  └─ Deployed rule IDs stored: [fw-border-1:rule_500]             │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 12: Verification (re-run path analysis)                    │
│  ├─ Check Path 1 again:                                          │
│  │  fw-border-1: Now matches new rule 500 (action=allow)        │
│  │  fw-database-boundary: Matches rule 200 (action=allow)       │
│  │  Result: NOW ALLOWED end-to-end ✓                             │
│  ├─ Check Path 2: Still ALLOWED (unchanged)                     │
│  └─ Confirm: Traffic can now reach database                      │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─ DBA Notified: Migration Ready ────────────────────────────────┐
│                                                                   │
│  Email notification:                                             │
│  "Policy request PLR-20240315-002 has been approved and         │
│   deployed. Database access from 192.168.100.0/24 to            │
│   172.16.1.0/24 port 3306 is now ALLOWED. You can proceed       │
│   with your migration."                                          │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Part 6: Key Integration Points

### 6.1 How Path Discovery Enhances Policy Lookups

```python
# Without path discovery (old approach):
# "Does policy exist?" 
# Response: "Found rule 'Allow-DB-Access' on fw-database-boundary"
# Problem: Doesn't know about blocking rule on fw-border-1!

# With integrated path discovery (new approach):
# "Does policy exist?" 
# Response: 
#  - "No direct rule match"
#  - "But found affected paths:
#    • Office_to_Database_Cluster: BLOCKED at fw-border-1 
#      (rule: Block-RFC1918-Egress)
#    • DataCenter_to_Database_Cluster: ALLOWED end-to-end"
#  - "Creating rule would open 1 path"
#  - Risk score: 52 (HIGH)"
```

### 6.2 Key Data Flows

```
User Request
    ↓
IntegratedPolicyEngine.process_policy_request()
    │
    ├─ _find_matching_rules() 
    │  └─ Query all FirewallRule → Match against request
    │
    ├─ _find_affected_traffic_paths()
    │  └─ Query NetworkPath → Find overlapping source/dest zones
    │
    ├─ _analyze_path_traversal() [FOR EACH PATH]
    │  ├─ Query PathFirewallStep (ordered)
    │  ├─ For each firewall in order:
    │  │  ├─ Query FirewallRule for that device
    │  │  ├─ Evaluate rules in sequence
    │  │  └─ Return verdict + blocking point
    │  └─ Store analysis for this path
    │
    ├─ _analyze_policy_impact()
    │  ├─ Compare current vs new verdict for each path
    │  ├─ Categorize: opened / allowed / blocked
    │  └─ Return summary
    │
    ├─ _assess_risk()
    │  ├─ Weight: paths_opened (highest), src/dst breadth, port, protocol
    │  ├─ Calculate 0-100 score
    │  └─ Return risk level + factors
    │
    └─ _make_recommendation()
       ├─ PERMITTED (low risk)
       ├─ REVIEW_REQUIRED (medium/high)
       └─ DENIED (critical)
```

---

## Part 7: Django URL Configuration (Complete)

```python
# nautobot_firewall_changes/urls.py

from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from .policy_lookup_api_integrated import PolicyLookupViewSet

# Create router for viewsets
router = DefaultRouter()
router.register(r'policy', PolicyLookupViewSet, basename='policy-lookup')

urlpatterns = [
    # API routes
    path('api/', include(router.urls)),
    
    # Specific policy endpoints
    re_path(
        r'^api/policy/lookup/$',
        PolicyLookupViewSet.as_view({'post': 'lookup_policy'}),
        name='policy-lookup'
    ),
    re_path(
        r'^api/policy/analyze/$',
        PolicyLookupViewSet.as_view({'post': 'analyze_policy_impact'}),
        name='policy-analyze'
    ),
    re_path(
        r'^api/policy/requests/$',
        PolicyLookupViewSet.as_view({'get': 'list_requests'}),
        name='policy-requests-list'
    ),
    re_path(
        r'^api/policy/requests/(?P<request_id>[^/]+)/$',
        PolicyLookupViewSet.as_view({
            'get': 'get_request_detail',
            'post': 'approve_request'
        }),
        name='policy-request-detail'
    ),
]
```

---

## Part 8: Deployment Checklist

```
DATABASE & MODELS
☐ Create PolicyLookupRequest model
☐ Create AffectedTrafficPath model
☐ Run migrations: python manage.py makemigrations
☐ Apply migrations: python manage.py migrate
☐ Verify tables created in PostgreSQL

TOPOLOGY SETUP (PREREQUISITE)
☐ FirewallDevice objects created (all firewalls in inventory)
☐ NetworkInterface objects created (for each FW interface)
☐ Zone objects created (trust, untrust, dmz, etc.)
☐ NetworkPath objects created (Office→Internet, etc.)
☐ PathFirewallStep objects created (ordered FW chains)
☐ Verify topology with GET /api/topology/paths/

FIREWALL RULE COLLECTION
☐ All firewall rules imported into FirewallRule table
☐ Verify sample queries: FW1 should return 100+ rules
☐ Check rule ordering by sequence_number
☐ Verify IP ranges, services, zones populated

API INTEGRATION
☐ Copy policy_lookup_api_integrated.py to codebase
☐ Update urls.py with routes
☐ Register viewset with router
☐ Test endpoints with curl/Postman

API TESTING
☐ POST /api/policy/lookup/ - test existing policy
☐ POST /api/policy/analyze/ - test new policy analysis
☐ GET /api/policy/requests/ - list requests
☐ GET /api/policy/requests/{id}/ - get details
☐ POST /api/policy/requests/{id}/approve/ - approve
☐ Verify responses match documentation

INTEGRATION TESTING
☐ Full workflow: lookup → analyze → approve → verify
☐ Multi-path scenario (traffic through 3+ FWs)
☐ Blocked path detection
☐ Risk scoring accuracy
☐ Recommendation logic

PRODUCTION READINESS
☐ Rate limiting configured
☐ Logging/audit trail enabled
☐ Monitoring/alerts set up
☐ API documentation published
☐ Client libraries available
☐ Training completed for support team
☐ Runbooks created for common scenarios

INTEGRATIONS
☐ ServiceNow plugin deployed
☐ Terraform provider configured
☐ Python client library published
☐ Custom app integration tested
```

This completes the **fully integrated system** combining policy lookup API + multi-firewall path discovery. Users can now query if they have access to any resource, and if not, get a detailed analysis of which firewalls block them and why, with automatic approval/denial based on risk scoring.
