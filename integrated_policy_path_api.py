# Integrated Multi-Firewall Traffic Path Discovery with Policy Lookup API
# Complete end-to-end implementation

import json
import netaddr
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from django.db import models
from django.utils import timezone
from rest_framework import serializers, viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)

# ============================================================================
# ENHANCED DATABASE MODELS
# ============================================================================

class TrafficPathPolicyRequest(models.Model):
    """
    Links a policy lookup request to the traffic paths it affects
    Integrates PolicyLookupRequest with multi-firewall path discovery
    """
    
    REQUEST_STATUS = [
        ('lookup', 'Lookup Only'),
        ('analysis', 'Impact Analysis'),
        ('approved', 'Approved'),
        ('deployed', 'Deployed'),
        ('blocked', 'Blocked by Policy'),
        ('no_path', 'No Path Found'),
    ]
    
    # Link to policy request
    policy_lookup_request = models.OneToOneField(
        'PolicyLookupRequest',
        on_delete=models.CASCADE,
        related_name='traffic_path_analysis'
    )
    
    # Traffic definition
    source_ip = models.CharField(max_length=100)
    dest_ip = models.CharField(max_length=100)
    protocol = models.CharField(max_length=20)
    port = models.IntegerField(null=True, blank=True)
    
    # Network path discovery results
    paths_found = models.IntegerField(default=0)  # How many paths traverse this traffic
    firewalls_involved = models.IntegerField(default=0)  # Total firewalls in paths
    
    # Current verdict across all paths
    overall_verdict = models.CharField(
        max_length=20,
        choices=[('ALLOWED', 'Allowed'), ('BLOCKED', 'Blocked'), ('MIXED', 'Mixed')],
        null=True
    )
    
    # Analysis status
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='lookup')
    
    # Path analysis details
    path_analysis = models.JSONField(default=dict)  # Full traversal results
    blocking_points = models.JSONField(default=list)  # [{"device": "fw1", "rule": "rule1"}]
    
    # Impact summary
    impact_summary = models.JSONField(default=dict)  # High-level impact assessment
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.source_ip} → {self.dest_ip}:{self.port} ({self.overall_verdict})"


class PathTraversalStep(models.Model):
    """
    Individual firewall evaluation step in a traffic path
    Tracks rule evaluation at each firewall
    """
    
    traffic_request = models.ForeignKey(
        TrafficPathPolicyRequest,
        on_delete=models.CASCADE,
        related_name='traversal_steps'
    )
    
    network_path = models.ForeignKey(
        'nautobot_firewall_changes.NetworkPath',
        on_delete=models.CASCADE
    )
    
    firewall = models.ForeignKey(
        'nautobot_firewall_changes.FirewallDevice',
        on_delete=models.CASCADE
    )
    
    step_order = models.IntegerField()  # Order in traversal
    
    # Evaluation results
    rules_evaluated = models.IntegerField()
    matching_rules = models.JSONField(default=list)
    verdict = models.CharField(
        max_length=20,
        choices=[('ALLOWED', 'Allowed'), ('BLOCKED', 'Blocked'), ('CONTINUE', 'Continue')]
    )
    
    blocking_rule = models.ForeignKey(
        'nautobot_firewall_changes.FirewallRule',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    
    # Details for this step
    step_details = models.JSONField(default=dict)
    warnings = models.JSONField(default=list)
    
    class Meta:
        ordering = ['step_order']


class PolicyPathCorrelation(models.Model):
    """
    Correlates a firewall rule change with traffic paths it affects
    Used to show which changes impact which traffic flows
    """
    
    firewall_change = models.ForeignKey(
        'nautobot_firewall_changes.FirewallChange',
        on_delete=models.CASCADE,
        related_name='path_correlations'
    )
    
    affected_paths = models.ManyToManyField(
        'nautobot_firewall_changes.NetworkPath',
        related_name='affecting_changes'
    )
    
    # Impact type
    IMPACT_TYPES = [
        ('opens', 'Opens Path'),
        ('closes', 'Closes Path'),
        ('modifies', 'Modifies Path'),
        ('shadows', 'Shadows Rules'),
    ]
    
    impact_type = models.CharField(max_length=20, choices=IMPACT_TYPES)
    
    # Risk assessment
    risk_score = models.IntegerField()
    is_critical = models.BooleanField(default=False)
    
    analysis = models.JSONField(default=dict)
    
    class Meta:
        unique_together = ('firewall_change', 'impact_type')


# ============================================================================
# INTEGRATED POLICY LOOKUP ENGINE WITH PATH DISCOVERY
# ============================================================================

class IntegratedPolicyPathEngine:
    """
    Unified engine combining:
    1. Policy lookup (do rules exist?)
    2. Multi-firewall path discovery (what paths exist?)
    3. Rule traversal (will traffic be blocked?)
    4. Risk assessment (how risky?)
    """
    
    def __init__(self):
        from nautobot_firewall_changes.models import (
            FirewallRule, NetworkPath, PathFirewallStep, 
            FirewallDevice, FirewallConfiguration
        )
        self.FirewallRule = FirewallRule
        self.NetworkPath = NetworkPath
        self.PathFirewallStep = PathFirewallStep
        self.FirewallDevice = FirewallDevice
        self.FirewallConfiguration = FirewallConfiguration
    
    def analyze_traffic_request(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: int = None,
        business_justification: str = None
    ) -> Dict:
        """
        Complete end-to-end analysis:
        1. Find all traffic paths matching this traffic
        2. For each path, evaluate all firewalls in order
        3. Determine verdict and blocking points
        4. Calculate risk score
        5. Generate recommendations
        
        Returns comprehensive analysis with:
        - All paths found
        - Verdict for each path
        - Overall verdict (ALLOWED/BLOCKED/MIXED)
        - Blocking points with rules
        - Risk assessment
        - Recommendations
        """
        
        logger.info(f"Analyzing: {source_ip} → {dest_ip}:{port} ({protocol})")
        
        src_net = netaddr.IPNetwork(source_ip)
        dst_net = netaddr.IPNetwork(dest_ip)
        
        # Step 1: Find applicable traffic paths
        paths = self._find_applicable_paths(src_net, dst_net)
        
        if not paths:
            return {
                'status': 'NO_PATH',
                'message': 'No traffic paths found for this traffic',
                'paths': [],
                'overall_verdict': 'UNKNOWN',
            }
        
        logger.info(f"Found {len(paths)} applicable traffic paths")
        
        # Step 2: Analyze each path through all firewalls
        path_analyses = []
        verdicts = []
        all_blocking_points = []
        
        for path in paths:
            path_analysis = self._analyze_path_completely(
                path, src_net, dst_net, protocol, port
            )
            
            path_analyses.append(path_analysis)
            verdicts.append(path_analysis['verdict'])
            
            if path_analysis['verdict'] == 'BLOCKED':
                all_blocking_points.extend(path_analysis['blocking_points'])
        
        # Step 3: Determine overall verdict
        if all(v == 'ALLOWED' for v in verdicts):
            overall_verdict = 'ALLOWED'
        elif any(v == 'BLOCKED' for v in verdicts):
            overall_verdict = 'BLOCKED'
        else:
            overall_verdict = 'MIXED'  # Some paths allowed, some blocked
        
        # Step 4: Calculate risk score
        risk_score = self._calculate_path_risk(
            source_ip, dest_ip, protocol, port,
            path_analyses, overall_verdict
        )
        
        # Step 5: Generate recommendations
        recommendations = self._generate_path_recommendations(
            path_analyses, all_blocking_points, risk_score,
            business_justification
        )
        
        # Step 6: Determine policy status
        status = self._determine_policy_status(
            overall_verdict, risk_score, all_blocking_points
        )
        
        analysis = {
            'status': status,
            'overall_verdict': overall_verdict,
            'paths_analyzed': len(path_analyses),
            'path_details': path_analyses,
            'blocking_points': all_blocking_points,
            'risk_score': risk_score,
            'risk_level': self._score_to_level(risk_score),
            'recommendations': recommendations,
            'message': self._build_analysis_message(
                overall_verdict, risk_score, len(path_analyses), status
            ),
        }
        
        logger.info(f"Analysis complete: {status} (Risk: {risk_score}/100)")
        
        return analysis
    
    def _find_applicable_paths(
        self,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork
    ) -> List:
        """
        Find all NetworkPaths that this traffic would traverse
        
        A path is applicable if:
        - Source network overlaps with path's source zone
        - Destination network overlaps with path's destination zone
        """
        
        paths = self.NetworkPath.objects.all()
        applicable = []
        
        for path in paths:
            try:
                path_src = netaddr.IPNetwork(path.source_network)
                path_dst = netaddr.IPNetwork(path.dest_network)
                
                # Check overlap
                if src_net.overlaps(path_src) and dst_net.overlaps(path_dst):
                    applicable.append(path)
                    logger.debug(f"Path '{path.name}' matches traffic")
            except:
                continue
        
        # If no specific paths found, return all paths as candidates
        if not applicable:
            applicable = list(paths[:10])
            logger.info(f"No specific paths matched, analyzing {len(applicable)} candidate paths")
        
        return applicable
    
    def _analyze_path_completely(
        self,
        path,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        protocol: str,
        port: int = None
    ) -> Dict:
        """
        Analyze a single traffic path through all firewalls
        
        Returns verdict, blocking points, details for this path
        """
        
        # Get firewalls in this path (ordered)
        path_steps = PathFirewallStep.objects.filter(path=path).order_by('order')
        
        if not path_steps:
            return {
                'path_name': path.name,
                'verdict': 'UNKNOWN',
                'blocking_points': [],
                'firewall_steps': [],
            }
        
        firewall_steps = []
        blocking_points = []
        overall_verdict = 'ALLOWED'  # Optimistic default
        
        # Evaluate each firewall in order
        for step in path_steps:
            device = step.firewall_device
            
            step_analysis = self._evaluate_firewall_step(
                device, src_net, dst_net, protocol, port, step
            )
            
            firewall_steps.append(step_analysis)
            
            if step_analysis['verdict'] == 'BLOCKED':
                overall_verdict = 'BLOCKED'
                blocking_points.append({
                    'firewall': device.name,
                    'rule': step_analysis.get('blocking_rule'),
                    'sequence': step_analysis.get('blocking_rule_seq'),
                    'reason': step_analysis.get('block_reason'),
                })
                break  # Stop at first blocking point
        
        return {
            'path_name': path.name,
            'source_zone': path.source_zone,
            'dest_zone': path.destination_zone,
            'firewall_count': len(firewall_steps),
            'verdict': overall_verdict,
            'blocking_points': blocking_points,
            'firewall_steps': firewall_steps,
            'traversal_time_ms': sum(s.get('eval_time_ms', 0) for s in firewall_steps),
        }
    
    def _evaluate_firewall_step(
        self,
        device,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        protocol: str,
        port: int = None,
        path_step = None
    ) -> Dict:
        """
        Evaluate rules on a single firewall for this traffic
        
        Returns which rules matched, verdict, blocking rule if any
        """
        
        logger.debug(f"Evaluating {device.name}")
        
        # Get all rules for this device (in sequence order)
        rules = self.FirewallRule.objects.filter(
            device=device
        ).order_by('sequence_number')
        
        matched_rules = []
        blocking_rule = None
        blocking_rule_seq = None
        verdict = 'UNKNOWN'
        eval_time = 0
        
        import time
        start = time.time()
        
        # Evaluate rules in order until we hit explicit action
        for rule in rules:
            if rule.disabled:
                continue
            
            # Check if traffic matches rule
            is_match = self._rule_matches_traffic(rule, src_net, dst_net, protocol, port)
            
            if is_match:
                matched_rules.append({
                    'rule_id': rule.rule_id,
                    'rule_name': rule.rule_name,
                    'action': rule.action,
                    'logging': rule.logging_enabled,
                    'sequence': rule.sequence_number,
                })
                
                # Determine verdict based on action
                if rule.action in ['deny', 'drop', 'reject']:
                    verdict = 'BLOCKED'
                    blocking_rule = rule.rule_name
                    blocking_rule_seq = rule.sequence_number
                    logger.debug(f"  BLOCKED by rule {rule.sequence_number}: {rule.rule_name}")
                    break
                
                elif rule.action == 'allow':
                    verdict = 'ALLOWED'
                    logger.debug(f"  ALLOWED by rule {rule.sequence_number}: {rule.rule_name}")
                    break
        
        eval_time = (time.time() - start) * 1000
        
        # Default action if no rule matched
        if verdict == 'UNKNOWN':
            verdict = 'BLOCKED'  # Pessimistic: default deny
        
        return {
            'firewall': device.name,
            'rules_evaluated': rules.count(),
            'rules_matched': len(matched_rules),
            'matched_rules': matched_rules,
            'verdict': verdict,
            'blocking_rule': blocking_rule,
            'blocking_rule_seq': blocking_rule_seq,
            'block_reason': 'Explicit deny rule' if verdict == 'BLOCKED' else None,
            'eval_time_ms': eval_time,
        }
    
    def _rule_matches_traffic(
        self,
        rule,
        src_net: netaddr.IPNetwork,
        dst_net: netaddr.IPNetwork,
        protocol: str,
        port: int = None
    ) -> bool:
        """Determine if a rule matches the traffic"""
        
        # Check source
        if rule.source_ips and 'any' not in rule.source_ips:
            src_match = any(
                self._ip_in_range(src_net, src_range)
                for src_range in rule.source_ips
            )
            if not src_match:
                return False
        
        # Check destination
        if rule.dest_ips and 'any' not in rule.dest_ips:
            dst_match = any(
                self._ip_in_range(dst_net, dst_range)
                for dst_range in rule.dest_ips
            )
            if not dst_match:
                return False
        
        # Check protocol/port
        if rule.services and 'any' not in rule.services:
            service_match = any(
                self._service_matches(protocol, port, rule_service)
                for rule_service in rule.services
            )
            if not service_match:
                return False
        
        return True
    
    def _ip_in_range(self, traffic_net: netaddr.IPNetwork, rule_range: str) -> bool:
        """Check if traffic overlaps with rule range"""
        
        if rule_range == 'any':
            return True
        
        try:
            rule_net = netaddr.IPNetwork(rule_range)
            return traffic_net.overlaps(rule_net)
        except:
            return False
    
    def _service_matches(self, protocol: str, port: int = None, rule_service: str = None) -> bool:
        """Check if service matches rule"""
        
        if not rule_service or rule_service == 'any':
            return True
        
        if '/' in rule_service:
            rule_proto, rule_port = rule_service.split('/')
            
            if protocol != 'all' and rule_proto not in ['all', protocol]:
                return False
            
            if port and rule_port.isdigit() and port != int(rule_port):
                return False
            
            return True
        
        return True
    
    def _calculate_path_risk(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: int,
        path_analyses: List[Dict],
        overall_verdict: str
    ) -> int:
        """
        Calculate risk score based on:
        1. IP scope (breadth)
        2. Port selection
        3. Number of paths affected
        4. Verdict across paths
        """
        
        score = 0
        
        # Source breadth (0-30)
        src_net = netaddr.IPNetwork(source_ip)
        if src_net.size > 1:
            score += min(30, int(20 * (32 - src_net.prefixlen) / 32))
        
        # Destination breadth (0-20)
        dst_net = netaddr.IPNetwork(dest_ip)
        if dst_net.size > 1:
            score += min(20, int(15 * (32 - dst_net.prefixlen) / 32))
        
        # Port risk (0-15)
        risky_ports = {22, 80, 443, 3306, 5432, 3389}
        if port and port in risky_ports:
            score += 15
        elif protocol == 'all':
            score += 10
        
        # Path verdict impact (0-20)
        blocked_count = sum(1 for p in path_analyses if p['verdict'] == 'BLOCKED')
        mixed_count = sum(1 for p in path_analyses if p['verdict'] == 'MIXED')
        
        if overall_verdict == 'BLOCKED':
            score += 10
        elif overall_verdict == 'MIXED':
            score += 5
        
        # Multiple paths (0-15)
        score += min(15, len(path_analyses) * 3)
        
        return max(0, min(100, score))
    
    def _generate_path_recommendations(
        self,
        path_analyses: List[Dict],
        blocking_points: List[Dict],
        risk_score: int,
        justification: str = None
    ) -> List[str]:
        """Generate specific recommendations based on path analysis"""
        
        recommendations = []
        
        # Risk-based
        if risk_score >= 75:
            recommendations.append(
                "🚨 CRITICAL RISK: Multiple traffic paths affected with blocking - "
                "requires director-level security review"
            )
        elif risk_score >= 50:
            recommendations.append(
                "⚠️ HIGH RISK: Multiple traffic paths affected - "
                "requires formal security approval"
            )
        
        # Blocking points
        if blocking_points:
            devices = set(bp['firewall'] for bp in blocking_points)
            recommendations.append(
                f"Traffic is blocked at: {', '.join(devices)}. "
                f"Must remove or modify blocking rules: "
                f"{', '.join(bp['rule'] for bp in blocking_points if bp['rule'])}"
            )
        
        # Path coverage
        allowed_paths = sum(1 for p in path_analyses if p['verdict'] == 'ALLOWED')
        blocked_paths = sum(1 for p in path_analyses if p['verdict'] == 'BLOCKED')
        
        if blocked_paths > 0 and allowed_paths == 0:
            recommendations.append(
                f"All {len(path_analyses)} traffic paths are BLOCKED - "
                "this traffic cannot flow without policy changes"
            )
        elif blocked_paths > 0:
            recommendations.append(
                f"{blocked_paths} of {len(path_analyses)} paths are blocked - "
                "consider alternative routing or rule modifications"
            )
        
        # Logging
        if not justification or len(justification) < 50:
            recommendations.append(
                "Provide detailed business justification (50+ characters) "
                "to justify policy changes"
            )
        
        # Scope
        if len(path_analyses) > 5:
            recommendations.append(
                f"This rule affects {len(path_analyses)} traffic paths - "
                "ensure impact is understood and accepted"
            )
        
        recommendations.append(
            "Enable logging on all new rules to track usage and detect misuse"
        )
        
        return recommendations
    
    def _determine_policy_status(
        self,
        overall_verdict: str,
        risk_score: int,
        blocking_points: List[Dict]
    ) -> str:
        """Determine if policy can be created/approved"""
        
        if overall_verdict == 'ALLOWED' and risk_score < 25:
            return 'PERMITTED'
        elif overall_verdict == 'BLOCKED' and len(blocking_points) > 0:
            if risk_score >= 75:
                return 'BLOCKED'  # Blocked by critical policies
            else:
                return 'REVIEW_REQUIRED'
        elif risk_score >= 75:
            return 'DENIED'
        elif risk_score >= 50 or len(blocking_points) > 0:
            return 'REVIEW_REQUIRED'
        else:
            return 'PERMITTED'
    
    def _score_to_level(self, score: int) -> str:
        """Convert score to level"""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _build_analysis_message(
        self,
        verdict: str,
        risk_score: int,
        path_count: int,
        status: str
    ) -> str:
        """Build human-readable summary message"""
        
        if status == 'NO_PATH':
            return "No traffic paths found for this traffic"
        
        verdict_str = f"Traffic verdict: {verdict} across {path_count} paths"
        
        if verdict == 'BLOCKED':
            return (
                f"{verdict_str}. Traffic is BLOCKED by existing policies. "
                f"Risk: {risk_score}/100. Status: {status}"
            )
        elif verdict == 'ALLOWED':
            return (
                f"{verdict_str}. Traffic is ALLOWED. "
                f"Risk: {risk_score}/100. Status: {status}"
            )
        else:  # MIXED
            return (
                f"{verdict_str}. Some paths allowed, others blocked. "
                f"Risk: {risk_score}/100. Status: {status}"
            )


# ============================================================================
# INTEGRATED REST API VIEWSET
# ============================================================================

class IntegratedPolicyPathSerializer(serializers.Serializer):
    """Validate integrated policy + path request"""
    
    source_ip = serializers.CharField(required=True)
    dest_ip = serializers.CharField(required=True)
    protocol = serializers.ChoiceField(choices=['tcp', 'udp', 'icmp', 'all'])
    port = serializers.IntegerField(required=False, allow_null=True)
    business_justification = serializers.CharField(required=True)
    requester_email = serializers.EmailField(required=True)
    ticket_id = serializers.CharField(required=False, allow_blank=True)


class IntegratedPolicyPathViewSet(viewsets.ViewSet):
    """
    Integrated API combining policy lookup with multi-firewall path discovery
    
    Endpoints:
    - POST /api/integrated/policy-path/analyze/ - Analyze traffic with path discovery
    - GET /api/integrated/policy-path/requests/ - List requests
    - GET /api/integrated/policy-path/requests/{id}/ - Get request details
    - POST /api/integrated/policy-path/requests/{id}/visualize/ - Get visual representation
    """
    
    permission_classes = [IsAuthenticated]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.engine = IntegratedPolicyPathEngine()
    
    @action(detail=False, methods=['post'], url_path='analyze')
    def analyze_traffic_with_paths(self, request):
        """
        POST /api/integrated/policy-path/analyze/
        
        Comprehensive traffic analysis with multi-firewall path discovery
        
        Request:
        {
            "source_ip": "192.168.1.0/24",
            "dest_ip": "172.16.0.0/16",
            "protocol": "tcp",
            "port": 3306,
            "business_justification": "Database replication for new data center",
            "requester_email": "dba@company.com",
            "ticket_id": "CHG001250"
        }
        
        Response:
        {
            "request_id": "IPP-20240315-001",
            "status": "REVIEW_REQUIRED",
            "overall_verdict": "BLOCKED",
            "paths_analyzed": 3,
            "path_details": [
                {
                    "path_name": "Office_to_DataCenter",
                    "source_zone": "trust",
                    "dest_zone": "dmz",
                    "firewall_count": 2,
                    "verdict": "BLOCKED",
                    "blocking_points": [
                        {
                            "firewall": "fw-border-1",
                            "rule": "Block-RFC1918-Route-Out",
                            "sequence": 5
                        }
                    ],
                    "firewall_steps": [
                        {
                            "firewall": "fw-border-1",
                            "rules_evaluated": 45,
                            "rules_matched": 1,
                            "verdict": "BLOCKED",
                            "blocking_rule": "Block-RFC1918-Route-Out"
                        },
                        {
                            "firewall": "fw-dc-boundary",
                            "rules_evaluated": 38,
                            "rules_matched": 0,
                            "verdict": "UNKNOWN"
                        }
                    ]
                },
                {
                    "path_name": "Office_to_AWS",
                    "verdict": "ALLOWED"
                },
                {
                    "path_name": "Office_to_Azure",
                    "verdict": "ALLOWED"
                }
            ],
            "blocking_points": [
                {
                    "firewall": "fw-border-1",
                    "rule": "Block-RFC1918-Route-Out",
                    "sequence": 5
                }
            ],
            "risk_score": 62,
            "risk_level": "HIGH",
            "recommendations": [
                "Traffic is blocked at: fw-border-1. Must remove or modify blocking rules: Block-RFC1918-Route-Out",
                "1 of 3 paths are blocked - consider alternative routing or rule modifications",
                "This rule affects 3 traffic paths - ensure impact is understood and accepted",
                "Enable logging on all new rules to track usage and detect misuse"
            ],
            "message": "Traffic verdict: BLOCKED across 3 paths. Traffic is BLOCKED by existing policies. Risk: 62/100. Status: REVIEW_REQUIRED",
            "business_justification": "Database replication for new data center",
            "requester_email": "dba@company.com",
            "ticket_id": "CHG001250"
        }
        """
        
        serializer = IntegratedPolicyPathSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        # Generate unique request ID
        request_id = self._generate_request_id()
        
        # Perform integrated analysis
        analysis = self.engine.analyze_traffic_request(
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            business_justification=data['business_justification']
        )
        
        # Store in database
        from nautobot_firewall_changes.models import (
            PolicyLookupRequest, FirewallDevice
        )
        
        policy_request = PolicyLookupRequest.objects.create(
            request_id=request_id,
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            business_justification=data['business_justification'],
            requester_email=data['requester_email'],
            ticket_id=data.get('ticket_id'),
            status=analysis['status'],
            is_new_request=True,
            impact_analysis=analysis,
            risk_score=analysis['risk_score'],
        )
        
        # Create traffic path analysis record
        traffic_analysis = TrafficPathPolicyRequest.objects.create(
            policy_lookup_request=policy_request,
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            paths_found=analysis['paths_analyzed'],
            firewalls_involved=self._count_firewalls(analysis['path_details']),
            overall_verdict=analysis['overall_verdict'],
            status=analysis['status'],
            path_analysis=analysis,
            blocking_points=analysis['blocking_points'],
            impact_summary={
                'risk_score': analysis['risk_score'],
                'risk_level': analysis['risk_level'],
                'status': analysis['status'],
            }
        )
        
        # Create traversal steps
        for path_analysis in analysis['path_details']:
            for i, fw_step in enumerate(path_analysis.get('firewall_steps', [])):
                PathTraversalStep.objects.create(
                    traffic_request=traffic_analysis,
                    network_path_id=self._get_path_id(path_analysis['path_name']),
                    firewall=self._get_firewall(fw_step['firewall']),
                    step_order=i,
                    rules_evaluated=fw_step['rules_evaluated'],
                    matching_rules=fw_step['matched_rules'],
                    verdict=fw_step['verdict'],
                    step_details=fw_step,
                )
        
        logger.info(f"Integrated analysis {request_id}: {analysis['status']}")
        
        response_data = {
            'request_id': request_id,
            **analysis,
            'business_justification': data['business_justification'],
            'requester_email': data['requester_email'],
            'ticket_id': data.get('ticket_id'),
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'], url_path='requests/(?P<request_id>[^/.]+)/visualize')
    def visualize_traffic_path(self, request, request_id=None):
        """
        POST /api/integrated/policy-path/requests/{request_id}/visualize/
        
        Generate visual representation of traffic path analysis
        
        Response:
        {
            "request_id": "IPP-20240315-001",
            "diagram": "... SVG diagram ...",
            "ascii_diagram": "
Source: 192.168.1.0/24 (Office Trust)
                |
                v
    ╔════════════════════════════╗
    ║   fw-border-1              ║
    ║ Eval 45 rules, Match: 1    ║
    ║ ✗ BLOCKED by rule #5       ║
    ║ 'Block-RFC1918-Route-Out'  ║
    ╚════════════════════════════╝
                |
                v
    ❌ TRAFFIC BLOCKED HERE
    
    Path: Office_to_DataCenter (BLOCKED)
    
---

Source: 192.168.1.0/24 (Office Trust)
                |
                v
    ╔════════════════════════════╗
    ║   fw-border-1              ║
    ║ Eval 45 rules              ║
    ║ ✓ ALLOWED by rule #250     ║
    ╚════════════════════════════╝
                |
                v
    ╔════════════════════════════╗
    ║   fw-aws-boundary          ║
    ║ Eval 30 rules              ║
    ║ ✓ ALLOWED (default)        ║
    ╚════════════════════════════╝
                |
                v
Destination: 172.31.0.0/16 (AWS Cloud)

    Path: Office_to_AWS (ALLOWED)
            "
        }
        """
        
        try:
            traffic_analysis = TrafficPathPolicyRequest.objects.get(
                policy_lookup_request__request_id=request_id
            )
        except TrafficPathPolicyRequest.DoesNotExist:
            return Response(
                {'error': f'Request {request_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Generate diagrams
        svg_diagram = self._generate_svg_diagram(traffic_analysis)
        ascii_diagram = self._generate_ascii_diagram(traffic_analysis)
        
        return Response({
            'request_id': request_id,
            'diagram_svg': svg_diagram,
            'diagram_ascii': ascii_diagram,
            'overall_verdict': traffic_analysis.overall_verdict,
            'paths_analyzed': traffic_analysis.paths_found,
        })
    
    @action(detail=False, methods=['get'], url_path='requests')
    def list_requests(self, request):
        """List all integrated policy-path requests"""
        
        status_filter = request.query_params.get('status')
        verdict_filter = request.query_params.get('verdict')
        days = int(request.query_params.get('days', 30))
        limit = int(request.query_params.get('limit', 50))
        
        since = timezone.now() - timedelta(days=days)
        
        queryset = TrafficPathPolicyRequest.objects.filter(created_at__gte=since)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        if verdict_filter:
            queryset = queryset.filter(overall_verdict=verdict_filter)
        
        queryset = queryset.order_by('-created_at')[:limit]
        
        results = [
            {
                'request_id': r.policy_lookup_request.request_id,
                'source_ip': r.source_ip,
                'dest_ip': r.dest_ip,
                'protocol': r.protocol,
                'port': r.port,
                'overall_verdict': r.overall_verdict,
                'status': r.status,
                'paths_found': r.paths_found,
                'firewalls_involved': r.firewalls_involved,
                'risk_score': r.impact_summary.get('risk_score'),
                'requester_email': r.policy_lookup_request.requester_email,
                'created_at': r.created_at,
            }
            for r in queryset
        ]
        
        return Response({
            'count': len(results),
            'results': results,
        })
    
    @action(detail=False, methods=['get'], url_path='requests/(?P<request_id>[^/.]+)$')
    def get_request_detail(self, request, request_id=None):
        """Get detailed information about a specific traffic path request"""
        
        try:
            traffic_analysis = TrafficPathPolicyRequest.objects.get(
                policy_lookup_request__request_id=request_id
            )
        except TrafficPathPolicyRequest.DoesNotExist:
            return Response(
                {'error': f'Request {request_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get traversal steps
        steps = PathTraversalStep.objects.filter(
            traffic_request=traffic_analysis
        ).order_by('step_order')
        
        traversal_details = []
        for step in steps:
            traversal_details.append({
                'step_order': step.step_order,
                'firewall': step.firewall.name,
                'rules_evaluated': step.rules_evaluated,
                'matching_rules': step.matching_rules,
                'verdict': step.verdict,
                'blocking_rule': step.blocking_rule.rule_name if step.blocking_rule else None,
                'warnings': step.warnings,
            })
        
        return Response({
            'request_id': request_id,
            'source_ip': traffic_analysis.source_ip,
            'dest_ip': traffic_analysis.dest_ip,
            'protocol': traffic_analysis.protocol,
            'port': traffic_analysis.port,
            'overall_verdict': traffic_analysis.overall_verdict,
            'status': traffic_analysis.status,
            'paths_found': traffic_analysis.paths_found,
            'firewalls_involved': traffic_analysis.firewalls_involved,
            'risk_score': traffic_analysis.impact_summary.get('risk_score'),
            'risk_level': traffic_analysis.impact_summary.get('risk_level'),
            'blocking_points': traffic_analysis.blocking_points,
            'path_analysis': traffic_analysis.path_analysis,
            'traversal_details': traversal_details,
            'recommendations': traffic_analysis.path_analysis.get('recommendations', []),
            'requester_email': traffic_analysis.policy_lookup_request.requester_email,
            'ticket_id': traffic_analysis.policy_lookup_request.ticket_id,
            'created_at': traffic_analysis.created_at,
        })
    
    def _generate_request_id(self) -> str:
        """Generate unique integrated request ID"""
        from datetime import datetime
        import random
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = f"{random.randint(1000, 9999)}"
        
        return f"IPP-{timestamp}-{random_suffix}"
    
    def _count_firewalls(self, path_details: List[Dict]) -> int:
        """Count unique firewalls across all paths"""
        firewalls = set()
        for path in path_details:
            for step in path.get('firewall_steps', []):
                firewalls.add(step['firewall'])
        return len(firewalls)
    
    def _get_path_id(self, path_name: str) -> int:
        """Get NetworkPath ID by name"""
        from nautobot_firewall_changes.models import NetworkPath
        try:
            return NetworkPath.objects.get(name=path_name).id
        except:
            return None
    
    def _get_firewall(self, device_name: str):
        """Get FirewallDevice by name"""
        from nautobot_firewall_changes.models import FirewallDevice
        try:
            return FirewallDevice.objects.get(name=device_name)
        except:
            return None
    
    def _generate_svg_diagram(self, traffic_analysis: TrafficPathPolicyRequest) -> str:
        """Generate SVG diagram of traffic path"""
        # Simplified SVG generation
        return f"""
        <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
            <text x="10" y="30" font-size="20" font-weight="bold">
                Traffic Path Analysis: {traffic_analysis.source_ip} → {traffic_analysis.dest_ip}
            </text>
            <text x="10" y="60" font-size="14">
                Verdict: {traffic_analysis.overall_verdict} | Paths: {traffic_analysis.paths_found}
            </text>
            <!-- Path details would be rendered here -->
        </svg>
        """
    
    def _generate_ascii_diagram(self, traffic_analysis: TrafficPathPolicyRequest) -> str:
        """Generate ASCII diagram of traffic path"""
        
        lines = [
            f"\nTraffic Path Analysis: {traffic_analysis.source_ip} → {traffic_analysis.dest_ip}\n",
            f"Overall Verdict: {traffic_analysis.overall_verdict} (Risk: {traffic_analysis.impact_summary.get('risk_score')}/100)\n",
            "=" * 80,
        ]
        
        for path in traffic_analysis.path_analysis.get('path_details', []):
            lines.append(f"\nPath: {path['path_name']}")
            lines.append(f"  Verdict: {path['verdict']}")
            lines.append(f"  Firewalls: {path['firewall_count']}")
            
            for fw_step in path.get('firewall_steps', []):
                lines.append(f"\n  ┌─ {fw_step['firewall']}")
                lines.append(f"  │  Rules evaluated: {fw_step['rules_evaluated']}")
                lines.append(f"  │  Rules matched: {fw_step['rules_matched']}")
                lines.append(f"  │  Verdict: {fw_step['verdict']}")
                if fw_step['blocking_rule']:
                    lines.append(f"  │  Blocked by: {fw_step['blocking_rule']}")
                lines.append(f"  └─")
        
        lines.append("\n" + "=" * 80)
        
        return "\n".join(lines)
