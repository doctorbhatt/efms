# policy_lookup_api.py
# API endpoint for real-time firewall policy lookup and impact analysis
# Accepts Source IP, Dest IP, Protocol, Port, and Business Justification
# Returns existing policies or impact analysis for new policies

from rest_framework import serializers, viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from typing import Dict, List, Tuple, Optional
import netaddr
import logging
import hashlib
import json

logger = logging.getLogger(__name__)


# ============================================================================
# SERIALIZERS
# ============================================================================

class PolicyLookupRequestSerializer(serializers.Serializer):
    """Validate incoming policy lookup/analysis request"""
    
    source_ip = serializers.CharField(
        required=True,
        help_text="Source IP address (e.g., 192.168.1.100 or 192.168.1.0/24)"
    )
    dest_ip = serializers.CharField(
        required=True,
        help_text="Destination IP address (e.g., 10.0.1.50 or 10.0.0.0/24)"
    )
    protocol = serializers.ChoiceField(
        choices=['tcp', 'udp', 'icmp', 'all'],
        help_text="Protocol (tcp, udp, icmp, all)"
    )
    port = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=1,
        max_value=65535,
        help_text="Destination port (optional, 1-65535)"
    )
    business_justification = serializers.CharField(
        required=True,
        help_text="Why this traffic needs to be allowed"
    )
    requester_email = serializers.EmailField(
        required=True,
        help_text="Email of person requesting policy"
    )
    ticket_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Change ticket ID (e.g., CHG001234)"
    )
    
    def validate(self, data):
        """Cross-field validation"""
        
        # Validate IP addresses
        try:
            src_net = netaddr.IPNetwork(data['source_ip'])
        except netaddr.AddrFormatError:
            raise serializers.ValidationError("Invalid source IP format")
        
        try:
            dst_net = netaddr.IPNetwork(data['dest_ip'])
        except netaddr.AddrFormatError:
            raise serializers.ValidationError("Invalid destination IP format")
        
        # Port required if TCP/UDP
        if data['protocol'] in ['tcp', 'udp'] and not data.get('port'):
            raise serializers.ValidationError("Port required for TCP/UDP protocols")
        
        return data


class MatchingRuleSerializer(serializers.Serializer):
    """Serialize matching firewall rules"""
    
    device_name = serializers.CharField()
    rule_id = serializers.CharField()
    rule_name = serializers.CharField()
    action = serializers.CharField()
    sequence_number = serializers.IntegerField()
    logging_enabled = serializers.BooleanField()
    source_zones = serializers.ListField(child=serializers.CharField())
    dest_zones = serializers.ListField(child=serializers.CharField())
    created_date = serializers.DateTimeField()
    change_ticket = serializers.CharField(allow_null=True)


class PolicyExistsResponseSerializer(serializers.Serializer):
    """Response when matching policy already exists"""
    
    policy_exists = serializers.BooleanField()
    matching_rules = MatchingRuleSerializer(many=True)
    verdict = serializers.CharField(help_text="ALLOWED or BLOCKED")
    blocking_firewall = serializers.CharField(allow_null=True)
    blocking_rule = serializers.CharField(allow_null=True)
    message = serializers.CharField()
    details = serializers.DictField()


class PathImpactSerializer(serializers.Serializer):
    """Impact analysis for a traffic path"""
    
    path_name = serializers.CharField()
    old_verdict = serializers.CharField(allow_null=True)
    new_verdict = serializers.CharField()
    verdict_changed = serializers.BooleanField()
    blocking_firewall = serializers.CharField(allow_null=True)
    blocking_rule = serializers.CharField(allow_null=True)
    warnings = serializers.ListField(child=serializers.CharField())


class PolicyImpactAnalysisResponseSerializer(serializers.Serializer):
    """Response for new policy impact analysis"""
    
    request_id = serializers.CharField()
    status = serializers.CharField(help_text="PERMITTED, DENIED, REVIEW_REQUIRED")
    message = serializers.CharField()
    
    # Path analysis
    paths_analyzed = serializers.IntegerField()
    paths_blocked = serializers.IntegerField()
    paths_opened = PathImpactSerializer(many=True)
    paths_already_blocked = PathImpactSerializer(many=True)
    
    # Risk assessment
    risk_score = serializers.IntegerField(help_text="0-100")
    risk_level = serializers.CharField(help_text="LOW, MEDIUM, HIGH, CRITICAL")
    
    # Recommendations
    recommendations = serializers.ListField(child=serializers.CharField())
    
    # Business justification
    business_justification = serializers.CharField()
    requester_email = serializers.CharField()
    ticket_id = serializers.CharField(allow_null=True)


# ============================================================================
# MODELS FOR POLICY LOOKUP TRACKING
# ============================================================================

from django.db import models
from nautobot.core.models import BaseModel

class PolicyLookupRequest(BaseModel):
    """Track all policy lookup requests"""
    
    STATUS_CHOICES = [
        ('exists', 'Policy Exists'),
        ('new', 'New Policy Request'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('deployed', 'Deployed'),
    ]
    
    request_id = models.CharField(max_length=50, unique=True)
    source_ip = models.CharField(max_length=100)
    dest_ip = models.CharField(max_length=100)
    protocol = models.CharField(max_length=20)
    port = models.IntegerField(null=True, blank=True)
    
    business_justification = models.TextField()
    requester_email = models.EmailField()
    ticket_id = models.CharField(max_length=50, null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # Analysis results
    policy_exists = models.BooleanField(default=False)
    existing_rules = models.JSONField(null=True, blank=True)
    
    is_new_request = models.BooleanField(default=False)
    impact_analysis = models.JSONField(null=True, blank=True)
    risk_score = models.IntegerField(null=True, blank=True)
    
    approved_by = models.CharField(max_length=100, null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    
    deployed_at = models.DateTimeField(null=True, blank=True)
    deployed_rule_ids = models.JSONField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['source_ip', 'dest_ip']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.request_id}: {self.source_ip} → {self.dest_ip}:{self.port}"


class ExistingPolicyMatch(BaseModel):
    """Link between lookup request and matching rules"""
    
    lookup_request = models.ForeignKey(
        PolicyLookupRequest,
        on_delete=models.CASCADE,
        related_name='matching_policies'
    )
    firewall_rule = models.ForeignKey(
        'nautobot_firewall_changes.FirewallRule',
        on_delete=models.CASCADE
    )
    
    match_percentage = models.FloatField(help_text="0-100, how closely rule matches request")
    match_reason = models.TextField(help_text="Why this rule matches the request")
    
    class Meta:
        ordering = ['-match_percentage']


# ============================================================================
# POLICY LOOKUP ENGINE
# ============================================================================

class FirewallPolicyEngine:
    """Core engine for policy lookup and analysis"""
    
    def __init__(self):
        from nautobot_firewall_changes.models import (
            FirewallRule, NetworkPath, PathFirewallStep, FirewallDevice
        )
        self.FirewallRule = FirewallRule
        self.NetworkPath = NetworkPath
        self.PathFirewallStep = PathFirewallStep
        self.FirewallDevice = FirewallDevice
    
    def lookup_policy(self, source_ip: str, dest_ip: str, protocol: str, port: int = None) -> Dict:
        """
        Look up existing policies that match the request
        
        Returns:
            Dict with matching rules, verdict, blocking point
        """
        
        logger.info(f"Policy lookup: {source_ip} → {dest_ip}:{port} ({protocol})")
        
        src_net = netaddr.IPNetwork(source_ip)
        dst_net = netaddr.IPNetwork(dest_ip)
        
        service_identifier = self._build_service_identifier(protocol, port)
        
        # Find all rules that could match this traffic
        matching_rules = self._find_matching_rules(src_net, dst_net, service_identifier)
        
        if not matching_rules:
            return {
                'policy_exists': False,
                'message': 'No existing policy found for this traffic',
                'matching_rules': [],
                'verdict': 'UNKNOWN',
            }
        
        # Determine overall verdict (which firewall is decisive)
        verdict_result = self._determine_verdict(matching_rules)
        
        return {
            'policy_exists': True,
            'matching_rules': matching_rules,
            'verdict': verdict_result['verdict'],
            'blocking_firewall': verdict_result.get('blocking_firewall'),
            'blocking_rule': verdict_result.get('blocking_rule'),
            'message': self._build_policy_message(matching_rules, verdict_result),
            'details': {
                'rules_found': len(matching_rules),
                'blocking_point': verdict_result.get('blocking_firewall'),
            }
        }
    
    def analyze_new_policy_impact(
        self, 
        source_ip: str, 
        dest_ip: str, 
        protocol: str, 
        port: int = None,
        business_justification: str = None
    ) -> Dict:
        """
        Analyze impact of creating a new policy allowing this traffic
        
        Returns:
            Dict with path impact, risk assessment, recommendations
        """
        
        logger.info(f"Impact analysis: {source_ip} → {dest_ip}:{port}")
        
        src_net = netaddr.IPNetwork(source_ip)
        dst_net = netaddr.IPNetwork(dest_ip)
        
        # Find traffic paths this would affect
        affected_paths = self._find_affected_paths(src_net, dst_net)
        
        paths_analysis = {
            'opened': [],
            'already_blocked': [],
            'already_allowed': [],
        }
        
        # Analyze each path
        for path in affected_paths:
            from nautobot_firewall_changes.rule_traversal import RuleTraversalAnalyzer
            
            analyzer = RuleTraversalAnalyzer(path)
            current_analysis = analyzer.analyze()
            
            path_impact = {
                'path_name': path.name,
                'current_verdict': 'ALLOWED' if current_analysis.traffic_allowed else 'BLOCKED',
                'blocking_firewall': current_analysis.blocking_firewall.name if current_analysis.blocking_firewall else None,
                'blocking_rule': current_analysis.blocking_rule.rule_name if current_analysis.blocking_rule else None,
            }
            
            if not current_analysis.traffic_allowed:
                paths_analysis['opened'].append(path_impact)
            elif current_analysis.traffic_allowed:
                paths_analysis['already_allowed'].append(path_impact)
            else:
                paths_analysis['already_blocked'].append(path_impact)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            source_ip, dest_ip, protocol, port,
            len(paths_analysis['opened']),
            business_justification
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            source_ip, dest_ip, protocol, port,
            paths_analysis, risk_score
        )
        
        return {
            'paths_opened': paths_analysis['opened'],
            'paths_already_allowed': paths_analysis['already_allowed'],
            'paths_already_blocked': paths_analysis['already_blocked'],
            'risk_score': risk_score,
            'risk_level': self._risk_score_to_level(risk_score),
            'recommendations': recommendations,
            'business_justification': business_justification,
        }
    
    def _find_matching_rules(
        self, 
        src_net: netaddr.IPNetwork, 
        dst_net: netaddr.IPNetwork, 
        service: str
    ) -> List[Dict]:
        """Find all rules matching this traffic"""
        
        matching = []
        
        # Query all rules
        rules = self.FirewallRule.objects.select_related('device').order_by('device', 'sequence_number')
        
        for rule in rules:
            if self._rule_matches_traffic(rule, src_net, dst_net, service):
                matching.append({
                    'device_name': rule.device.name,
                    'rule_id': rule.rule_id,
                    'rule_name': rule.rule_name,
                    'action': rule.action,
                    'sequence_number': rule.sequence_number,
                    'logging_enabled': rule.logging_enabled,
                    'source_zones': rule.source_zones,
                    'dest_zones': rule.dest_zones,
                    'created_date': rule.created_at,
                    'change_ticket': rule.change_ticket if hasattr(rule, 'change_ticket') else None,
                })
        
        return matching
    
    def _rule_matches_traffic(
        self, 
        rule, 
        src_net: netaddr.IPNetwork, 
        dst_net: netaddr.IPNetwork, 
        service: str
    ) -> bool:
        """Determine if rule matches traffic pattern"""
        
        # Check if rule is disabled
        if rule.disabled:
            return False
        
        # Check source IPs
        if rule.source_ips:
            src_match = any(
                self._ip_in_range(src_net, src_range)
                for src_range in rule.source_ips
            )
            if not src_match:
                return False
        
        # Check destination IPs
        if rule.dest_ips:
            dst_match = any(
                self._ip_in_range(dst_net, dst_range)
                for dst_range in rule.dest_ips
            )
            if not dst_match:
                return False
        
        # Check services/ports
        if rule.services and service != 'all':
            service_match = any(
                self._service_matches(service, rule_service)
                for rule_service in rule.services
            )
            if not service_match:
                return False
        
        return True
    
    def _ip_in_range(self, traffic_net: netaddr.IPNetwork, rule_range: str) -> bool:
        """Check if traffic network is in rule range"""
        
        if rule_range == 'any':
            return True
        
        try:
            rule_net = netaddr.IPNetwork(rule_range)
            # Check if traffic net overlaps or is contained in rule net
            return traffic_net.ip in rule_net or traffic_net.cidr in rule_net.cidr
        except:
            return False
    
    def _service_matches(self, traffic_service: str, rule_service: str) -> bool:
        """Check if traffic service matches rule service"""
        
        if rule_service == 'any':
            return True
        
        # Parse formats: "tcp/22", "80", "https"
        traffic_proto, traffic_port = self._parse_service(traffic_service)
        rule_proto, rule_port = self._parse_service(rule_service)
        
        # Protocol must match
        if rule_proto not in ['all', traffic_proto]:
            return False
        
        # Port must match (if both specified)
        if traffic_port and rule_port and traffic_port != rule_port:
            return False
        
        return True
    
    def _parse_service(self, service: str) -> Tuple[str, Optional[int]]:
        """Parse service string into protocol and port"""
        
        if '/' in service:
            proto, port = service.split('/')
            return proto, int(port) if port.isdigit() else None
        
        # Map service names to ports
        common_services = {
            'http': ('tcp', 80),
            'https': ('tcp', 443),
            'ssh': ('tcp', 22),
            'rdp': ('tcp', 3389),
            'dns': ('udp', 53),
            'ntp': ('udp', 123),
        }
        
        if service.lower() in common_services:
            return common_services[service.lower()]
        
        # Assume it's a protocol
        return service, None
    
    def _build_service_identifier(self, protocol: str, port: int = None) -> str:
        """Build service identifier from protocol and port"""
        
        if protocol == 'all':
            return 'all'
        
        if port:
            return f"{protocol}/{port}"
        
        return protocol
    
    def _find_affected_paths(
        self, 
        src_net: netaddr.IPNetwork, 
        dst_net: netaddr.IPNetwork
    ) -> List:
        """Find all NetworkPaths that this traffic would traverse"""
        
        paths = self.NetworkPath.objects.all()
        affected = []
        
        for path in paths:
            path_src = netaddr.IPNetwork(path.source_network)
            path_dst = netaddr.IPNetwork(path.dest_network)
            
            # Check if traffic overlaps with path
            if (self._ranges_overlap(src_net, path_src) and 
                self._ranges_overlap(dst_net, path_dst)):
                affected.append(path)
        
        if not affected:
            # Return generic paths if no specific paths found
            affected = list(paths[:5])
        
        return affected
    
    def _ranges_overlap(self, net1: netaddr.IPNetwork, net2: netaddr.IPNetwork) -> bool:
        """Check if two networks overlap"""
        
        try:
            return net1.overlaps(net2)
        except:
            return False
    
    def _determine_verdict(self, matching_rules: List[Dict]) -> Dict:
        """Determine overall verdict from matching rules"""
        
        # Group by device to determine verdict per device
        by_device = {}
        for rule in matching_rules:
            device = rule['device_name']
            if device not in by_device:
                by_device[device] = []
            by_device[device].append(rule)
        
        # For each device, find first matching rule (in order)
        verdicts = {}
        blocking_device = None
        blocking_rule = None
        
        for device, rules in by_device.items():
            # Rules should already be ordered
            sorted_rules = sorted(rules, key=lambda r: r['sequence_number'])
            
            if sorted_rules:
                first_rule = sorted_rules[0]
                action = first_rule['action']
                
                verdicts[device] = action
                
                if action in ['deny', 'drop', 'reject']:
                    blocking_device = device
                    blocking_rule = first_rule['rule_name']
        
        # Determine overall verdict
        # If ANY device blocks, traffic is blocked (pessimistic)
        overall_verdict = 'BLOCKED' if blocking_device else 'ALLOWED'
        
        return {
            'verdict': overall_verdict,
            'blocking_firewall': blocking_device,
            'blocking_rule': blocking_rule,
            'verdicts_by_device': verdicts,
        }
    
    def _build_policy_message(self, matching_rules: List[Dict], verdict_result: Dict) -> str:
        """Build human-readable policy message"""
        
        if verdict_result['verdict'] == 'BLOCKED':
            return (
                f"Traffic is BLOCKED by rule '{verdict_result['blocking_rule']}' "
                f"on {verdict_result['blocking_firewall']}. "
                f"Found {len(matching_rules)} matching rule(s)."
            )
        else:
            return (
                f"Traffic is ALLOWED. "
                f"Found {len(matching_rules)} matching rule(s)."
            )
    
    def _calculate_risk_score(
        self, 
        source_ip: str, 
        dest_ip: str, 
        protocol: str, 
        port: int,
        paths_opened: int,
        business_justification: str
    ) -> int:
        """Calculate risk score for new policy (0-100)"""
        
        score = 0
        
        # Risk factors
        
        # 1. Source is broad (0-30 points)
        src_net = netaddr.IPNetwork(source_ip)
        if src_net.size > 1:  # Not a single IP
            score += min(30, int(20 * (src_net.prefixlen / 32)))
        
        # 2. Destination is broad (0-20 points)
        dst_net = netaddr.IPNetwork(dest_ip)
        if dst_net.size > 1:
            score += min(20, int(15 * (dst_net.prefixlen / 32)))
        
        # 3. Port is risky (0-20 points)
        risky_ports = {80, 443, 22, 3389, 3306, 5432}  # Common targets
        if port and port in risky_ports:
            score += 15
        
        # 4. Protocol risk (0-15 points)
        if protocol == 'all':
            score += 15
        elif protocol == 'tcp':
            score += 5
        
        # 5. Paths opened (0-20 points)
        score += min(20, paths_opened * 5)
        
        # 6. Business justification quality (0 to -20 points)
        if business_justification:
            justif_length = len(business_justification)
            if justif_length > 100:
                score -= 20
            elif justif_length > 50:
                score -= 10
            else:
                score -= 5
        
        return max(0, min(100, score))
    
    def _risk_score_to_level(self, score: int) -> str:
        """Convert risk score to level"""
        
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(
        self, 
        source_ip: str, 
        dest_ip: str, 
        protocol: str, 
        port: int,
        paths_analysis: Dict,
        risk_score: int
    ) -> List[str]:
        """Generate recommendations for new policy"""
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_score >= 75:
            recommendations.append(
                "⚠️ CRITICAL: This rule opens risky access - requires security review and approval"
            )
        elif risk_score >= 50:
            recommendations.append(
                "⚠️ HIGH RISK: Multiple policy paths affected - requires change management approval"
            )
        
        # Scope recommendations
        src_net = netaddr.IPNetwork(source_ip)
        if src_net.size > 256:
            recommendations.append(
                f"Source range is very broad ({src_net.size} IPs) - consider narrowing to specific subnets"
            )
        
        dst_net = netaddr.IPNetwork(dest_ip)
        if dst_net.size > 256:
            recommendations.append(
                f"Destination range is very broad ({dst_net.size} IPs) - consider narrowing to specific hosts"
            )
        
        # Port recommendations
        if port is None:
            recommendations.append(
                "No port specified - consider limiting to specific required ports only"
            )
        
        if protocol == 'all':
            recommendations.append(
                "Protocol set to 'all' - restrict to TCP/UDP only if possible"
            )
        
        # Logging recommendations
        recommendations.append(
            "Enable logging on this rule to track usage and detect misuse"
        )
        
        # Paths opened
        if paths_analysis['opened']:
            recommendations.append(
                f"This rule opens {len(paths_analysis['opened'])} previously blocked path(s): "
                f"{', '.join([p['path_name'] for p in paths_analysis['opened']])}"
            )
        
        # Business justification
        if not source_ip or not dest_ip:
            recommendations.append(
                "Ensure business justification is detailed and approved by manager"
            )
        
        return recommendations


# ============================================================================
# API VIEWSET
# ============================================================================

class PolicyLookupViewSet(viewsets.ViewSet):
    """
    API for firewall policy lookup and analysis
    
    Endpoints:
    - POST /api/policy/lookup/ - Look up existing policies
    - POST /api/policy/analyze/ - Analyze impact of new policy
    - GET /api/policy/requests/ - View lookup history
    - GET /api/policy/requests/{id}/ - View specific request details
    """
    
    permission_classes = [IsAuthenticated]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy_engine = FirewallPolicyEngine()
    
    @action(detail=False, methods=['post'], url_path='lookup')
    def lookup_policy(self, request):
        """
        POST /api/policy/lookup/
        
        Look up existing firewall policies matching the request.
        
        Request body:
        {
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.1.50",
            "protocol": "tcp",
            "port": 443,
            "business_justification": "User needs access to internal app",
            "requester_email": "user@company.com",
            "ticket_id": "CHG001234"
        }
        
        Response (if policy exists):
        {
            "policy_exists": true,
            "verdict": "ALLOWED",
            "matching_rules": [
                {
                    "device_name": "fw-border-1",
                    "rule_id": "100",
                    "rule_name": "Allow-Internal-HTTPS",
                    "action": "allow",
                    "sequence_number": 100,
                    "logging_enabled": true,
                    "source_zones": ["trust"],
                    "dest_zones": ["dmz"],
                    "created_date": "2024-01-15T10:30:00Z",
                    "change_ticket": "CHG000999"
                }
            ],
            "message": "Traffic is ALLOWED. Found 1 matching rule(s).",
            "details": {
                "rules_found": 1,
                "blocking_point": null
            }
        }
        
        Response (if policy doesn't exist):
        {
            "policy_exists": false,
            "matching_rules": [],
            "verdict": "UNKNOWN",
            "message": "No existing policy found for this traffic"
        }
        """
        
        serializer = PolicyLookupRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        # Create tracking record
        request_id = self._generate_request_id()
        lookup_record = PolicyLookupRequest.objects.create(
            request_id=request_id,
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            business_justification=data['business_justification'],
            requester_email=data['requester_email'],
            ticket_id=data.get('ticket_id'),
            status='exists' if self._policy_exists(data) else 'new',
        )
        
        # Perform lookup
        result = self.policy_engine.lookup_policy(
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port')
        )
        
        # Store results
        lookup_record.policy_exists = result['policy_exists']
        lookup_record.existing_rules = {
            'matching_rules': result['matching_rules'],
            'verdict': result['verdict'],
        }
        lookup_record.save()
        
        # Store matching policy references
        if result['matching_rules']:
            for rule_data in result['matching_rules']:
                try:
                    from nautobot_firewall_changes.models import FirewallDevice, FirewallRule
                    
                    device = FirewallDevice.objects.get(name=rule_data['device_name'])
                    rule = FirewallRule.objects.get(
                        device=device,
                        rule_id=rule_data['rule_id']
                    )
                    
                    ExistingPolicyMatch.objects.create(
                        lookup_request=lookup_record,
                        firewall_rule=rule,
                        match_percentage=95.0,
                        match_reason=f"Exact match on {data['protocol']}:{data.get('port', 'any')}"
                    )
                except:
                    pass
        
        logger.info(f"Policy lookup {request_id}: "
                   f"{'EXISTS' if result['policy_exists'] else 'NOT FOUND'}")
        
        response_data = {
            'request_id': request_id,
            **result
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'], url_path='analyze')
    def analyze_policy_impact(self, request):
        """
        POST /api/policy/analyze/
        
        Analyze the impact of creating a new firewall policy allowing this traffic.
        
        Request body:
        {
            "source_ip": "192.168.1.0/24",
            "dest_ip": "172.16.0.0/16",
            "protocol": "tcp",
            "port": 3306,
            "business_justification": "New database server migration - production database access required",
            "requester_email": "dba@company.com",
            "ticket_id": "CHG001250"
        }
        
        Response:
        {
            "request_id": "PLR-20240315-001",
            "status": "REVIEW_REQUIRED",
            "message": "New policy would affect 3 traffic paths. Risk assessment required.",
            "paths_analyzed": 3,
            "paths_opened": [
                {
                    "path_name": "Office_to_Database",
                    "new_verdict": "ALLOWED",
                    "warnings": []
                }
            ],
            "paths_already_blocked": [],
            "risk_score": 65,
            "risk_level": "HIGH",
            "recommendations": [
                "⚠️ HIGH RISK: Multiple policy paths affected - requires change management approval",
                "Destination range is very broad (65536 IPs) - consider narrowing to specific hosts",
                "This rule opens 1 previously blocked path(s): Office_to_Database",
                "Enable logging on this rule to track usage and detect misuse"
            ],
            "business_justification": "New database server migration...",
            "requester_email": "dba@company.com",
            "ticket_id": "CHG001250"
        }
        """
        
        serializer = PolicyLookupRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        # First check if policy exists
        lookup_result = self.policy_engine.lookup_policy(
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port')
        )
        
        if lookup_result['policy_exists']:
            # Policy exists - return that instead
            request_id = self._generate_request_id()
            PolicyLookupRequest.objects.create(
                request_id=request_id,
                source_ip=data['source_ip'],
                dest_ip=data['dest_ip'],
                protocol=data['protocol'],
                port=data.get('port'),
                business_justification=data['business_justification'],
                requester_email=data['requester_email'],
                ticket_id=data.get('ticket_id'),
                status='exists',
                policy_exists=True,
                existing_rules=lookup_result,
            )
            
            return Response({
                'request_id': request_id,
                'policy_exists': True,
                'message': 'Policy already exists - no new rule required',
                'existing_policy': lookup_result,
                'status': 'EXISTS',
            }, status=status.HTTP_200_OK)
        
        # Policy doesn't exist - analyze impact of creating it
        impact = self.policy_engine.analyze_new_policy_impact(
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            business_justification=data['business_justification']
        )
        
        # Determine overall status
        if impact['risk_level'] == 'CRITICAL':
            overall_status = 'DENIED'
        elif impact['risk_level'] == 'HIGH':
            overall_status = 'REVIEW_REQUIRED'
        else:
            overall_status = 'PERMITTED'
        
        # Create tracking record
        request_id = self._generate_request_id()
        lookup_record = PolicyLookupRequest.objects.create(
            request_id=request_id,
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port'),
            business_justification=data['business_justification'],
            requester_email=data['requester_email'],
            ticket_id=data.get('ticket_id'),
            status='new',
            policy_exists=False,
            is_new_request=True,
            impact_analysis=impact,
            risk_score=impact['risk_score'],
        )
        
        logger.info(f"Policy impact analysis {request_id}: "
                   f"Risk={impact['risk_level']}, Status={overall_status}")
        
        response_data = {
            'request_id': request_id,
            'status': overall_status,
            'message': self._build_impact_message(impact, overall_status),
            'paths_analyzed': len(impact['paths_opened']) + len(impact['paths_already_allowed']),
            'paths_opened': impact['paths_opened'],
            'paths_already_allowed': impact['paths_already_allowed'],
            'paths_already_blocked': impact['paths_already_blocked'],
            'risk_score': impact['risk_score'],
            'risk_level': impact['risk_level'],
            'recommendations': impact['recommendations'],
            'business_justification': data['business_justification'],
            'requester_email': data['requester_email'],
            'ticket_id': data.get('ticket_id'),
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'], url_path='requests')
    def list_requests(self, request):
        """
        GET /api/policy/requests/?status=new&days=7
        
        List policy lookup requests with optional filtering
        
        Query parameters:
        - status: exists, new, approved, rejected, deployed
        - days: Number of days to look back (default 30)
        - limit: Number of results (default 50)
        """
        
        status_filter = request.query_params.get('status')
        days = int(request.query_params.get('days', 30))
        limit = int(request.query_params.get('limit', 50))
        
        since = timezone.now() - timedelta(days=days)
        
        queryset = PolicyLookupRequest.objects.filter(created_at__gte=since)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        queryset = queryset.order_by('-created_at')[:limit]
        
        results = [
            {
                'request_id': r.request_id,
                'source_ip': r.source_ip,
                'dest_ip': r.dest_ip,
                'protocol': r.protocol,
                'port': r.port,
                'status': r.status,
                'policy_exists': r.policy_exists,
                'requester_email': r.requester_email,
                'risk_score': r.risk_score,
                'created_at': r.created_at,
            }
            for r in queryset
        ]
        
        return Response({
            'count': len(results),
            'results': results,
        })
    
    @action(detail=False, methods=['get'], url_path='requests/(?P<request_id>[^/.]+)')
    def get_request_detail(self, request, request_id=None):
        """
        GET /api/policy/requests/{request_id}/
        
        Get detailed information about a specific policy request
        """
        
        try:
            lookup_request = PolicyLookupRequest.objects.get(request_id=request_id)
        except PolicyLookupRequest.DoesNotExist:
            return Response(
                {'error': f'Request {request_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get matching policies if they exist
        matching_policies = []
        if lookup_request.policy_exists:
            matches = ExistingPolicyMatch.objects.filter(
                lookup_request=lookup_request
            ).select_related('firewall_rule__device')
            
            matching_policies = [
                {
                    'device': m.firewall_rule.device.name,
                    'rule_id': m.firewall_rule.rule_id,
                    'rule_name': m.firewall_rule.rule_name,
                    'action': m.firewall_rule.action,
                    'match_percentage': m.match_percentage,
                }
                for m in matches
            ]
        
        response_data = {
            'request_id': lookup_request.request_id,
            'source_ip': lookup_request.source_ip,
            'dest_ip': lookup_request.dest_ip,
            'protocol': lookup_request.protocol,
            'port': lookup_request.port,
            'status': lookup_request.status,
            'policy_exists': lookup_request.policy_exists,
            'matching_policies': matching_policies,
            'business_justification': lookup_request.business_justification,
            'requester_email': lookup_request.requester_email,
            'ticket_id': lookup_request.ticket_id,
            'risk_score': lookup_request.risk_score,
            'impact_analysis': lookup_request.impact_analysis,
            'approved_by': lookup_request.approved_by,
            'approved_at': lookup_request.approved_at,
            'deployed_at': lookup_request.deployed_at,
            'created_at': lookup_request.created_at,
        }
        
        return Response(response_data)
    
    @action(detail=False, methods=['post'], url_path='requests/(?P<request_id>[^/.]+)/approve')
    def approve_request(self, request, request_id=None):
        """
        POST /api/policy/requests/{request_id}/approve/
        
        Approve a policy request (admin only)
        
        Request body:
        {
            "approver_email": "secops-lead@company.com",
            "notes": "Approved for Q1 database migration"
        }
        """
        
        try:
            lookup_request = PolicyLookupRequest.objects.get(request_id=request_id)
        except PolicyLookupRequest.DoesNotExist:
            return Response(
                {'error': f'Request {request_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        approver_email = request.data.get('approver_email')
        
        lookup_request.status = 'approved'
        lookup_request.approved_by = approver_email
        lookup_request.approved_at = timezone.now()
        lookup_request.save()
        
        logger.info(f"Policy request {request_id} approved by {approver_email}")
        
        return Response({
            'request_id': request_id,
            'status': 'approved',
            'approved_by': approver_email,
            'approved_at': lookup_request.approved_at,
        })
    
    @action(detail=False, methods=['post'], url_path='requests/(?P<request_id>[^/.]+)/reject')
    def reject_request(self, request, request_id=None):
        """
        POST /api/policy/requests/{request_id}/reject/
        
        Reject a policy request (admin only)
        """
        
        try:
            lookup_request = PolicyLookupRequest.objects.get(request_id=request_id)
        except PolicyLookupRequest.DoesNotExist:
            return Response(
                {'error': f'Request {request_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        reject_reason = request.data.get('reason', 'No reason provided')
        
        lookup_request.status = 'rejected'
        lookup_request.save()
        
        logger.warning(f"Policy request {request_id} rejected: {reject_reason}")
        
        return Response({
            'request_id': request_id,
            'status': 'rejected',
            'reason': reject_reason,
        })
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        
        from datetime import datetime
        import random
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = f"{random.randint(1000, 9999)}"
        
        return f"PLR-{timestamp}-{random_suffix}"
    
    def _policy_exists(self, data: Dict) -> bool:
        """Quick check if policy exists"""
        
        result = self.policy_engine.lookup_policy(
            source_ip=data['source_ip'],
            dest_ip=data['dest_ip'],
            protocol=data['protocol'],
            port=data.get('port')
        )
        
        return result['policy_exists']
    
    def _build_impact_message(self, impact: Dict, status: str) -> str:
        """Build human-readable impact message"""
        
        if status == 'DENIED':
            return (
                f"DENIED: This rule is too risky (risk score {impact['risk_score']}/100) "
                f"and would open {len(impact['paths_opened'])} traffic path(s). "
                "Requires security review and director-level approval."
            )
        elif status == 'REVIEW_REQUIRED':
            return (
                f"REVIEW REQUIRED: This rule has {impact['risk_level']} risk "
                f"(score {impact['risk_score']}/100) and would open {len(impact['paths_opened'])} "
                "traffic path(s). Requires change management approval."
            )
        else:  # PERMITTED
            return (
                f"PERMITTED: This rule is low risk (score {impact['risk_score']}/100) "
                f"and opens {len(impact['paths_opened'])} traffic path(s). "
                "May be approved with standard change process."
            )
