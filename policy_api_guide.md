# Policy Lookup API Implementation Guide

## Overview

This document describes how to integrate a real-time **Policy Lookup API** into the Nautobot multi-firewall change tracking system. The API allows external applications to:

1. **Query if a policy already exists** for specific traffic (source IP, dest IP, protocol, port)
2. **Get the current verdict** (ALLOWED/BLOCKED) and blocking point
3. **Analyze impact** of creating a new policy
4. **Assess risk** and receive recommendations
5. **Track all requests** with audit trail

### Use Cases

```
Use Case 1: Application Team Needs Network Access
─────────────────────────────────────────────────
App team: "We need access to database server 172.16.1.50 port 3306"

POST /api/policy/lookup/
{
    "source_ip": "192.168.10.0/24",
    "dest_ip": "172.16.1.50",
    "protocol": "tcp",
    "port": 3306,
    "business_justification": "New app server needs DB access",
    "requester_email": "app-lead@company.com"
}

Response:
{
    "request_id": "PLR-20240315-001",
    "policy_exists": false,
    "verdict": "UNKNOWN"
}
→ Policy doesn't exist, proceed to analyze impact

────────────────────────────────────────────────────

Use Case 2: Verify Existing Access
────────────────────────────────────
Network team: "Does HR workstation have access to payroll server?"

POST /api/policy/lookup/
{
    "source_ip": "192.168.50.100",
    "dest_ip": "10.0.2.20",
    "protocol": "tcp",
    "port": 443,
    "business_justification": "Verify access for HR team",
    "requester_email": "netadmin@company.com"
}

Response:
{
    "request_id": "PLR-20240315-002",
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
            "change_ticket": "CHG000999",
            "created_date": "2024-01-10T14:30:00Z"
        }
    ],
    "message": "Traffic is ALLOWED. Found 1 matching rule(s).",
    "details": {
        "rules_found": 1,
        "blocking_point": null
    }
}
→ Access confirmed! No new rules needed.

────────────────────────────────────────────────────

Use Case 3: Analyze Impact Before Creating Rule
────────────────────────────────────────────────
Database team: "We want to allow replication from backup server. What are risks?"

POST /api/policy/analyze/
{
    "source_ip": "192.168.100.50",
    "dest_ip": "172.16.1.0/24",
    "protocol": "tcp",
    "port": 3307,
    "business_justification": "Database replication traffic (MySQL backup)",
    "requester_email": "dba@company.com",
    "ticket_id": "CHG001250"
}

Response:
{
    "request_id": "PLR-20240315-003",
    "status": "REVIEW_REQUIRED",
    "risk_score": 45,
    "risk_level": "MEDIUM",
    "paths_analyzed": 2,
    "paths_opened": [
        {
            "path_name": "Office_to_Database",
            "new_verdict": "ALLOWED"
        }
    ],
    "recommendations": [
        "Destination range is very broad (256 IPs) - consider narrowing to specific hosts",
        "This rule opens 1 previously blocked path(s): Office_to_Database",
        "Enable logging on this rule to track usage and detect misuse",
        "Ensure business justification is detailed and approved by manager"
    ],
    "business_justification": "Database replication traffic (MySQL backup)"
}
→ Medium risk - can be approved with standard change process
→ Recommendation: Log all traffic and narrow destination range
```

---

## Part 1: Installation & Configuration

### 1.1 Add to Nautobot

```bash
# Copy policy_lookup_api.py to nautobot_firewall_changes/
cp policy_lookup_api.py /path/to/nautobot_firewall_changes/

# Create migrations
python manage.py makemigrations nautobot_firewall_changes

# Apply migrations
python manage.py migrate nautobot_firewall_changes

# Restart Nautobot
systemctl restart nautobot nautobot-worker
```

### 1.2 Register URL Routes

```python
# nautobot_firewall_changes/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .policy_lookup_api import PolicyLookupViewSet

router = DefaultRouter()
router.register(r'policy', PolicyLookupViewSet, basename='policy')

urlpatterns = [
    path('api/', include(router.urls)),
]
```

### 1.3 Database Setup

```bash
# Verify tables created
python manage.py dbshell

\dt nautobot_firewall_changes_policylookuprequest
\dt nautobot_firewall_changes_existingpolicymatch
```

---

## Part 2: API Endpoints

### 2.1 POST /api/policy/lookup/

**Purpose**: Look up if a policy already exists for this traffic

**Request Format**:
```json
{
    "source_ip": "192.168.1.0/24",
    "dest_ip": "10.0.1.0/24",
    "protocol": "tcp",
    "port": 443,
    "business_justification": "Required for application access",
    "requester_email": "user@company.com",
    "ticket_id": "CHG001234"
}
```

**Response (Policy Exists)**:
```json
{
    "request_id": "PLR-20240315-001",
    "policy_exists": true,
    "verdict": "ALLOWED",
    "blocking_firewall": null,
    "blocking_rule": null,
    "matching_rules": [
        {
            "device_name": "fw-border-1",
            "rule_id": "100",
            "rule_name": "Allow-Office-to-Internal",
            "action": "allow",
            "sequence_number": 100,
            "logging_enabled": true,
            "source_zones": ["trust"],
            "dest_zones": ["dmz"],
            "created_date": "2024-01-10T10:30:00Z",
            "change_ticket": "CHG000999"
        }
    ],
    "message": "Traffic is ALLOWED. Found 1 matching rule(s).",
    "details": {
        "rules_found": 1,
        "blocking_point": null
    }
}
```

**Response (Policy Doesn't Exist)**:
```json
{
    "request_id": "PLR-20240315-002",
    "policy_exists": false,
    "verdict": "UNKNOWN",
    "blocking_firewall": null,
    "blocking_rule": null,
    "matching_rules": [],
    "message": "No existing policy found for this traffic",
    "details": {
        "rules_found": 0,
        "blocking_point": null
    }
}
```

**Response (Policy Blocks Traffic)**:
```json
{
    "request_id": "PLR-20240315-003",
    "policy_exists": true,
    "verdict": "BLOCKED",
    "blocking_firewall": "fw-border-1",
    "blocking_rule": "Block-RFC1918-Egress",
    "matching_rules": [
        {
            "device_name": "fw-border-1",
            "rule_id": "10",
            "rule_name": "Block-RFC1918-Egress",
            "action": "deny",
            "sequence_number": 10,
            "logging_enabled": true,
            "source_zones": ["trust"],
            "dest_zones": ["untrust"],
            "created_date": "2024-01-01T00:00:00Z",
            "change_ticket": null
        }
    ],
    "message": "Traffic is BLOCKED by rule 'Block-RFC1918-Egress' on fw-border-1. Found 1 matching rule(s).",
    "details": {
        "rules_found": 1,
        "blocking_point": "fw-border-1"
    }
}
```

**cURL Example**:
```bash
curl -X POST http://nautobot.example.com/api/policy/lookup/ \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.1.50",
    "protocol": "tcp",
    "port": 443,
    "business_justification": "User needs access to internal app",
    "requester_email": "user@company.com"
  }'
```

**Python Example**:
```python
import requests

url = "http://nautobot.example.com/api/policy/lookup/"
headers = {
    "Authorization": "Token abc123xyz",
    "Content-Type": "application/json"
}
payload = {
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.1.50",
    "protocol": "tcp",
    "port": 443,
    "business_justification": "User needs access to internal app",
    "requester_email": "user@company.com"
}

response = requests.post(url, json=payload, headers=headers)
result = response.json()

if result['policy_exists']:
    print(f"✓ Policy EXISTS: {result['verdict']}")
    for rule in result['matching_rules']:
        print(f"  Device: {rule['device_name']}")
        print(f"  Rule: {rule['rule_name']} ({rule['rule_id']})")
        print(f"  Action: {rule['action']}")
else:
    print("✗ No policy found - would require new rule")
```

---

### 2.2 POST /api/policy/analyze/

**Purpose**: Analyze impact of creating a new policy

**Request Format**:
```json
{
    "source_ip": "192.168.100.0/24",
    "dest_ip": "172.16.0.0/16",
    "protocol": "tcp",
    "port": 3306,
    "business_justification": "New database server access for migration project",
    "requester_email": "dba-team@company.com",
    "ticket_id": "CHG001250"
}
```

**Response (Low Risk)**:
```json
{
    "request_id": "PLR-20240315-004",
    "status": "PERMITTED",
    "message": "PERMITTED: This rule is low risk (score 20/100) and opens 0 traffic path(s). May be approved with standard change process.",
    "paths_analyzed": 1,
    "paths_opened": [],
    "paths_already_allowed": [
        {
            "path_name": "Office_to_Database",
            "new_verdict": "ALLOWED"
        }
    ],
    "paths_already_blocked": [],
    "risk_score": 20,
    "risk_level": "LOW",
    "recommendations": [
        "Enable logging on this rule to track usage and detect misuse"
    ],
    "business_justification": "New database server access for migration project",
    "requester_email": "dba-team@company.com",
    "ticket_id": "CHG001250"
}
```

**Response (High Risk)**:
```json
{
    "request_id": "PLR-20240315-005",
    "status": "REVIEW_REQUIRED",
    "message": "REVIEW REQUIRED: This rule has HIGH risk (score 65/100) and would open 2 traffic path(s). Requires change management approval.",
    "paths_analyzed": 2,
    "paths_opened": [
        {
            "path_name": "Office_to_Internet",
            "new_verdict": "ALLOWED"
        },
        {
            "path_name": "Office_to_Partner_Network",
            "new_verdict": "ALLOWED"
        }
    ],
    "paths_already_allowed": [],
    "paths_already_blocked": [],
    "risk_score": 65,
    "risk_level": "HIGH",
    "recommendations": [
        "⚠️ HIGH RISK: Multiple policy paths affected - requires change management approval",
        "Source range is very broad (256 IPs) - consider narrowing to specific subnets",
        "Destination range is very broad (65536 IPs) - consider narrowing to specific hosts",
        "This rule opens 2 previously blocked path(s): Office_to_Internet, Office_to_Partner_Network",
        "Enable logging on this rule to track usage and detect misuse"
    ],
    "business_justification": "New database server access...",
    "requester_email": "dba-team@company.com",
    "ticket_id": "CHG001250"
}
```

**Response (Critical Risk)**:
```json
{
    "request_id": "PLR-20240315-006",
    "status": "DENIED",
    "message": "DENIED: This rule is too risky (risk score 88/100) and would open 5 traffic path(s). Requires security review and director-level approval.",
    "paths_analyzed": 5,
    "paths_opened": [
        ...5 paths...
    ],
    "risk_score": 88,
    "risk_level": "CRITICAL",
    "recommendations": [
        "⚠️ CRITICAL: This rule opens risky access - requires security review and approval",
        "Source range is very broad (1048576 IPs) - consider narrowing to specific subnets",
        "Protocol set to 'all' - restrict to TCP/UDP only if possible",
        "This rule opens 5 previously blocked path(s): ...",
        "Enable logging on this rule to track usage and detect misuse"
    ]
}
```

**Risk Score Calculation**:
```
Risk Factors:
- Source IP breadth:        0-30 points (larger = more risky)
- Destination IP breadth:   0-20 points
- Port selection:           0-20 points (risky ports: 22, 80, 443, 3389, 3306, 5432)
- Protocol type:            0-15 points ('all' = 15, TCP = 5, UDP = 3)
- Paths opened:             0-20 points (5 per path)
- Business justification:   -20 to 0 points (longer/detailed = lower risk)

Total: 0-100 scale

Risk Levels:
- CRITICAL:  75-100  (Automatic DENIED)
- HIGH:      50-74   (REVIEW_REQUIRED)
- MEDIUM:    25-49   (REVIEW_REQUIRED)
- LOW:       0-24    (PERMITTED)
```

---

### 2.3 GET /api/policy/requests/

**Purpose**: List all policy lookup requests with filtering

**Query Parameters**:
```
- status:  exists, new, approved, rejected, deployed (default: all)
- days:    Number of days to look back (default: 30)
- limit:   Number of results (default: 50, max: 500)
```

**Example**:
```bash
# Get all new requests from last 7 days
GET /api/policy/requests/?status=new&days=7&limit=50

# Get all requests that found existing policies
GET /api/policy/requests/?status=exists&limit=100

# Get recent high-risk requests
GET /api/policy/requests/?days=1&limit=100
(then filter on risk_score >= 50 client-side)
```

**Response**:
```json
{
    "count": 15,
    "results": [
        {
            "request_id": "PLR-20240315-001",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.1.50",
            "protocol": "tcp",
            "port": 443,
            "status": "exists",
            "policy_exists": true,
            "requester_email": "user@company.com",
            "risk_score": null,
            "created_at": "2024-03-15T14:30:00Z"
        },
        {
            "request_id": "PLR-20240315-002",
            "source_ip": "192.168.100.0/24",
            "dest_ip": "172.16.0.0/16",
            "protocol": "tcp",
            "port": 3306,
            "status": "new",
            "policy_exists": false,
            "requester_email": "dba@company.com",
            "risk_score": 65,
            "created_at": "2024-03-15T15:00:00Z"
        }
    ]
}
```

---

### 2.4 GET /api/policy/requests/{request_id}/

**Purpose**: Get detailed information about a specific request

**Example**:
```bash
GET /api/policy/requests/PLR-20240315-001/
```

**Response (Existing Policy)**:
```json
{
    "request_id": "PLR-20240315-001",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.1.50",
    "protocol": "tcp",
    "port": 443,
    "status": "exists",
    "policy_exists": true,
    "matching_policies": [
        {
            "device": "fw-border-1",
            "rule_id": "100",
            "rule_name": "Allow-Office-to-Internal",
            "action": "allow",
            "match_percentage": 95.0
        }
    ],
    "business_justification": "User needs access to internal app",
    "requester_email": "user@company.com",
    "ticket_id": null,
    "risk_score": null,
    "impact_analysis": null,
    "approved_by": null,
    "approved_at": null,
    "deployed_at": null,
    "created_at": "2024-03-15T14:30:00Z"
}
```

**Response (New Policy Request)**:
```json
{
    "request_id": "PLR-20240315-002",
    "source_ip": "192.168.100.0/24",
    "dest_ip": "172.16.0.0/16",
    "protocol": "tcp",
    "port": 3306,
    "status": "approved",
    "policy_exists": false,
    "matching_policies": [],
    "business_justification": "Database migration project",
    "requester_email": "dba@company.com",
    "ticket_id": "CHG001250",
    "risk_score": 65,
    "impact_analysis": {
        "paths_opened": [
            {
                "path_name": "Office_to_Database",
                "new_verdict": "ALLOWED"
            }
        ],
        "risk_level": "HIGH",
        "recommendations": [...]
    },
    "approved_by": "secops-lead@company.com",
    "approved_at": "2024-03-15T16:00:00Z",
    "deployed_at": "2024-03-16T08:30:00Z",
    "created_at": "2024-03-15T15:00:00Z"
}
```

---

### 2.5 POST /api/policy/requests/{request_id}/approve/

**Purpose**: Approve a policy request (requires admin/security role)

**Request**:
```json
{
    "approver_email": "secops-lead@company.com",
    "notes": "Approved for database migration"
}
```

**Response**:
```json
{
    "request_id": "PLR-20240315-002",
    "status": "approved",
    "approved_by": "secops-lead@company.com",
    "approved_at": "2024-03-15T16:00:00Z"
}
```

---

### 2.6 POST /api/policy/requests/{request_id}/reject/

**Purpose**: Reject a policy request

**Request**:
```json
{
    "reason": "Risk too high without additional scoping"
}
```

**Response**:
```json
{
    "request_id": "PLR-20240315-002",
    "status": "rejected",
    "reason": "Risk too high without additional scoping"
}
```

---

## Part 3: Integration Workflows

### 3.1 Workflow: Existing Policy Lookup

```
User Application (Terraform, ServiceNow, etc.)
        │
        ├─ Needs network access
        │
        ▼
Policy Lookup API
        │
        ├─ Query: Does policy exist?
        │
        ├─ Search firewall rules
        │ (all firewalls, all rules in order)
        │
        ├─ If matches found:
        │   ├─ Determine verdict (ALLOWED/BLOCKED)
        │   ├─ Identify blocking point (if blocked)
        │   └─ Return matching rules + verdict
        │
        └─ Response to requester
           (Policy exists: No new rule needed)
              OR
           (Policy doesn't exist: Proceed to impact analysis)
              OR
           (Policy blocks: Must request override or modification)
```

### 3.2 Workflow: New Policy Impact Analysis

```
User requests network access
        │
        ├─ First check: Does policy exist?
        │
        ├─ If no policy:
        │
        ▼
Analyze Impact of New Rule
        │
        ├─ Find affected traffic paths
        │ (routes through multiple firewalls)
        │
        ├─ For each path:
        │   ├─ Would new rule unblock path?
        │   ├─ Determine verdict
        │   └─ Identify warnings
        │
        ├─ Calculate risk score
        │ (source breadth, dest breadth, port risk, etc.)
        │
        ├─ Generate recommendations
        │ (narrow scope, enable logging, etc.)
        │
        └─ Response with status
           PERMITTED (low risk, auto-approve)
           REVIEW_REQUIRED (medium/high risk, needs approval)
           DENIED (critical risk, requires director approval)
```

### 3.3 Workflow: Approval & Deployment

```
Policy Request (REVIEW_REQUIRED or PERMITTED)
        │
        ├─ Security team reviews
        │ (risk score, recommendations, justification)
        │
        ├─ Decision:
        │
        ├─ APPROVED:
        │  ├─ Send to change management system
        │  ├─ Create change ticket
        │  ├─ Deploy rule to firewall(s)
        │  ├─ Mark request as "deployed"
        │  └─ Notify requester
        │
        └─ REJECTED:
           ├─ Notify requester with reason
           ├─ Suggest scoping changes
           └─ Allow resubmission with narrower scope
```

---

## Part 4: Security & Permissions

### 4.1 API Token Management

```python
# Create API token for service account
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

user = User.objects.create_user('policy-lookup-api', password='secure_password')
token = Token.objects.create(user=user)
print(f"API Token: {token.key}")

# Or use Django management command
python manage.py drf_create_token policy-lookup-api
```

### 4.2 Role-Based Permissions

```python
# nautobot_firewall_changes/permissions.py

from rest_framework import permissions

class IsNetworkAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='NetworkAdmin').exists()

class IsSecurityOps(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='SecurityOps').exists()

# Update ViewSet
class PolicyLookupViewSet(viewsets.ViewSet):
    
    def lookup_policy(self, request):
        # Any authenticated user can lookup
        permission_classes = [IsAuthenticated]
    
    def analyze_policy_impact(self, request):
        # Any authenticated user can analyze
        permission_classes = [IsAuthenticated]
    
    def approve_request(self, request):
        # Only SecurityOps can approve
        if not request.user.groups.filter(name='SecurityOps').exists():
            return Response({'error': 'Permission denied'}, status=403)
```

### 4.3 Audit Logging

All requests are automatically logged to `PolicyLookupRequest` table:
- Request ID (for tracing)
- Requester email
- Source/dest IP
- Protocol/port
- Business justification
- Status
- Approval details
- Deployment details
- Timestamps

---

## Part 5: Integration Examples

### 5.1 Terraform Integration

```hcl
# Terraform provider for policy lookup
terraform {
  required_providers {
    firewall-policy = {
      source = "internal/firewall-policy"
    }
  }
}

provider "firewall_policy" {
  api_endpoint = "http://nautobot.example.com"
  api_token    = var.nautobot_api_token
}

# Check if policy exists before creating resource
data "firewall_policy_lookup" "app_db_access" {
  source_ip             = aws_instance.app_server.private_ip
  dest_ip               = aws_rds_cluster.db.network_interface[0].private_ip
  protocol              = "tcp"
  port                  = 3306
  business_justification = "App requires database access"
  requester_email       = "terraform@company.com"
}

# If policy doesn't exist, analyze impact
data "firewall_policy_analyze" "app_db_impact" {
  count = data.firewall_policy_lookup.app_db_access.policy_exists ? 0 : 1
  
  source_ip             = aws_instance.app_server.private_ip
  dest_ip               = aws_rds_cluster.db.network_interface[0].private_ip
  protocol              = "tcp"
  port                  = 3306
  business_justification = "App requires database access"
  requester_email       = "terraform@company.com"
}

# Create application only if access already exists OR can be safely added
resource "aws_instance" "app_server" {
  count = (
    data.firewall_policy_lookup.app_db_access.policy_exists ||
    (data.firewall_policy_analyze.app_db_impact[0].status != "DENIED")
  ) ? 1 : 0
  
  # ... instance configuration ...
}
```

### 5.2 ServiceNow Integration

```javascript
// ServiceNow Business Rule (before insert on Change Request)
(function executeRule(current, previous) {
    
    var nautobot_url = gs.getProperty('nautobot.api.endpoint');
    var nautobot_token = gs.getSecureProperty('nautobot.api.token');
    
    // Check if network access is required
    if (current.cmdb_ci && 
        current.cmdb_ci.getRefRecord().getClassValue() == 'cmdb_ci_service') {
        
        var source_ip = current.u_source_ip;  // Custom field
        var dest_ip = current.u_dest_ip;
        var protocol = current.u_protocol;
        var port = current.u_port;
        
        // Lookup policy
        var req = new GlideHTTPClient();
        req.setBasicAuth('nautobot_user', nautobot_token);
        req.setRequestHeader('Content-Type', 'application/json');
        
        var payload = {
            source_ip: source_ip,
            dest_ip: dest_ip,
            protocol: protocol,
            port: port,
            business_justification: current.description,
            requester_email: current.requested_by.name,
            ticket_id: current.number
        };
        
        req.post(nautobot_url + '/api/policy/lookup/', 
                 JSON.stringify(payload));
        
        var response = JSON.parse(req.getResponseText());
        
        if (response.policy_exists) {
            // Policy exists - add comment
            current.addComment(
                'NETWORK: Policy already exists - ' + 
                response.matching_rules[0].rule_name
            );
            current.u_network_policy_status = 'EXISTS';
        } else {
            // Need to create new policy - analyze impact
            req.post(nautobot_url + '/api/policy/analyze/', 
                     JSON.stringify(payload));
            
            response = JSON.parse(req.getResponseText());
            
            current.u_firewall_risk_score = response.risk_score;
            current.u_firewall_risk_level = response.risk_level;
            current.u_network_policy_status = response.status;
            
            // Add recommendations as comments
            response.recommendations.forEach(function(rec) {
                current.addComment('NETWORK: ' + rec);
            });
            
            // Auto-approve if low risk
            if (response.status == 'PERMITTED') {
                current.u_network_approval = 'APPROVED';
            }
        }
    }
    
})(current, previous);
```

### 5.3 Python Client Library

```python
# policy_client.py

import requests
from typing import Dict, Optional

class NautobotPolicyClient:
    """Client for Nautobot firewall policy lookup API"""
    
    def __init__(self, api_endpoint: str, api_token: str):
        self.api_endpoint = api_endpoint
        self.api_token = api_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {api_token}',
            'Content-Type': 'application/json'
        })
    
    def lookup_policy(
        self, 
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: Optional[int] = None,
        business_justification: str = "",
        requester_email: str = ""
    ) -> Dict:
        """Look up if a policy exists for this traffic"""
        
        payload = {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port,
            'business_justification': business_justification,
            'requester_email': requester_email,
        }
        
        response = self.session.post(
            f'{self.api_endpoint}/api/policy/lookup/',
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def analyze_policy(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: Optional[int] = None,
        business_justification: str = "",
        requester_email: str = "",
        ticket_id: Optional[str] = None
    ) -> Dict:
        """Analyze impact of creating a new policy"""
        
        payload = {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port,
            'business_justification': business_justification,
            'requester_email': requester_email,
            'ticket_id': ticket_id,
        }
        
        response = self.session.post(
            f'{self.api_endpoint}/api/policy/analyze/',
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def get_request(self, request_id: str) -> Dict:
        """Get details of a specific policy request"""
        
        response = self.session.get(
            f'{self.api_endpoint}/api/policy/requests/{request_id}/'
        )
        response.raise_for_status()
        return response.json()
    
    def approve_request(self, request_id: str, approver_email: str) -> Dict:
        """Approve a policy request"""
        
        payload = {'approver_email': approver_email}
        response = self.session.post(
            f'{self.api_endpoint}/api/policy/requests/{request_id}/approve/',
            json=payload
        )
        response.raise_for_status()
        return response.json()

# Usage Example
if __name__ == '__main__':
    client = NautobotPolicyClient(
        api_endpoint='http://nautobot.example.com',
        api_token='your_api_token_here'
    )
    
    # Step 1: Check if policy exists
    lookup = client.lookup_policy(
        source_ip='192.168.1.100',
        dest_ip='10.0.1.50',
        protocol='tcp',
        port=443,
        business_justification='User needs access to internal app',
        requester_email='user@company.com'
    )
    
    if lookup['policy_exists']:
        print(f"✓ Policy EXISTS: {lookup['verdict']}")
        for rule in lookup['matching_rules']:
            print(f"  {rule['rule_name']} on {rule['device_name']}")
    else:
        # Step 2: Analyze impact if policy doesn't exist
        analysis = client.analyze_policy(
            source_ip='192.168.1.100',
            dest_ip='10.0.1.50',
            protocol='tcp',
            port=443,
            business_justification='User needs access to internal app',
            requester_email='user@company.com',
            ticket_id='CHG001234'
        )
        
        print(f"Analysis: {analysis['status']} (Risk: {analysis['risk_level']})")
        print(f"Score: {analysis['risk_score']}/100")
        print("\nRecommendations:")
        for rec in analysis['recommendations']:
            print(f"  - {rec}")
        
        if analysis['status'] != 'DENIED':
            # Proceed with approval process
            print("\nRequest approved - proceeding with deployment")
```

---

## Part 6: Monitoring & Alerts

### 6.1 Dashboard Metrics

```python
# Add to Django management commands

from django.core.management.base import BaseCommand
from datetime import timedelta
from django.utils import timezone
from .models import PolicyLookupRequest

class Command(BaseCommand):
    def handle(self, *args, **options):
        # Metrics for last 24 hours
        since = timezone.now() - timedelta(hours=24)
        
        requests = PolicyLookupRequest.objects.filter(created_at__gte=since)
        
        metrics = {
            'total_requests': requests.count(),
            'policies_found': requests.filter(policy_exists=True).count(),
            'new_policy_requests': requests.filter(is_new_request=True).count(),
            'pending_review': requests.filter(status='new').count(),
            'approved': requests.filter(status='approved').count(),
            'rejected': requests.filter(status='rejected').count(),
            'deployed': requests.filter(status='deployed').count(),
            'avg_risk_score': requests.filter(risk_score__isnull=False).aggregate(
                avg=Avg('risk_score')
            )['avg'],
            'high_risk_count': requests.filter(risk_score__gte=50).count(),
            'critical_risk_count': requests.filter(risk_score__gte=75).count(),
        }
        
        return metrics
```

### 6.2 Alert Rules

```yaml
# Prometheus alert rules

groups:
  - name: nautobot_policy_api
    rules:
      - alert: HighRiskPolicyRequests
        expr: |
          count(nautobot_policy_requests{risk_score > 50}) > 5
        for: 1h
        annotations:
          summary: "Multiple high-risk policy requests"
          description: "{{ $value }} high-risk policy requests in last hour"
      
      - alert: PolicyApprovalBacklog
        expr: |
          count(nautobot_policy_requests{status = "new"}) > 20
        for: 30m
        annotations:
          summary: "Policy approval backlog"
          description: "{{ $value }} requests awaiting approval"
      
      - alert: PolicyLookupAPIDown
        expr: |
          up{job="nautobot_policy_api"} == 0
        for: 5m
        annotations:
          summary: "Policy lookup API is down"
```

---

## Part 7: Testing

### 7.1 Unit Tests

```python
# tests/test_policy_api.py

from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token

class PolicyLookupAPITestCase(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', password='test123')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_lookup_existing_policy(self):
        """Test looking up existing policy"""
        response = self.client.post('/api/policy/lookup/', {
            'source_ip': '192.168.1.0/24',
            'dest_ip': '10.0.1.0/24',
            'protocol': 'tcp',
            'port': 443,
            'business_justification': 'Test',
            'requester_email': 'test@example.com',
        })
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('policy_exists', data)
        self.assertIn('request_id', data)
    
    def test_analyze_new_policy(self):
        """Test analyzing impact of new policy"""
        response = self.client.post('/api/policy/analyze/', {
            'source_ip': '192.168.100.0/24',
            'dest_ip': '172.16.0.0/16',
            'protocol': 'tcp',
            'port': 3306,
            'business_justification': 'Database access',
            'requester_email': 'dba@example.com',
        })
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('risk_score', data)
        self.assertIn('risk_level', data)
        self.assertIn('recommendations', data)
    
    def test_invalid_ip_format(self):
        """Test validation of IP format"""
        response = self.client.post('/api/policy/lookup/', {
            'source_ip': 'invalid-ip',
            'dest_ip': '10.0.1.0/24',
            'protocol': 'tcp',
            'port': 443,
            'business_justification': 'Test',
            'requester_email': 'test@example.com',
        })
        
        self.assertEqual(response.status_code, 400)
```

---

## Deployment Checklist

```
☐ Database migrations created and applied
☐ API endpoints registered in urls.py
☐ API tokens created for service accounts
☐ Role-based permissions configured
☐ Firewall rules indexed for fast lookup
☐ Monitoring dashboards created
☐ Alert rules configured
☐ Integration tests passing
☐ Documentation created for API consumers
☐ Sample requests/responses provided
☐ Client libraries (Python, Terraform) published
☐ Rate limiting configured (prevent abuse)
☐ Logging enabled for audit trail
☐ API documentation (Swagger/OpenAPI) generated
☐ Training completed for support team
```

This implementation provides a complete, production-ready Policy Lookup API that integrates seamlessly with the multi-firewall change tracking system.
