# Integrated Multi-Firewall Traffic Path Discovery + Policy Lookup API

## Overview

This document describes the complete **Integrated Policy Lookup and Traffic Path Discovery** system. It combines:

1. **Real-time Policy Lookup** – Does a policy exist for this traffic?
2. **Multi-Firewall Path Discovery** – What paths does this traffic traverse?
3. **Rule Traversal Analysis** – Will traffic be blocked at each firewall?
4. **Risk Assessment** – How risky is this policy change?
5. **Recommendations** – What should be done?

All in a single unified API call.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    User/Application                              │
│        (Terraform, ServiceNow, CI/CD, etc.)                     │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      │ POST /api/integrated/policy-path/analyze/
                      │ {
                      │   "source_ip": "192.168.1.0/24",
                      │   "dest_ip": "172.16.0.0/16",
                      │   "protocol": "tcp",
                      │   "port": 3306,
                      │   "business_justification": "..."
                      │ }
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│          Integrated Policy-Path Engine                           │
│                                                                   │
│  Step 1: Find Applicable Traffic Paths                          │
│  ──────────────────────────────────────────────────────────     │
│  Input: Source IP, Dest IP                                      │
│  Output: List of NetworkPaths (Office→DataCenter, Office→AWS)   │
│                                                                   │
│  Step 2: For Each Path, Evaluate ALL Firewalls in Order        │
│  ────────────────────────────────────────────────────────      │
│  FW1 (Border):  Eval rules 1-45  → BLOCKED by rule #5         │
│  FW2 (DC Edge): Not reached due to FW1 block                    │
│                                                                   │
│  Step 3: Determine Path Verdict                                 │
│  ──────────────────────────────────────────────────────────     │
│  Office→DataCenter: BLOCKED (at FW1 rule #5)                    │
│  Office→AWS:       ALLOWED                                      │
│  Office→Azure:     ALLOWED                                      │
│  Overall:         MIXED (some paths blocked)                    │
│                                                                   │
│  Step 4: Calculate Risk Score                                   │
│  ──────────────────────────────────────────────────────────     │
│  Source breadth: 20 pts (256 IPs)                               │
│  Dest breadth:   15 pts (65k IPs)                               │
│  Port risk:      15 pts (MySQL port 3306)                       │
│  Paths affected:  9 pts (3 paths × 3)                           │
│  Total:          59/100 = HIGH RISK                             │
│                                                                   │
│  Step 5: Generate Recommendations                               │
│  ──────────────────────────────────────────────────────────     │
│  - Remove rule #5 from FW1 (Block-RFC1918-Route-Out)           │
│  - 1 of 3 paths blocked - consider alternative routing          │
│  - Enable logging to track rule usage                           │
│  - Narrow destination to specific servers (not /16)             │
│                                                                   │
│  Step 6: Determine Policy Status                                │
│  ──────────────────────────────────────────────────────────     │
│  REVIEW_REQUIRED (blocked path + high risk)                     │
│                                                                   │
└──────────────────────┬─────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Database (Audit Trail)                        │
│                                                                   │
│  PolicyLookupRequest                                             │
│  ├─ request_id: IPP-20240315-001                                │
│  ├─ status: REVIEW_REQUIRED                                     │
│  ├─ risk_score: 59                                              │
│  └─ impact_analysis: {...}                                      │
│                                                                   │
│  TrafficPathPolicyRequest                                        │
│  ├─ paths_found: 3                                              │
│  ├─ overall_verdict: MIXED                                      │
│  ├─ blocking_points: [{"firewall": "fw-border-1", "rule": "..."}]
│  └─ path_analysis: {...}                                        │
│                                                                   │
│  PathTraversalStep (multiple rows)                              │
│  ├─ fw-border-1: BLOCKED by rule #5                            │
│  ├─ fw-aws-boundary: ALLOWED                                    │
│  └─ fw-azure-boundary: ALLOWED                                  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Differences from Separate APIs

### Old Approach (Separate Endpoints):
```
1. User calls: POST /api/policy/lookup/
   Response: "No policy exists"

2. User calls: POST /api/policy/analyze/
   Response: "Risk: 45"

3. Missing: Where is traffic blocked? On which firewall?
   Missing: How many paths are affected?
   Missing: What's the blocking rule?
```

### New Integrated Approach:
```
1. User calls: POST /api/integrated/policy-path/analyze/
   Response: 
   {
     "overall_verdict": "MIXED",
     "paths_analyzed": 3,
     "blocking_points": [
       {"firewall": "fw-border-1", "rule": "Block-RFC1918-Route-Out"}
     ],
     "path_details": [
       {
         "path_name": "Office_to_DataCenter",
         "verdict": "BLOCKED",
         "firewall_steps": [
           {
             "firewall": "fw-border-1",
             "rules_evaluated": 45,
             "verdict": "BLOCKED",
             "blocking_rule": "Block-RFC1918-Route-Out"
           }
         ]
       },
       {
         "path_name": "Office_to_AWS",
         "verdict": "ALLOWED",
         "firewall_steps": [...]
       }
     ]
   }

✓ Shows which paths exist
✓ Shows which firewall blocks
✓ Shows which rule blocks
✓ Shows rules evaluated at each FW
✓ Shows overall risk
✓ Complete end-to-end visibility
```

---

## API Endpoint

### POST /api/integrated/policy-path/analyze/

**Purpose**: Complete end-to-end traffic analysis with path discovery and rule evaluation

**Request**:
```bash
curl -X POST http://nautobot.example.com/api/integrated/policy-path/analyze/ \
  -H "Authorization: Token <api-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.100.0/24",
    "dest_ip": "172.16.0.0/16",
    "protocol": "tcp",
    "port": 3306,
    "business_justification": "Database replication for disaster recovery site",
    "requester_email": "dba-team@company.com",
    "ticket_id": "CHG001250"
  }'
```

**Response (Blocked Traffic)**:
```json
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
      "traversal_time_ms": 2.5,
      
      "blocking_points": [
        {
          "firewall": "fw-border-1",
          "rule": "Block-RFC1918-Route-Out",
          "sequence": 5,
          "reason": "Explicit deny rule"
        }
      ],
      
      "firewall_steps": [
        {
          "firewall": "fw-border-1",
          "rules_evaluated": 45,
          "rules_matched": 1,
          "verdict": "BLOCKED",
          "blocking_rule": "Block-RFC1918-Route-Out",
          "blocking_rule_seq": 5,
          "matched_rules": [
            {
              "rule_id": "5",
              "rule_name": "Block-RFC1918-Route-Out",
              "action": "deny",
              "logging": true,
              "sequence": 5
            }
          ],
          "eval_time_ms": 1.2
        },
        {
          "firewall": "fw-dc-boundary",
          "rules_evaluated": 38,
          "rules_matched": 0,
          "verdict": "UNKNOWN",
          "blocking_rule": null,
          "matched_rules": [],
          "eval_time_ms": 1.3
        }
      ]
    },
    {
      "path_name": "Office_to_AWS",
      "verdict": "ALLOWED",
      "firewall_count": 1,
      "firewall_steps": [
        {
          "firewall": "fw-border-1",
          "rules_evaluated": 45,
          "rules_matched": 1,
          "verdict": "ALLOWED",
          "blocking_rule": null,
          "matched_rules": [
            {
              "rule_id": "250",
              "rule_name": "Allow-Office-to-Cloud",
              "action": "allow",
              "logging": true,
              "sequence": 250
            }
          ]
        }
      ]
    },
    {
      "path_name": "Office_to_Azure",
      "verdict": "ALLOWED",
      "firewall_count": 1,
      "firewall_steps": [...]
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
  
  "business_justification": "Database replication for disaster recovery site",
  "requester_email": "dba-team@company.com",
  "ticket_id": "CHG001250"
}
```

**Response (Allowed Traffic)**:
```json
{
  "request_id": "IPP-20240315-002",
  "status": "PERMITTED",
  "overall_verdict": "ALLOWED",
  "paths_analyzed": 2,
  
  "path_details": [
    {
      "path_name": "Office_to_DataCenter",
      "verdict": "ALLOWED",
      "firewall_count": 2,
      "firewall_steps": [
        {
          "firewall": "fw-border-1",
          "rules_evaluated": 45,
          "verdict": "ALLOWED",
          "matching_rules": [
            {
              "rule_id": "100",
              "rule_name": "Allow-Internal-Replication",
              "action": "allow",
              "sequence": 100
            }
          ]
        },
        {
          "firewall": "fw-dc-boundary",
          "rules_evaluated": 30,
          "verdict": "ALLOWED"
        }
      ]
    },
    {
      "path_name": "Office_to_Partner",
      "verdict": "ALLOWED",
      "firewall_count": 2
    }
  ],
  
  "blocking_points": [],
  "risk_score": 35,
  "risk_level": "MEDIUM",
  "status": "PERMITTED",
  
  "recommendations": [
    "Destination range is very broad (65536 IPs) - consider narrowing to specific servers",
    "Enable logging on all new rules to track usage and detect misuse"
  ]
}
```

**Response (Mixed Verdict)**:
```json
{
  "request_id": "IPP-20240315-003",
  "status": "REVIEW_REQUIRED",
  "overall_verdict": "MIXED",
  "paths_analyzed": 5,
  
  "path_details": [
    {"path_name": "Office_to_DataCenter", "verdict": "BLOCKED"},
    {"path_name": "Office_to_AWS", "verdict": "ALLOWED"},
    {"path_name": "Office_to_Azure", "verdict": "ALLOWED"},
    {"path_name": "Office_to_GCP", "verdict": "ALLOWED"},
    {"path_name": "Office_to_Backup", "verdict": "BLOCKED"}
  ],
  
  "blocking_points": [
    {"firewall": "fw-border-1", "rule": "Block-RFC1918-Route-Out"},
    {"firewall": "fw-backup-gw", "rule": "Deny-Corporate-Backups"}
  ],
  
  "risk_score": 55,
  "status": "REVIEW_REQUIRED",
  
  "recommendations": [
    "Traffic is blocked at: fw-border-1, fw-backup-gw. Must remove or modify blocking rules: Block-RFC1918-Route-Out, Deny-Corporate-Backups",
    "2 of 5 paths are blocked - consider alternative routing or rule modifications",
    "This rule affects 5 traffic paths - ensure impact is understood and accepted"
  ]
}
```

---

## Database Schema Integration

### Stored Records

**PolicyLookupRequest** (Parent)
```
request_id: IPP-20240315-001
source_ip: 192.168.100.0/24
dest_ip: 172.16.0.0/16
protocol: tcp
port: 3306
status: REVIEW_REQUIRED
risk_score: 62
```

**TrafficPathPolicyRequest** (Detailed Analysis)
```
policy_lookup_request_id: (link to above)
paths_found: 3
firewalls_involved: 2
overall_verdict: BLOCKED
blocking_points: [{"firewall": "fw-border-1", "rule": "Block-RFC1918-Route-Out"}]
path_analysis: { full analysis JSON }
```

**PathTraversalStep** (Individual Steps - Multiple Rows)
```
traffic_request_id: (link to TrafficPathPolicyRequest)
network_path_id: 5 (Office_to_DataCenter path)
firewall_id: 1 (fw-border-1)
step_order: 0
verdict: BLOCKED
blocking_rule_id: 15
rules_evaluated: 45
```

---

## Query Examples

### Find all traffic currently blocked at a specific firewall
```sql
SELECT DISTINCT traffic_requests.source_ip, traffic_requests.dest_ip
FROM nautobot_firewall_changes_trafficpathpolicyrequest AS traffic_requests
WHERE traffic_requests.overall_verdict = 'BLOCKED'
AND traffic_requests.firewall_id = (SELECT id FROM nautobot_firewall_changes_firewalldevice WHERE name = 'fw-border-1');
```

### Find which policies would be blocked by a specific rule
```sql
SELECT DISTINCT pp.source_ip, pp.dest_ip, pp.protocol, pp.port
FROM nautobot_firewall_changes_trafficpathpolicyrequest AS pp
WHERE pp.blocking_points LIKE '%Block-RFC1918-Route-Out%';
```

### Get risk distribution
```sql
SELECT 
  CASE 
    WHEN impact_summary->>'risk_score' >= 75 THEN 'CRITICAL'
    WHEN impact_summary->>'risk_score' >= 50 THEN 'HIGH'
    WHEN impact_summary->>'risk_score' >= 25 THEN 'MEDIUM'
    ELSE 'LOW'
  END AS risk_level,
  COUNT(*) AS count
FROM nautobot_firewall_changes_trafficpathpolicyrequest
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY risk_level;
```

---

## Real-World Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│ Step 1: DBA Requests Database Access                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ DBA: "We need MySQL replication from 192.168.100.50:3307         │
│       to 172.16.1.50:3306"                                       │
│                                                                    │
│ ServiceNow Change Request: CHG001250                              │
│ Business Justification: "Disaster recovery replication"           │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 2: ServiceNow Calls Integrated API                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ POST /api/integrated/policy-path/analyze/                        │
│ {                                                                 │
│   "source_ip": "192.168.100.50",                                 │
│   "dest_ip": "172.16.1.50",                                      │
│   "protocol": "tcp",                                             │
│   "port": 3306,                                                  │
│   "business_justification": "Disaster recovery replication",      │
│   "requester_email": "dba@company.com",                          │
│   "ticket_id": "CHG001250"                                       │
│ }                                                                 │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 3: Integrated Engine Analyzes                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ Path Discovery: Found 3 paths                                    │
│ - Office_to_DataCenter (primary route)                           │
│ - Office_to_AWS (backup cloud)                                   │
│ - Office_to_Azure (alternate cloud)                              │
│                                                                    │
│ Rule Evaluation:                                                  │
│ Office_to_DataCenter:                                            │
│   fw-border-1: Rules 1-45 → BLOCKED at rule #5                  │
│   fw-dc-boundary: (not reached)                                  │
│                                                                    │
│ Office_to_AWS:                                                    │
│   fw-border-1: Rules 1-45 → ALLOWED at rule #250                │
│                                                                    │
│ Office_to_Azure:                                                  │
│   fw-border-1: Rules 1-45 → ALLOWED at rule #250                │
│                                                                    │
│ Risk Assessment:                                                  │
│ - Single IP (low src risk): 0 pts                                │
│ - Specific server (low dst risk): 0 pts                          │
│ - MySQL port 3306 (risky): 15 pts                                │
│ - 3 paths affected: 9 pts                                        │
│ - Blocking point must be resolved: 40 pts                        │
│ Total: 64/100 = HIGH RISK                                        │
│                                                                    │
│ Status: REVIEW_REQUIRED                                          │
│ Blocking Rule: "Block-RFC1918-Route-Out" on fw-border-1         │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 4: Response to ServiceNow                                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ {                                                                 │
│   "status": "REVIEW_REQUIRED",                                   │
│   "overall_verdict": "BLOCKED",                                  │
│   "blocking_points": [                                           │
│     {"firewall": "fw-border-1",                                  │
│      "rule": "Block-RFC1918-Route-Out"}                          │
│   ],                                                              │
│   "recommendations": [                                           │
│     "Remove rule #5 from fw-border-1 or create exception",       │
│     "Ensure primary path (DataCenter) is unblocked",             │
│     "Monitor rule usage with logging enabled"                    │
│   ]                                                               │
│ }                                                                 │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 5: Security Review                                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ Security team:                                                    │
│ ✓ Specific traffic (single IPs, single port)                    │
│ ✓ Good business justification                                   │
│ ✓ Approved by DBA manager                                       │
│ ✓ Change ticket linked                                          │
│ ✓ Blocking rule understood                                      │
│                                                                    │
│ Decision: APPROVE                                                │
│ Condition: Add exception to rule #5 or move replication         │
│           through AWS path instead                               │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 6: Rule Modification & Deployment                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ Option A: Add exception to rule #5                               │
│   Block-RFC1918-Route-Out EXCEPT 192.168.100.50 → 172.16.1.50   │
│                                                                    │
│ Option B: Add new allow rule before blocking rule                │
│   Allow replication 192.168.100.50:3307 → 172.16.1.50:3306      │
│                                                                    │
│ Option C: Route through AWS instead                              │
│   Use Office_to_AWS path (already ALLOWED)                       │
│   Backup server receives traffic from AWS                        │
│                                                                    │
│ Chosen: Option B (cleaner, explicit)                             │
│ Deployed to fw-border-1                                          │
│                                                                    │
│ Status updated: IPP-20240315-001 → "deployed"                    │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 7: Verification                                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│ Re-run analysis with new rule:                                   │
│ POST /api/integrated/policy-path/analyze/ (same params)          │
│                                                                    │
│ Response: "overall_verdict": "ALLOWED"                           │
│ All 3 paths now showing ALLOWED                                  │
│ New rule #6 "Allow-Replication" appears in traversal             │
│                                                                    │
│ DBA confirms replication working                                 │
│ CHG001250 closes with "COMPLETED"                                │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Visualization Endpoints

### Get ASCII Diagram
```bash
POST /api/integrated/policy-path/requests/IPP-20240315-001/visualize/

Response:

Traffic Path Analysis: 192.168.100.0/24 → 172.16.0.0/16
Overall Verdict: BLOCKED (Risk: 62/100)
================================================================================

Path: Office_to_DataCenter
  Verdict: BLOCKED
  Firewalls: 2

  ┌─ fw-border-1
  │  Rules evaluated: 45
  │  Rules matched: 1
  │  Verdict: BLOCKED
  │  Blocked by: Block-RFC1918-Route-Out (rule #5)
  └─

  ┌─ fw-dc-boundary
  │  (not reached due to upstream block)
  └─

---

Path: Office_to_AWS
  Verdict: ALLOWED
  Firewalls: 1

  ┌─ fw-border-1
  │  Rules evaluated: 45
  │  Rules matched: 1
  │  Verdict: ALLOWED
  │  Allowed by: Allow-Office-to-Cloud (rule #250)
  └─

================================================================================
```

---

## Integration with Change Management

### ServiceNow Business Rule
```javascript
// Runs when Change Request is created with network access
if (current.cmdb_ci && current.u_network_access_required) {
    var nautobot = new HttpClient();
    var response = nautobot.post(
        'http://nautobot/api/integrated/policy-path/analyze/',
        {
            source_ip: current.u_source_ip,
            dest_ip: current.u_dest_ip,
            protocol: current.u_protocol,
            port: current.u_port,
            business_justification: current.description,
            requester_email: gs.getUser().getEmail(),
            ticket_id: current.number
        }
    );
    
    var analysis = JSON.parse(response);
    
    // Add findings to change record
    current.u_network_analysis = analysis.request_id;
    current.u_firewall_blocking_points = analysis.blocking_points;
    current.u_firewall_risk = analysis.risk_level;
    
    if (analysis.status == 'BLOCKED') {
        // Notify security team
        gs.addErrorMessage('Traffic is blocked - requires security review');
        current.state = 'pending_security';
    } else if (analysis.status == 'REVIEW_REQUIRED') {
        current.state = 'pending_approval';
        // Auto-assign to security team
        current.assignment_group = 'Security Operations';
    } else {
        current.state = 'approved';
        // Can proceed automatically
    }
}
```

---

## Installation

```bash
# Copy integrated API code
cp integrated_policy_path_api.py /path/to/nautobot_firewall_changes/

# Create migrations
python manage.py makemigrations nautobot_firewall_changes

# Apply migrations
python manage.py migrate nautobot_firewall_changes

# Register URL routes
# (Add to nautobot_firewall_changes/urls.py)

# Restart services
systemctl restart nautobot nautobot-worker

# Test
curl -X POST http://nautobot/api/integrated/policy-path/analyze/ \
  -H "Authorization: Token <token>" \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "192.168.1.0/24", "dest_ip": "10.0.0.0/8", "protocol": "tcp", "port": 443, "business_justification": "Test", "requester_email": "test@example.com"}'
```

---

## Benefits Over Separate APIs

| Aspect | Separate APIs | Integrated |
|--------|---------------|-----------|
| **Blocking Point** | ❌ Unknown | ✅ Specific device + rule |
| **Path Coverage** | ❌ Single verdict | ✅ Verdict per path |
| **Firewall Count** | ❌ No visibility | ✅ Total FW evaluation |
| **Rules Evaluated** | ❌ Not visible | ✅ Per-firewall count |
| **Traversal Time** | ❌ N/A | ✅ ms per-firewall |
| **Alternatives** | ❌ Unknown | ✅ Show which paths work |
| **Risk Assessment** | ⚠️ Basic | ✅ Path-aware scoring |
| **Recommendations** | ⚠️ Generic | ✅ Specific to paths |
| **Visualization** | ❌ No | ✅ ASCII + SVG diagrams |
| **Database Queries** | Multiple | Single transaction |

---

## Performance Characteristics

**Typical Response Time**: 50-200ms

```
Network Path Discovery:     10ms (indexed queries)
Rule Evaluation (per FW):    10-30ms (depends on rule count)
Risk Calculation:            5ms
Response Serialization:      5-10ms
Total (3 paths, 2 FW each):  ~100ms
```

---

## Conclusion

The Integrated Policy-Path API provides **complete end-to-end visibility** into how traffic flows through your multi-firewall environment. Instead of running separate lookups, a single API call gives you:

✅ Which paths exist  
✅ Which paths are blocked  
✅ Which firewall blocks them  
✅ Which rule blocks at each step  
✅ Overall risk assessment  
✅ Specific recommendations  
✅ Full audit trail  

Perfect for automated provisioning, change management integration, and security decision-making.
