# Firewall Change Tracking with Nautobot + Custom Integrations

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Firewall Devices                             │
│  (Palo Alto, Cisco ASA/Nexus, FortiGate, Check Point, etc.)    │
└────────────┬────────────────────────────────────────────────────┘
             │
             │ API calls, syslog, SNMP traps
             ▼
┌─────────────────────────────────────────────────────────────────┐
│          Nautobot Change Tracking Plugins                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Firewall Config Collector (API/syslog ingestion)       │   │
│  │ • Change Parser (vendor-specific syntax normalization)   │   │
│  │ • Git Integration (version control & diffing)            │   │
│  │ • Change Analyzer (rule impact, conflicts, drift)        │   │
│  │ • Webhook Dispatcher (alerts, integrations)              │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────┬────────────────────────────────────────────────────┘
             │
             ├─────────────────┬──────────────────┬─────────────────┐
             ▼                 ▼                  ▼                 ▼
        ┌─────────┐      ┌────────────┐    ┌──────────┐     ┌──────────┐
        │   Git   │      │ PostgreSQL │    │ Webhooks │     │ Nautobot │
        │  Repos  │      │ Database   │    │ (Slack,  │     │   API    │
        │         │      │ (Changes)  │    │  Splunk) │     │          │
        └────┬────┘      └──────┬─────┘    └──────────┘     └──────────┘
             │                  │
             └──────────┬───────┘
                        ▼
             ┌─────────────────────────┐
             │  Dashboards & Reports   │
             │  • Change history view  │
             │  • Impact correlation   │
             │  • Compliance reports   │
             │  • Drift detection      │
             └─────────────────────────┘
```

---

## Part 1: Nautobot Setup & Configuration

### 1.1 Install Nautobot

```bash
# Option A: Docker (recommended for most)
docker run -d \
  --name nautobot \
  -e NAUTOBOT_DB_HOST=postgres \
  -e NAUTOBOT_DB_NAME=nautobot \
  -e NAUTOBOT_DB_USER=nautobot \
  -e NAUTOBOT_DB_PASSWORD=<secure_password> \
  -e NAUTOBOT_SECRET_KEY=<secret_key> \
  -p 8000:8000 \
  networktocode/nautobot:latest

# Option B: Kubernetes (enterprise)
helm repo add networktocode https://helm.networktocode.com
helm install nautobot networktocode/nautobot \
  --values values.yaml \
  --namespace nautobot

# Option C: Bare metal Python
pip install nautobot
nautobot-server init
nautobot-server migrate
nautobot-server createsuperuser
```

### 1.2 Configure Nautobot Database

```python
# nautobot_config.py - Add custom tables for firewall changes
PLUGINS = [
    "nautobot_firewall_changes",
    "nautobot_git",
    "nautobot_webhooks",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "nautobot",
        "USER": "nautobot",
        "PASSWORD": "secure_password",
        "HOST": "postgres-host",
        "PORT": 5432,
    }
}

# Git integration for version control
PLUGINS_CONFIG = {
    "nautobot_git": {
        "repo_path": "/var/lib/nautobot/git_repos",
        "auto_commit": True,
        "commit_interval_seconds": 300,
    },
    "nautobot_firewall_changes": {
        "retention_days": 1095,  # 3 years
        "git_enabled": True,
    }
}
```

---

## Part 2: Custom Firewall Change Collector Plugin

### 2.1 Plugin Structure

```
nautobot_firewall_changes/
├── __init__.py
├── models.py              # Database schema for changes
├── views.py               # UI endpoints
├── forms.py               # Configuration forms
├── jobs.py                # Collector jobs
├── collectors/
│   ├── __init__.py
│   ├── palo_alto.py       # PA-OS API collector
│   ├── cisco_asa.py       # Cisco ASA collector
│   ├── cisco_nexus.py     # Nexus collector
│   ├── fortigate.py       # FortiGate collector
│   └── base.py            # Abstract base class
├── parsers/
│   ├── __init__.py
│   ├── rule_normalizer.py # Convert vendor formats to common schema
│   └── change_parser.py   # Diff & change identification
└── templates/
    └── nautobot_firewall_changes/
        ├── change_list.html
        ├── change_detail.html
        └── dashboard.html
```

### 2.2 Database Models

```python
# models.py
from django.db import models
from nautobot.core.models import BaseModel

class FirewallDevice(BaseModel):
    """Track managed firewall devices"""
    name = models.CharField(max_length=100, unique=True)
    device_type = models.CharField(
        max_length=50,
        choices=[
            ('palo_alto', 'Palo Alto Networks'),
            ('cisco_asa', 'Cisco ASA'),
            ('cisco_nexus', 'Cisco Nexus'),
            ('fortigate', 'FortiGate'),
            ('checkpoint', 'Check Point'),
        ]
    )
    management_ip = models.GenericIPAddressField()
    api_endpoint = models.URLField()
    api_username = models.CharField(max_length=100)
    api_password = models.CharField(max_length=256)  # Encrypt in production!
    api_key = models.CharField(max_length=512, blank=True, null=True)
    enabled = models.BooleanField(default=True)
    last_sync = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Firewall Device"
    
    def __str__(self):
        return f"{self.name} ({self.device_type})"


class FirewallConfiguration(BaseModel):
    """Store firewall configuration snapshots"""
    device = models.ForeignKey(FirewallDevice, on_delete=models.CASCADE)
    raw_config = models.TextField()  # Full XML/JSON config
    config_hash = models.CharField(max_length=64, unique=True)  # SHA-256
    timestamp = models.DateTimeField(auto_now_add=True)
    git_commit_hash = models.CharField(max_length=40, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['device', '-timestamp']),
        ]


class FirewallRule(BaseModel):
    """Normalized firewall rule representation"""
    device = models.ForeignKey(FirewallDevice, on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=100)  # Rule number/name
    rule_name = models.CharField(max_length=255)
    
    # Normalized fields (vendor-agnostic)
    source_zones = models.JSONField(default=list)  # ["trust", "dmz"]
    dest_zones = models.JSONField(default=list)
    source_ips = models.JSONField(default=list)  # CIDR blocks
    dest_ips = models.JSONField(default=list)
    services = models.JSONField(default=list)  # ["tcp/22", "tcp/443"]
    action = models.CharField(
        max_length=20,
        choices=[
            ('allow', 'Allow'),
            ('deny', 'Deny'),
            ('drop', 'Drop'),
            ('reject', 'Reject'),
        ]
    )
    logging_enabled = models.BooleanField(default=False)
    disabled = models.BooleanField(default=False)
    sequence_number = models.IntegerField()
    raw_rule = models.JSONField()  # Vendor-specific data
    
    class Meta:
        ordering = ['sequence_number']
        unique_together = ('device', 'rule_id', 'rule_name')


class FirewallChange(BaseModel):
    """Track individual rule/config changes"""
    CHANGE_TYPES = [
        ('rule_added', 'Rule Added'),
        ('rule_deleted', 'Rule Deleted'),
        ('rule_modified', 'Rule Modified'),
        ('object_added', 'Object Added'),
        ('object_deleted', 'Object Deleted'),
        ('object_modified', 'Object Modified'),
        ('policy_changed', 'Policy Changed'),
    ]
    
    device = models.ForeignKey(FirewallDevice, on_delete=models.CASCADE)
    change_type = models.CharField(max_length=30, choices=CHANGE_TYPES)
    rule_id = models.CharField(max_length=100, null=True, blank=True)
    rule_name = models.CharField(max_length=255, null=True, blank=True)
    
    # Before/after states
    before_state = models.JSONField()  # Full rule object
    after_state = models.JSONField()
    diff = models.TextField()  # Human-readable diff
    
    # Metadata
    detected_at = models.DateTimeField(auto_now_add=True)
    detected_by = models.CharField(max_length=50, default="api")  # api, syslog, snapshot
    change_ticket = models.CharField(max_length=50, null=True, blank=True)  # ServiceNow ID
    approval_status = models.CharField(
        max_length=20,
        choices=[
            ('approved', 'Approved'),
            ('pending', 'Pending'),
            ('rejected', 'Rejected'),
            ('unknown', 'Unknown'),
        ],
        default='unknown'
    )
    
    # Analysis
    severity = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('info', 'Info'),
        ],
        default='medium'
    )
    analysis_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['device', '-detected_at']),
            models.Index(fields=['change_type', '-detected_at']),
            models.Index(fields=['approval_status']),
        ]


class ChangeAlert(BaseModel):
    """Notifications for changes"""
    change = models.OneToOneField(FirewallChange, on_delete=models.CASCADE)
    alert_type = models.CharField(
        max_length=30,
        choices=[
            ('unauthorized', 'Unauthorized Change'),
            ('high_risk', 'High Risk Change'),
            ('approval_missing', 'Missing Approval'),
            ('drift_detected', 'Configuration Drift'),
        ]
    )
    sent_to = models.CharField(max_length=255)  # webhook URL or email
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('sent', 'Sent'),
            ('failed', 'Failed'),
        ],
        default='pending'
    )
    sent_at = models.DateTimeField(null=True, blank=True)
    response = models.TextField(blank=True)
```

### 2.3 Base Collector Class

```python
# collectors/base.py
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class FirewallCollectorBase(ABC):
    """Abstract base class for firewall collectors"""
    
    def __init__(self, device_config: Dict):
        self.device = device_config
        self.config = None
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to firewall"""
        pass
    
    @abstractmethod
    def get_full_config(self) -> str:
        """Retrieve complete firewall configuration"""
        pass
    
    @abstractmethod
    def get_rules(self) -> List[Dict]:
        """Parse and return normalized rules"""
        pass
    
    def compare_configs(self, old_config: str, new_config: str) -> Tuple[str, List[Dict]]:
        """Generate diff and list of changes"""
        import difflib
        
        old_lines = old_config.split('\n')
        new_lines = new_config.split('\n')
        
        diff = '\n'.join(difflib.unified_diff(
            old_lines, new_lines,
            fromfile='before', tofile='after',
            lineterm=''
        ))
        
        # Extract changes (simplified)
        changes = []
        for line in diff.split('\n'):
            if line.startswith('+ ') or line.startswith('- '):
                changes.append({'line': line})
        
        return diff, changes
    
    def disconnect(self):
        """Close connection"""
        pass
```

---

## Part 3: Vendor-Specific Collectors

### 3.1 Palo Alto Networks Collector

```python
# collectors/palo_alto.py
import requests
import xml.etree.ElementTree as ET
from .base import FirewallCollectorBase
import logging

logger = logging.getLogger(__name__)

class PaloAltoCollector(FirewallCollectorBase):
    """Collector for Palo Alto Networks firewalls"""
    
    def __init__(self, device_config: Dict):
        super().__init__(device_config)
        self.session = requests.Session()
        self.api_key = device_config.get('api_key') or self._get_api_key()
        self.base_url = f"https://{device_config['management_ip']}"
    
    def _get_api_key(self) -> str:
        """Generate API key from username/password"""
        url = f"{self.base_url}/api/?type=keygen"
        params = {
            'user': self.device['api_username'],
            'passwd': self.device['api_password']
        }
        
        response = self.session.get(url, params=params, verify=False)
        root = ET.fromstring(response.text)
        return root.find('./result/key').text
    
    def connect(self) -> bool:
        """Test connection"""
        try:
            url = f"{self.base_url}/api/?type=op&cmd=<test><blah/></test>&key={self.api_key}"
            response = self.session.get(url, verify=False, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def get_full_config(self) -> str:
        """Retrieve full firewall config as XML"""
        url = f"{self.base_url}/api/"
        params = {
            'type': 'export',
            'category': 'configuration',
            'key': self.api_key
        }
        
        response = self.session.get(url, params=params, verify=False)
        return response.text
    
    def get_rules(self) -> List[Dict]:
        """Extract security rules from device"""
        url = f"{self.base_url}/api/"
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules',
            'key': self.api_key
        }
        
        response = self.session.get(url, params=params, verify=False)
        root = ET.fromstring(response.text)
        
        rules = []
        for idx, rule_elem in enumerate(root.findall('.//entry'), 1):
            rule = {
                'rule_id': rule_elem.get('name'),
                'rule_name': rule_elem.get('name'),
                'sequence_number': idx,
                'source_zones': [elem.text for elem in rule_elem.findall('.//from/member')],
                'dest_zones': [elem.text for elem in rule_elem.findall('.//to/member')],
                'source_ips': [elem.text for elem in rule_elem.findall('.//source/member')],
                'dest_ips': [elem.text for elem in rule_elem.findall('.//destination/member')],
                'services': [elem.text for elem in rule_elem.findall('.//service/member')],
                'action': rule_elem.findtext('.//action'),
                'logging_enabled': rule_elem.findtext('.//log-end') == 'yes',
                'disabled': rule_elem.findtext('.//disabled') == 'yes',
                'raw_rule': ET.tostring(rule_elem, encoding='unicode')
            }
            rules.append(rule)
        
        return rules
    
    def get_incremental_changes(self, since_timestamp: str = None) -> List[Dict]:
        """Get changes via syslog or audit logs (if available)"""
        # PA-OS doesn't expose incremental changes directly
        # Use full config diff as fallback
        return []
```

### 3.2 Cisco ASA Collector

```python
# collectors/cisco_asa.py
from netmiko import ConnectHandler
from .base import FirewallCollectorBase
import logging

logger = logging.getLogger(__name__)

class CiscoASACollector(FirewallCollectorBase):
    """Collector for Cisco ASA firewalls"""
    
    def __init__(self, device_config: Dict):
        super().__init__(device_config)
        self.ssh_conn = None
        self.device_params = {
            'device_type': 'cisco_asa',
            'host': device_config['management_ip'],
            'username': device_config['api_username'],
            'password': device_config['api_password'],
            'port': 22,
            'timeout': 30,
        }
    
    def connect(self) -> bool:
        """SSH connection to ASA"""
        try:
            self.ssh_conn = ConnectHandler(**self.device_params)
            self.ssh_conn.enable()
            return True
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            return False
    
    def get_full_config(self) -> str:
        """Retrieve running config"""
        return self.ssh_conn.send_command('show running-config')
    
    def get_rules(self) -> List[Dict]:
        """Parse ACL rules from ASA"""
        output = self.ssh_conn.send_command('show access-list')
        
        rules = []
        lines = output.split('\n')
        rule_num = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('access-list'):
                continue
            
            rule_num += 1
            # Parse standard ACL format: permit/deny protocol source dest
            parts = line.split()
            if len(parts) < 4:
                continue
            
            rule = {
                'rule_id': f"line_{rule_num}",
                'rule_name': line[:60],  # Truncate long lines
                'sequence_number': rule_num,
                'action': parts[0],  # permit/deny
                'services': [parts[1]],  # protocol
                'source_ips': [parts[2]] if parts[2] != 'any' else ['0.0.0.0/0'],
                'dest_ips': [parts[3]] if parts[3] != 'any' else ['0.0.0.0/0'],
                'source_zones': ['unknown'],
                'dest_zones': ['unknown'],
                'logging_enabled': 'log' in line,
                'disabled': False,
                'raw_rule': line
            }
            rules.append(rule)
        
        return rules
    
    def disconnect(self):
        if self.ssh_conn:
            self.ssh_conn.disconnect()
```

### 3.3 Cisco Nexus Collector

```python
# collectors/cisco_nexus.py
from nxapi_utilities import NXAPI
from .base import FirewallCollectorBase
import logging
import json

logger = logging.getLogger(__name__)

class CiscoNexusCollector(FirewallCollectorBase):
    """Collector for Cisco Nexus switches with firewall modules"""
    
    def __init__(self, device_config: Dict):
        super().__init__(device_config)
        self.nxapi = NXAPI(
            host=device_config['management_ip'],
            username=device_config['api_username'],
            password=device_config['api_password'],
            transport='https'
        )
    
    def connect(self) -> bool:
        try:
            result = self.nxapi.get_json('show version')
            return 'hostname' in result
        except Exception as e:
            logger.error(f"NXAPI connection failed: {e}")
            return False
    
    def get_full_config(self) -> str:
        """Retrieve running configuration"""
        return self.nxapi.get_text('show running-config')
    
    def get_rules(self) -> List[Dict]:
        """Extract access-control-lists (ACLs)"""
        output = self.nxapi.get_json('show access-lists detail')
        
        rules = []
        if 'TABLE_acl' in output:
            for acl in output['TABLE_acl']['ROW_acl']:
                rule_num = 0
                if 'TABLE_ace' in acl:
                    for ace in acl['TABLE_ace']['ROW_ace']:
                        rule_num += 1
                        rule = {
                            'rule_id': f"{acl['aclname']}_line_{rule_num}",
                            'rule_name': f"{acl['aclname']} - {ace.get('protocol', 'any')}",
                            'sequence_number': rule_num,
                            'action': ace.get('permitdeny', 'deny'),
                            'services': [ace.get('protocol', 'ip')],
                            'source_ips': [ace.get('src', '0.0.0.0/0')],
                            'dest_ips': [ace.get('dst', '0.0.0.0/0')],
                            'source_zones': [],
                            'dest_zones': [],
                            'logging_enabled': 'log' in str(ace),
                            'disabled': False,
                            'raw_rule': ace
                        }
                        rules.append(rule)
        
        return rules
```

---

## Part 4: Change Detection & Analysis Jobs

### 4.1 Scheduled Collector Job

```python
# jobs.py
from nautobot.core.celery import register_jobs
from nautobot.core.jobs import Job, StringVar, BooleanVar
from celery.schedules import crontab
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from datetime import datetime
from .models import FirewallDevice, FirewallConfiguration, FirewallChange
from .collectors.palo_alto import PaloAltoCollector
from .collectors.cisco_asa import CiscoASACollector
from .collectors.cisco_nexus import CiscoNexusCollector
import logging
import hashlib

logger = logging.getLogger(__name__)

COLLECTOR_MAP = {
    'palo_alto': PaloAltoCollector,
    'cisco_asa': CiscoASACollector,
    'cisco_nexus': CiscoNexusCollector,
}


class CollectFirewallConfigs(Job):
    """Scheduled job to collect firewall configurations"""
    description = "Collect current configuration from all firewalls"
    
    device = StringVar(
        description="Device name (or 'all' for all devices)",
        default="all"
    )
    
    def execute(self):
        if self.device == "all":
            devices = FirewallDevice.objects.filter(enabled=True)
        else:
            devices = FirewallDevice.objects.filter(name=self.device)
        
        for device in devices:
            try:
                self.log_info(f"Collecting config from {device.name}...")
                
                # Instantiate appropriate collector
                collector_class = COLLECTOR_MAP.get(device.device_type)
                if not collector_class:
                    self.log_warning(f"No collector for {device.device_type}")
                    continue
                
                collector = collector_class({
                    'management_ip': device.management_ip,
                    'api_username': device.api_username,
                    'api_password': device.api_password,
                    'api_key': device.api_key,
                })
                
                # Connect and retrieve config
                if not collector.connect():
                    self.log_error(f"Failed to connect to {device.name}")
                    continue
                
                new_config = collector.get_full_config()
                new_rules = collector.get_rules()
                
                # Calculate config hash
                config_hash = hashlib.sha256(new_config.encode()).hexdigest()
                
                # Check if config changed
                last_config = FirewallConfiguration.objects.filter(
                    device=device
                ).latest('timestamp') if FirewallConfiguration.objects.filter(device=device).exists() else None
                
                if last_config and last_config.config_hash == config_hash:
                    self.log_info(f"No changes detected on {device.name}")
                    device.last_sync = datetime.now()
                    device.save()
                    continue
                
                # Save new configuration
                new_config_obj = FirewallConfiguration.objects.create(
                    device=device,
                    raw_config=new_config,
                    config_hash=config_hash
                )
                
                # Detect changes
                if last_config:
                    diff, changes = collector.compare_configs(
                        last_config.raw_config,
                        new_config
                    )
                    self._analyze_changes(device, diff, changes, new_rules)
                
                # Update device sync time
                device.last_sync = datetime.now()
                device.save()
                
                self.log_success(f"✓ {device.name} synchronized")
                
                collector.disconnect()
                
            except Exception as e:
                logger.exception(f"Error collecting from {device.name}: {e}")
                self.log_error(f"✗ Error: {str(e)}")
    
    def _analyze_changes(self, device, diff, changes, new_rules):
        """Analyze detected changes"""
        # Parse diff to identify rule changes
        rule_changes = self._extract_rule_changes(diff, new_rules)
        
        for change in rule_changes:
            change_obj = FirewallChange.objects.create(
                device=device,
                change_type=change.get('type'),
                rule_id=change.get('rule_id'),
                rule_name=change.get('rule_name'),
                before_state=change.get('before', {}),
                after_state=change.get('after', {}),
                diff=change.get('diff', ''),
                detected_by='api',
                severity=self._assess_severity(change)
            )
            
            # Create alert if needed
            self._create_alert_if_needed(change_obj)
    
    def _assess_severity(self, change: Dict) -> str:
        """Assess change severity"""
        rule = change.get('after', {})
        
        # Critical: Any rule allowing "any" to "any"
        if (rule.get('source_ips') == ['0.0.0.0/0'] and 
            rule.get('dest_ips') == ['0.0.0.0/0'] and
            rule.get('action') == 'allow'):
            return 'critical'
        
        # High: Logging disabled on existing rule
        if not rule.get('logging_enabled'):
            return 'high'
        
        # Medium: Normal rule change
        return 'medium'
    
    def _extract_rule_changes(self, diff: str, new_rules: List[Dict]) -> List[Dict]:
        """Extract specific rule changes from diff output"""
        # Simplified extraction - in production, use more sophisticated parsing
        changes = []
        
        for line in diff.split('\n'):
            if line.startswith('+ '):  # Added line
                changes.append({
                    'type': 'rule_added',
                    'line': line,
                    'after': {'raw_rule': line},
                })
            elif line.startswith('- '):  # Deleted line
                changes.append({
                    'type': 'rule_deleted',
                    'line': line,
                    'before': {'raw_rule': line},
                })
        
        return changes
    
    def _create_alert_if_needed(self, change_obj):
        """Create alert for high-risk changes"""
        if change_obj.severity in ['critical', 'high']:
            from .models import ChangeAlert
            ChangeAlert.objects.create(
                change=change_obj,
                alert_type='high_risk',
                sent_to='slack://webhook-url',
                status='pending'
            )


# Register the job as a periodic task (every 15 minutes)
class ScheduledCollectorTask:
    """Scheduled task that runs every 15 minutes"""
    
    @staticmethod
    def schedule():
        schedule, created = CrontabSchedule.objects.get_or_create(
            minute='*/15',  # Every 15 minutes
            hour='*',
            day_of_week='*',
        )
        
        PeriodicTask.objects.update_or_create(
            name='Collect Firewall Configs',
            defaults={
                'task': 'nautobot_firewall_changes.jobs.CollectFirewallConfigs',
                'crontab': schedule,
            }
        )


register_jobs(CollectFirewallConfigs)
```

---

## Part 5: Git Integration for Version Control

### 5.1 Git Configuration Storage

```python
# git_integration.py
import git
import os
from datetime import datetime
from .models import FirewallConfiguration, FirewallDevice

class GitConfigManager:
    """Manage firewall configs in Git for version control"""
    
    def __init__(self, repo_path: str = "/var/lib/nautobot/firewall_configs"):
        self.repo_path = repo_path
        if not os.path.exists(repo_path):
            os.makedirs(repo_path)
            self.repo = git.Repo.init(repo_path)
        else:
            self.repo = git.Repo(repo_path)
    
    def commit_configuration(self, device: FirewallDevice, config: str) -> str:
        """Commit config to Git"""
        # Create device directory
        device_dir = os.path.join(self.repo_path, device.name)
        os.makedirs(device_dir, exist_ok=True)
        
        # Write config to file
        config_file = os.path.join(device_dir, 'running-config.txt')
        with open(config_file, 'w') as f:
            f.write(config)
        
        # Stage and commit
        self.repo.index.add([config_file])
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        commit = self.repo.index.commit(
            f"Update {device.name} config - {timestamp}",
            author=git.Actor('Nautobot', 'nautobot@example.com')
        )
        
        return commit.hexsha
    
    def get_config_history(self, device: FirewallDevice, limit: int = 50):
        """Get config history for device"""
        device_dir = f"{device.name}/running-config.txt"
        
        history = []
        for commit in self.repo.iter_commits(paths=device_dir)[:limit]:
            history.append({
                'commit_hash': commit.hexsha[:8],
                'timestamp': datetime.fromtimestamp(commit.committed_date),
                'message': commit.message.strip(),
                'author': commit.author.name,
            })
        
        return history
    
    def diff_configs(self, device: FirewallDevice, commit1: str, commit2: str) -> str:
        """Show diff between two config commits"""
        diffs = self.repo.commit(commit1).diff(commit2)
        
        output = []
        for diff_item in diffs:
            output.append(f"File: {diff_item.a_path}")
            output.append(diff_item.diff.decode('utf-8'))
        
        return '\n'.join(output)
    
    def rollback_config(self, device: FirewallDevice, target_commit: str):
        """Checkout specific commit"""
        self.repo.git.checkout(target_commit, '--', f"{device.name}/running-config.txt")
        
        config_file = os.path.join(self.repo_path, device.name, 'running-config.txt')
        with open(config_file, 'r') as f:
            return f.read()
```

---

## Part 6: Dashboard & Reporting

### 6.1 Django View for Change Dashboard

```python
# views.py
from django.shortcuts import render
from django.views.generic import ListView, DetailView
from django.db.models import Count, Q
from datetime import timedelta
from django.utils import timezone
from .models import FirewallChange, FirewallDevice, ChangeAlert

class ChangeListView(ListView):
    """Display recent changes with filtering"""
    model = FirewallChange
    template_name = 'nautobot_firewall_changes/change_list.html'
    context_object_name = 'changes'
    paginate_by = 50
    
    def get_queryset(self):
        queryset = FirewallChange.objects.select_related('device').order_by('-detected_at')
        
        # Filter by device
        device_id = self.request.GET.get('device')
        if device_id:
            queryset = queryset.filter(device_id=device_id)
        
        # Filter by change type
        change_type = self.request.GET.get('type')
        if change_type:
            queryset = queryset.filter(change_type=change_type)
        
        # Filter by severity
        severity = self.request.GET.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by date range
        days = self.request.GET.get('days', 7)
        since = timezone.now() - timedelta(days=int(days))
        queryset = queryset.filter(detected_at__gte=since)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['devices'] = FirewallDevice.objects.all()
        context['change_types'] = FirewallChange.CHANGE_TYPES
        
        # Dashboard stats
        context['total_changes'] = FirewallChange.objects.count()
        context['critical_changes'] = FirewallChange.objects.filter(severity='critical').count()
        context['pending_alerts'] = ChangeAlert.objects.filter(status='pending').count()
        context['unapproved_changes'] = FirewallChange.objects.filter(approval_status='unknown').count()
        
        return context


class ChangeDetailView(DetailView):
    """Detailed view of single change with before/after"""
    model = FirewallChange
    template_name = 'nautobot_firewall_changes/change_detail.html'
    context_object_name = 'change'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        change = self.get_object()
        
        # Get related changes (other rules on same device in same timeframe)
        context['related_changes'] = FirewallChange.objects.filter(
            device=change.device,
            detected_at__range=[
                change.detected_at - timedelta(minutes=30),
                change.detected_at + timedelta(minutes=30)
            ]
        ).exclude(id=change.id)[:10]
        
        return context


def dashboard_view(request):
    """Overall security posture dashboard"""
    
    # Last 7 days of changes
    since = timezone.now() - timedelta(days=7)
    changes_7d = FirewallChange.objects.filter(detected_at__gte=since)
    
    # Changes by device
    by_device = changes_7d.values('device__name').annotate(count=Count('id')).order_by('-count')[:10]
    
    # Changes by type
    by_type = changes_7d.values('change_type').annotate(count=Count('id')).order_by('-count')
    
    # Changes by severity
    by_severity = changes_7d.values('severity').annotate(count=Count('id'))
    
    # Unapproved changes
    unapproved = FirewallChange.objects.filter(
        approval_status='unknown',
        detected_at__gte=since
    ).order_by('-detected_at')[:15]
    
    # Critical alerts
    critical_alerts = ChangeAlert.objects.filter(
        alert_type__in=['critical', 'unauthorized'],
        status='pending'
    )[:10]
    
    context = {
        'total_changes_7d': changes_7d.count(),
        'critical_changes': changes_7d.filter(severity='critical').count(),
        'changes_by_device': by_device,
        'changes_by_type': by_type,
        'changes_by_severity': by_severity,
        'unapproved_changes': unapproved,
        'critical_alerts': critical_alerts,
    }
    
    return render(request, 'nautobot_firewall_changes/dashboard.html', context)
```

### 6.1 HTML Dashboard Template

```html
<!-- templates/nautobot_firewall_changes/dashboard.html -->
{% extends "base.html" %}
{% load humanize %}

{% block title %}Firewall Change Dashboard{% endblock %}

{% block content %}
<div class="container-fluid">
    <h1>Firewall Configuration Change Tracking</h1>
    
    <!-- Key Metrics -->
    <div class="row mt-4">
        <div class="col-md-3">
            <div class="card border-primary">
                <div class="card-body">
                    <h5 class="card-title">Total Changes (7d)</h5>
                    <p class="card-text display-4 text-primary">{{ total_changes_7d }}</p>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-danger">
                <div class="card-body">
                    <h5 class="card-title">Critical Changes</h5>
                    <p class="card-text display-4 text-danger">{{ critical_changes }}</p>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-warning">
                <div class="card-body">
                    <h5 class="card-title">Unapproved Changes</h5>
                    <p class="card-text display-4 text-warning">{{ unapproved_changes|length }}</p>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-info">
                <div class="card-body">
                    <h5 class="card-title">Pending Alerts</h5>
                    <p class="card-text display-4 text-info">{{ critical_alerts|length }}</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Charts -->
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">Changes by Device</div>
                <div class="card-body">
                    <canvas id="deviceChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">Changes by Severity</div>
                <div class="card-body">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Recent Unapproved Changes -->
    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card">
                <div class="card-header bg-warning">
                    <h5>Pending Approval ({{ unapproved_changes|length }})</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped table-sm">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>Type</th>
                                <th>Rule</th>
                                <th>Detected</th>
                                <th>Severity</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for change in unapproved_changes %}
                            <tr>
                                <td>{{ change.device.name }}</td>
                                <td>{{ change.get_change_type_display }}</td>
                                <td>{{ change.rule_name|truncatewords:3 }}</td>
                                <td>{{ change.detected_at|naturaltime }}</td>
                                <td>
                                    <span class="badge badge-{{ change.severity }}">
                                        {{ change.severity|title }}
                                    </span>
                                </td>
                                <td>
                                    <a href="{% url 'change-detail' change.id %}" class="btn btn-sm btn-info">Review</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Device chart
const deviceCtx = document.getElementById('deviceChart').getContext('2d');
new Chart(deviceCtx, {
    type: 'bar',
    data: {
        labels: {{ devices_list|safe }},
        datasets: [{
            label: 'Changes',
            data: {{ device_counts|safe }},
            backgroundColor: '#007bff'
        }]
    }
});

// Severity pie chart
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {
    type: 'pie',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: {{ severity_data|safe }},
            backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']
        }]
    }
});
</script>
{% endblock %}
```

---

## Part 7: Webhook Integration for Alerts

### 7.1 Slack Integration

```python
# webhooks.py
import requests
import json
from .models import ChangeAlert, FirewallChange
import logging

logger = logging.getLogger(__name__)

class SlackNotifier:
    """Send alerts to Slack"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_change_alert(self, change: FirewallChange):
        """Notify Slack of firewall change"""
        
        severity_color = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d',
        }
        
        payload = {
            'attachments': [{
                'color': severity_color.get(change.severity, '#808080'),
                'title': f'Firewall Change: {change.get_change_type_display()}',
                'fields': [
                    {
                        'title': 'Device',
                        'value': change.device.name,
                        'short': True
                    },
                    {
                        'title': 'Severity',
                        'value': change.severity.upper(),
                        'short': True
                    },
                    {
                        'title': 'Rule',
                        'value': change.rule_name or 'N/A',
                        'short': True
                    },
                    {
                        'title': 'Detected',
                        'value': change.detected_at.isoformat(),
                        'short': True
                    },
                    {
                        'title': 'Change Type',
                        'value': change.get_change_type_display(),
                        'short': True
                    },
                    {
                        'title': 'Approval Status',
                        'value': change.get_approval_status_display(),
                        'short': True
                    },
                    {
                        'title': 'Notes',
                        'value': change.analysis_notes or 'No additional notes',
                        'short': False
                    }
                ],
                'actions': [
                    {
                        'type': 'button',
                        'text': 'Review in Nautobot',
                        'url': f'https://nautobot.example.com/plugins/firewall-changes/changes/{change.id}/'
                    }
                ]
            }]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False


class ServiceNowIntegrator:
    """Integrate with ServiceNow for change management"""
    
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url
        self.auth = (username, password)
    
    def link_change_to_ticket(self, change: FirewallChange, ticket_id: str):
        """Link Nautobot change to ServiceNow change request"""
        
        headers = {'Content-Type': 'application/json'}
        
        payload = {
            'short_description': f"Firewall change detected: {change.rule_name}",
            'description': f"""
Device: {change.device.name}
Change Type: {change.get_change_type_display()}
Severity: {change.severity}
Detected: {change.detected_at}

Before State:
{json.dumps(change.before_state, indent=2)}

After State:
{json.dumps(change.after_state, indent=2)}
            """,
            'assignment_group': 'Network Security',
            'impact': {'critical': '1', 'high': '2', 'medium': '3', 'low': '4'}.get(change.severity, '3'),
            'urgency': {'critical': '1', 'high': '2', 'medium': '3', 'low': '4'}.get(change.severity, '3'),
            'cmdb_ci': change.device.name,
        }
        
        url = f"{self.instance_url}/api/now/table/change_request"
        response = requests.post(url, json=payload, auth=self.auth, headers=headers)
        
        if response.status_code == 201:
            ticket_data = response.json()['result']
            change.change_ticket = ticket_data['number']
            change.save()
            return ticket_data['number']
        else:
            logger.error(f"ServiceNow integration failed: {response.text}")
            return None
```

---

## Part 8: Compliance Reporting

### 8.1 Automated Audit Report Generation

```python
# compliance.py
from django.utils import timezone
from datetime import timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from .models import FirewallChange, FirewallDevice
import io

class ComplianceReportGenerator:
    """Generate PCI-DSS, SOC2, HIPAA compliance reports"""
    
    def __init__(self, start_date: str, end_date: str):
        self.start_date = timezone.datetime.fromisoformat(start_date)
        self.end_date = timezone.datetime.fromisoformat(end_date)
    
    def generate_pci_dss_report(self) -> bytes:
        """Generate PCI-DSS 6.5.1 audit report"""
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1F4E78'),
            spaceAfter=30,
        )
        story.append(Paragraph('PCI-DSS 6.5.1 Configuration Change Audit Report', title_style))
        story.append(Spacer(1, 0.3 * 72))
        
        # Executive Summary
        story.append(Paragraph('Executive Summary', styles['Heading2']))
        
        changes = FirewallChange.objects.filter(
            detected_at__range=[self.start_date, self.end_date]
        )
        
        summary_text = f"""
        <b>Reporting Period:</b> {self.start_date.date()} to {self.end_date.date()}<br/>
        <b>Total Changes:</b> {changes.count()}<br/>
        <b>Approved Changes:</b> {changes.filter(approval_status='approved').count()}<br/>
        <b>Unauthorized Changes:</b> {changes.filter(approval_status='rejected').count()}<br/>
        <b>Devices Monitored:</b> {FirewallDevice.objects.count()}<br/>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2 * 72))
        
        # Changes Table
        story.append(Paragraph('Firewall Configuration Changes', styles['Heading2']))
        
        table_data = [
            ['Device', 'Change Type', 'Timestamp', 'Approval Status', 'Severity']
        ]
        
        for change in changes.order_by('-detected_at'):
            table_data.append([
                change.device.name,
                change.get_change_type_display(),
                change.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
                change.get_approval_status_display(),
                change.severity.upper(),
            ])
        
        table = Table(table_data, colWidths=[1.5*72, 1.5*72, 1.5*72, 1.5*72, 1*72])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E75B6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        story.append(table)
        
        # Footer
        story.append(Spacer(1, 0.5 * 72))
        story.append(Paragraph(
            f'Report generated: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")} UTC',
            styles['Normal']
        ))
        
        doc.build(story)
        return buffer.getvalue()
    
    def generate_soc2_report(self) -> bytes:
        """Generate SOC2 Type II control report"""
        # Similar structure, different compliance focus
        pass
    
    def generate_hipaa_report(self) -> bytes:
        """Generate HIPAA audit log report"""
        # Similar structure, includes PHI protection controls
        pass
```

---

## Part 9: Deployment & Operations

### 9.1 Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: nautobot
      POSTGRES_USER: nautobot
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  nautobot:
    image: networktocode/nautobot:latest
    environment:
      NAUTOBOT_DB_HOST: postgres
      NAUTOBOT_DB_NAME: nautobot
      NAUTOBOT_DB_USER: nautobot
      NAUTOBOT_DB_PASSWORD: secure_password
      NAUTOBOT_SECRET_KEY: your-secret-key-here
      NAUTOBOT_REDIS_HOST: redis
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
    volumes:
      - ./plugins/nautobot_firewall_changes:/app/nautobot_firewall_changes

  celery-worker:
    image: networktocode/nautobot:latest
    command: celery -A nautobot worker -l debug
    environment:
      NAUTOBOT_DB_HOST: postgres
      NAUTOBOT_DB_NAME: nautobot
      NAUTOBOT_DB_USER: nautobot
      NAUTOBOT_DB_PASSWORD: secure_password
      NAUTOBOT_REDIS_HOST: redis
    depends_on:
      - postgres
      - redis
      - nautobot

  celery-beat:
    image: networktocode/nautobot:latest
    command: celery -A nautobot beat -l debug
    environment:
      NAUTOBOT_DB_HOST: postgres
      NAUTOBOT_DB_NAME: nautobot
      NAUTOBOT_DB_USER: nautobot
      NAUTOBOT_DB_PASSWORD: secure_password
      NAUTOBOT_REDIS_HOST: redis
    depends_on:
      - postgres
      - redis
      - nautobot

volumes:
  postgres_data:
```

### 9.2 Kubernetes Deployment

```yaml
# kubernetes/nautobot-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nautobot-firewall-tracker
  namespace: nautobot
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nautobot
  template:
    metadata:
      labels:
        app: nautobot
    spec:
      containers:
      - name: nautobot
        image: networktocode/nautobot:latest
        ports:
        - containerPort: 8000
        env:
        - name: NAUTOBOT_DB_HOST
          valueFrom:
            configMapKeyRef:
              name: nautobot-config
              key: db-host
        - name: NAUTOBOT_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: nautobot-secrets
              key: db-password
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"

---
apiVersion: v1
kind: Service
metadata:
  name: nautobot-service
  namespace: nautobot
spec:
  selector:
    app: nautobot
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

---

## Part 10: Complete Implementation Checklist

```
PRE-DEPLOYMENT
☐ Inventory all firewall devices (vendor, version, management IP)
☐ Verify API capabilities for each device
☐ Plan Git repository structure
☐ Establish change management process integration
☐ Define approval workflows
☐ Set up Slack/ServiceNow webhooks
☐ Plan data retention (3+ years)

NAUTOBOT SETUP
☐ Deploy Nautobot (Docker, K8s, or bare metal)
☐ Configure PostgreSQL database
☐ Set up Redis for Celery
☐ Install nautobot_firewall_changes plugin
☐ Configure git integration (repo path, auto-commit)
☐ Set up Celery Beat for scheduled tasks
☐ Create superuser account

FIREWALL INTEGRATION
☐ Enable API on each firewall (if supported)
☐ Create API credentials (read-only where possible)
☐ Test connectivity from Nautobot
☐ Configure syslog export (if API unavailable)
☐ Set up SNMP traps for alerts
☐ Establish baseline configuration in Git

CUSTOMIZATION
☐ Deploy vendor-specific collectors
☐ Implement rule normalization for each vendor
☐ Configure change analysis rules
☐ Set severity assessment thresholds
☐ Create custom dashboards
☐ Develop compliance report templates

ALERTS & INTEGRATION
☐ Configure Slack webhook notifications
☐ Set up ServiceNow change request linkage
☐ Create escalation rules (critical changes)
☐ Test alert delivery
☐ Set up email notifications

MONITORING & OPERATIONS
☐ Monitor Celery worker/beat health
☐ Set up log aggregation (ELK, Splunk)
☐ Create runbooks for common scenarios
☐ Establish on-call procedures
☐ Schedule regular compliance reports

TESTING
☐ Make test change on dev firewall, verify detection
☐ Test rollback capability
☐ Validate report generation
☐ Test alert delivery to all channels
☐ Load test with multiple concurrent changes
☐ Disaster recovery drill
```

---

## Key Advantages of This Approach

| Feature | Benefit |
|---------|---------|
| **Open Source** | No licensing costs; full control over codebase |
| **Extensible** | Easy to add new device types or integrations |
| **Git-Based** | Full version control history; easy rollbacks |
| **API-Driven** | Near real-time change detection; no polling overhead |
| **Vendor-Agnostic** | Single pane of glass for all firewall vendors |
| **Compliance-Ready** | Built-in audit trails and report generation |
| **Scalable** | Kubernetes-native; handles thousands of devices |
| **Customizable** | Adapt change analysis to your risk model |

---

## Limitations & Workarounds

| Limitation | Workaround |
|-----------|-----------|
| No native workflow engine | Integrate with ServiceNow/Jira via webhooks |
| Requires custom plugins | Community plugins available; hire dev if needed |
| Learning curve | Strong Python/Django knowledge required for team |
| No GUI rule builder | API-first; use change requests from external tools |
| Vendor API inconsistency | Abstract via collector classes; add as needed |

---

## Support & Resources

- **Nautobot Docs:** https://docs.nautobot.com
- **Network to Code Community:** https://slack.networktocode.com
- **GitHub Issues:** https://github.com/nautobot/nautobot/issues
- **Nautobot Plugins:** https://github.com/topics/nautobot-plugin
