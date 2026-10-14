# AWS Network Automation & Security Auditing with Python (Boto3)

## Project Overview

This hands-on cloud computing project demonstrates how Python and the AWS SDK for Python (Boto3) can automate network infrastructure discovery, security auditing, performance monitoring, and resource quota management.

The project was completed in a guided AWS lab environment as part of my Cloud Computing and DevOps studies.

The objective was to understand how cloud engineers can use automation to manage AWS infrastructure efficiently, identify security risks, and generate useful operational reports.

## Technologies Used

- **Amazon Web Services (AWS)**
- **Python 3**
- **Boto3 (AWS SDK for Python)**
- **Amazon EC2**
- **Amazon VPC**
- **AWS Identity and Access Management (IAM)**
- **Amazon CloudWatch**
- **AWS Service Quotas**
- **JSON and CSV**
- **Linux Terminal**

## Project Structure

The project consists of eight Python scripts:

| Script | Purpose |
|---|---|
| `session_test.py` | Authenticate and verify AWS connectivity |
| `discover.py` | Discover VPCs, subnets, and Internet Gateways |
| `discover_paginated.py` | Retrieve network resources using API pagination |
| `find_insecure.py` | Identify potentially insecure SSH rules |
| `audit.py` | Compare Security Groups against a security policy |
| `metrics.py` | Monitor EC2 network traffic through CloudWatch |
| `eni_export.py` | Export network interface information to CSV |
| `quota_check.py` | Monitor AWS resource quotas |

---

## 1. AWS Authentication with Boto3

**File: `session_test.py`**

The first task was to establish a Boto3 session and verify that the lab environment could successfully authenticate with AWS.

```python
import boto3

session = boto3.Session()
sts = session.client('sts')
identity = sts.get_caller_identity()

print(f"Account: {identity['Account']}")
print(f"ARN: {identity['Arn']}")
print(f"Region: {session.region_name}")
print("Session initialized successfully.")
```

### Explanation

- `boto3.Session()` initializes an AWS session.
- `sts` provides access to AWS Security Token Service.
- `get_caller_identity()` retrieves information about the current AWS identity.
- The script displays the AWS account, IAM identity ARN, and configured region.

**Result:** Successfully authenticated using the IAM role provided by the lab environment.

No AWS access keys were hardcoded into the script.

---

## 2. Discovering AWS Network Resources

**File: `discover.py`**

This script automatically retrieves information about VPCs, subnets, and Internet Gateways.

```python
import boto3

ec2 = boto3.client('ec2')

def get_name(resource):
    return next(
        (t['Value'] for t in resource.get('Tags', [])
         if t['Key'] == 'Name'),
        'N/A'
    )

print("=" * 65)
print("VPCs")
print("=" * 65)

vpcs = ec2.describe_vpcs()['Vpcs']

for vpc in vpcs:
    print(
        f"  {vpc['VpcId']} "
        f"CIDR: {vpc['CidrBlock']:18s} "
        f"Name: {get_name(vpc)}"
    )

print(f"\n  Total: {len(vpcs)} VPCs")

print(f"\n{'=' * 65}")
print("SUBNETS")
print("=" * 65)

subnets = ec2.describe_subnets()['Subnets']

for sn in subnets:
    print(
        f"  {sn['SubnetId']} "
        f"CIDR: {sn['CidrBlock']:18s} "
        f"AZ: {sn['AvailabilityZone']} "
        f"Name: {get_name(sn)}"
    )

print(f"\n  Total: {len(subnets)} subnets")

print(f"\n{'=' * 65}")
print("INTERNET GATEWAYS")
print("=" * 65)

igws = ec2.describe_internet_gateways()['InternetGateways']

for igw in igws:
    attached = [
        a['VpcId'] for a in igw['Attachments']
    ]

    print(
        f"  {igw['InternetGatewayId']} "
        f"Attached to: {attached} "
        f"Name: {get_name(igw)}"
    )

print(f"\n  Total: {len(igws)} internet gateways")
```

### Explanation

The script uses AWS EC2 API operations to discover network resources.

- **VPC:** A logically isolated virtual network in AWS.
- **Subnet:** A smaller network segment inside a VPC.
- **Internet Gateway:** A component that enables internet connectivity when correctly configured.
- **CIDR:** Defines the IP address range associated with a network.

**Result:** Successfully retrieved the lab's VPCs, subnets, and Internet Gateways.

---

## 3. AWS API Pagination

**File: `discover_paginated.py`**

AWS APIs can return large amounts of data. Pagination allows a script to retrieve results across multiple pages.

```python
import boto3

ec2 = boto3.client('ec2')

def get_name(resource):
    return next(
        (t['Value'] for t in resource.get('Tags', [])
         if t['Key'] == 'Name'),
        'N/A'
    )

print("=" * 65)
print("PAGINATED SUBNET DISCOVERY")
print("=" * 65)

paginator = ec2.get_paginator('describe_subnets')

page_num = 0
total = 0

for page in paginator.paginate(
    PaginationConfig={'PageSize': 5}
):
    page_num += 1
    subnets = page['Subnets']

    print(
        f"\n--- Page {page_num} "
        f"({len(subnets)} results) ---"
    )

    for sn in subnets:
        total += 1
        print(
            f"  {sn['SubnetId']} "
            f"CIDR: {sn['CidrBlock']:18s} "
            f"Name: {get_name(sn)}"
        )

print(
    f"\nFetched {total} subnets "
    f"across {page_num} page(s)"
)
```

### Explanation

The Boto3 paginator automatically handles multiple API result pages.

This approach is useful for larger AWS environments where hundreds or thousands of resources may exist.

**Result:** Successfully retrieved subnet information using pagination.

---

## 4. Identifying Insecure Security Group Rules

**File: `find_insecure.py`**

Security Groups act as virtual firewalls controlling traffic to AWS resources.

This script identifies SSH rules that expose port 22 to the entire IPv4 internet.

```python
import boto3

ec2 = boto3.client('ec2')

def get_name(sg):
    return sg.get('GroupName', 'N/A')

print("=" * 65)
print("INSECURE SECURITY GROUP RULES")
print("=" * 65)

sgs = ec2.describe_security_groups()['SecurityGroups']

violations = []

for sg in sgs:
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', 'All')

        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')

            if cidr == '0.0.0.0/0' and from_port == 22:
                violations.append({
                    'sg_id': sg['GroupId'],
                    'sg_name': get_name(sg),
                    'port': from_port,
                    'cidr': cidr
                })

if violations:
    print(
        f"\nFound {len(violations)} "
        f"violation(s):\n"
    )

    for v in violations:
        print(
            f"[HIGH] {v['sg_name']} "
            f"({v['sg_id']})"
        )
        print(
            f"SSH (port {v['port']}) "
            f"open to {v['cidr']}"
        )
else:
    print("\nNo insecure SSH rules found.")

print(
    f"\nScanned {len(sgs)} "
    f"security groups total."
)
```

### Explanation

- Port `22` is commonly used for SSH.
- `0.0.0.0/0` represents all IPv4 addresses.
- Exposing SSH to the entire internet increases the potential attack surface.

**Result:** Identified potentially insecure SSH access configurations in the lab environment.

The script reports findings without changing any AWS resources.

---

## 5. Security Compliance Audit

**File: `audit.py`**

This script compares AWS Security Group configurations against an existing organizational security policy.

The policy is stored in a JSON file named `gold-standard.json`.

```python
import boto3
import json
import sys

ec2 = boto3.client('ec2')
dry_run = '--dry-run' in sys.argv

with open('/home/cloud_user/lab/gold-standard.json') as f:
    policy = json.load(f)

sgs = ec2.describe_security_groups()['SecurityGroups']

print("=" * 65)
print("GOLD STANDARD COMPLIANCE AUDIT")

if dry_run:
    print("[DRY RUN MODE - no changes will be applied]")

print("=" * 65)

for p in policy['policies']:
    prefix = p['sg_name_pattern']

    matching = [
        sg for sg in sgs
        if sg['GroupName'].startswith(prefix)
    ]

    for sg in matching:
        print(
            f"\nChecking: {sg['GroupName']} "
            f"({sg['GroupId']})"
        )
        print(f"Policy: {p['name']}")

        for allowed in p['allowed_inbound']:
            found = False

            for rule in sg.get('IpPermissions', []):
                if rule.get('FromPort') == allowed['from_port']:
                    for ipr in rule.get('IpRanges', []):
                        if ipr.get('CidrIp') == allowed['cidr']:
                            found = True

            status = "COMPLIANT" if found else "MISSING"
            icon = "+" if found else "!"

            print(
                f"[{icon}] Port {allowed['from_port']} "
                f"from {allowed['cidr']} - {status}"
            )

        for rule in sg.get('IpPermissions', []):
            port = rule.get('FromPort', 'All')

            for ipr in rule.get('IpRanges', []):
                cidr = ipr.get('CidrIp', '')

                is_allowed = any(
                    a['from_port'] == port
                    and a['cidr'] == cidr
                    for a in p['allowed_inbound']
                )

                if not is_allowed:
                    print(
                        f"[x] Port {port} from {cidr} "
                        f"- NOT IN POLICY"
                    )

                    if dry_run:
                        print(
                            f"-> Would revoke: port {port} "
                            f"from {cidr} on {sg['GroupId']}"
                        )

if dry_run:
    print("\n[DRY RUN] No changes were applied.")
else:
    print(
        "\nAudit complete. Run with --dry-run "
        "to simulate remediation."
    )
```

### Explanation

The script evaluates Security Group rules against approved configurations.

Possible results:

- **COMPLIANT:** The expected rule exists.
- **MISSING:** An approved rule is absent.
- **NOT IN POLICY:** An existing rule does not match the approved policy.

The `--dry-run` option displays proposed remediation actions.

**Important:** This script does not actually revoke AWS Security Group rules, with or without `--dry-run`.

### Lab Findings

| Security Group | Finding |
|---|---|
| Web server | HTTP 80 and HTTPS 443 compliant; extra SSH rule |
| SSH management | SSH allowed from an unapproved public CIDR |
| Database server | MySQL port 3306 compliant with policy |

The audit identified configuration drift between actual AWS security settings and the approved policy.

**Note:** The JSON policy file was provided by the lab and is not included in this README. To run this script independently, an equivalent policy file must be supplied.

---

## 6. Monitoring Network Traffic with CloudWatch

**File: `metrics.py`**

Amazon CloudWatch provides metrics used to monitor AWS infrastructure.

This script retrieves network traffic statistics for running EC2 instances.

```python
import boto3
from datetime import datetime, timedelta, UTC

ec2 = boto3.client('ec2')
cw = boto3.client('cloudwatch')

def get_name(instance):
    return next(
        (t['Value'] for t in instance.get('Tags', [])
         if t['Key'] == 'Name'),
        'N/A'
    )

print("=" * 65)
print("NETWORK THROUGHPUT METRICS (Last 1 Hour)")
print("=" * 65)

reservations = ec2.describe_instances(
    Filters=[
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]
)['Reservations']

for res in reservations:
    for inst in res['Instances']:
        iid = inst['InstanceId']
        name = get_name(inst)

        for metric_name in ['NetworkIn', 'NetworkOut']:
            result = cw.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName=metric_name,
                Dimensions=[
                    {
                        'Name': 'InstanceId',
                        'Value': iid
                    }
                ],
                StartTime=datetime.now(UTC) - timedelta(hours=1),
                EndTime=datetime.now(UTC),
                Period=300,
                Statistics=['Average', 'Maximum']
            )

            dps = result.get('Datapoints', [])

            if dps:
                avg = sum(
                    d['Average'] for d in dps
                ) / len(dps)

                mx = max(
                    d['Maximum'] for d in dps
                )

                print(f"\n{name} ({iid})")
                print(
                    f"{metric_name}: "
                    f"avg={avg:,.0f} bytes "
                    f"max={mx:,.0f} bytes"
                )

                if mx > avg * 3 and avg > 0:
                    print(
                        f"*** ANOMALY: max is "
                        f"{mx/avg:.1f}x the average ***"
                    )
            else:
                print(f"\n{name} ({iid})")
                print(
                    f"{metric_name}: "
                    "No datapoints yet"
                )
```

### Explanation

The script retrieves two CloudWatch metrics:

- **NetworkIn:** Incoming network traffic.
- **NetworkOut:** Outgoing network traffic.

It compares average and maximum traffic values.

A metric is flagged when its maximum value exceeds three times its average.

### Lab Results

| Metric | Average | Maximum | Detection |
|---|---:|---:|---|
| NetworkIn | 16,000,397 bytes | 75,038,647 bytes | 4.7× average |
| NetworkOut | 62,512 bytes | 252,767 bytes | 4.0× average |

Both metrics triggered the anomaly condition.

These results indicate traffic spikes that may deserve investigation. They do not independently prove a cybersecurity incident.

---

## 7. Exporting Network Interface Data to CSV

**File: `eni_export.py`**

This script collects Elastic Network Interface (ENI) metadata and exports it to a CSV file.

```python
import boto3
import csv

ec2 = boto3.client('ec2')

print("=" * 65)
print("ENI METADATA EXPORT")
print("=" * 65)

enis = ec2.describe_network_interfaces()['NetworkInterfaces']

csv_path = '/home/cloud_user/lab/eni_report.csv'

with open(csv_path, 'w', newline='') as f:
    writer = csv.writer(f)

    writer.writerow([
        'ENI_ID',
        'Status',
        'VPC_ID',
        'Subnet_ID',
        'Private_IP',
        'Attachment_Status',
        'Description'
    ])

    for eni in enis:
        writer.writerow([
            eni['NetworkInterfaceId'],
            eni['Status'],
            eni['VpcId'],
            eni['SubnetId'],
            eni.get('PrivateIpAddress', 'N/A'),
            eni.get('Attachment', {}).get(
                'Status', 'detached'
            ),
            eni.get('Description', 'N/A')
        ])

print(
    f"\nExported {len(enis)} ENIs "
    f"to {csv_path}"
)
```

### Explanation

An ENI is a virtual network interface attached to an AWS resource.

The exported CSV includes:

- Network Interface ID
- Interface status
- VPC ID
- Subnet ID
- Private IP address
- Attachment status
- Description

**Result:** Successfully exported 2 ENIs to `eni_report.csv`.

This demonstrates how Python can automate cloud infrastructure inventory and reporting.

---

## 8. AWS Resource Quota Monitoring

**File: `quota_check.py`**

AWS applies service quotas to infrastructure resources.

This script checks resource usage against configured AWS quotas and identifies when usage reaches or exceeds 80%.

```python
import boto3

ec2 = boto3.client('ec2')
sq = boto3.client('service-quotas')

print("=" * 65)
print("RESOURCE QUOTA CHECK (80% threshold)")
print("=" * 65)

def check_quota(
    service_code,
    quota_code,
    current_count,
    resource_name
):
    try:
        response = sq.get_service_quota(
            ServiceCode=service_code,
            QuotaCode=quota_code
        )

        limit = int(response['Quota']['Value'])
        usage_pct = (current_count / limit) * 100

        if usage_pct >= 80:
            status = "ALERT"
            icon = "!"
        else:
            status = "OK"
            icon = "+"

        print(f"\n[{icon}] {resource_name}")
        print(
            f"Current: {current_count} "
            f"Limit: {limit} "
            f"Usage: {usage_pct:.1f}% "
            f"[{status}]"
        )

        if usage_pct >= 80:
            print(
                "Action required: request a quota "
                f"increase for {resource_name}"
            )

    except Exception as e:
        print(f"\n[?] {resource_name}")
        print(f"Could not retrieve quota: {e}")

vpc_count = len(ec2.describe_vpcs()['Vpcs'])

check_quota(
    'vpc',
    'L-F678F1CE',
    vpc_count,
    'VPCs per Region'
)

eni_count = len(
    ec2.describe_network_interfaces()['NetworkInterfaces']
)

check_quota(
    'vpc',
    'L-DF5E4CA3',
    eni_count,
    'Network Interfaces per Region'
)

sg_count = len(
    ec2.describe_security_groups()['SecurityGroups']
)

check_quota(
    'vpc',
    'L-E79EC296',
    sg_count,
    'Security Groups per Region'
)

print(f"\n{'=' * 65}")
print(
    "To integrate with alerting, publish "
    "these results to an SNS topic or "
    "webhook endpoint."
)
print("=" * 65)
```

### Explanation

The script uses AWS Service Quotas to retrieve resource limits.

It compares the number of resources currently in use against the applicable regional quota.

When usage reaches 80%, the script displays an alert.

### Actual Lab Results

| Resource | Current | Quota | Usage | Status |
|---|---:|---:|---:|---|
| VPCs | 2 | 5 | 40.0% | OK |
| Network Interfaces | 2 | 5,000 | 0.04% | OK |
| Security Groups | 6 | 2,500 | 0.24% | OK |

All three resource categories were below the 80% warning threshold.

---

## How to Run

These scripts were executed in a temporary Linux-based AWS lab environment.

### Requirements

- Python 3
- Boto3
- AWS credentials or an IAM role with the required read permissions
- Access to the applicable AWS services

Install Boto3 if necessary:

```bash
python3 -m pip install boto3
```

Example commands:

```bash
python3 session_test.py
python3 discover.py
python3 discover_paginated.py
python3 find_insecure.py
python3 audit.py
python3 audit.py --dry-run
python3 metrics.py
python3 eni_export.py
python3 quota_check.py
```

The scripts shown above use the lab's directory structure. Some file paths, IAM permissions, and the JSON policy must be adapted before running them in another AWS environment.

The scripts are educational examples and are not intended to be deployed unchanged as production monitoring or security controls.

## Security Considerations

- No AWS access keys or passwords are included in this repository.
- AWS authentication uses the environment's configured credentials.
- The security audit does not modify live Security Groups.
- Infrastructure identifiers and exported network metadata should be reviewed before public sharing.
- Production implementations should include stronger error handling, pagination where applicable, and comprehensive security rule evaluation.

## Skills Demonstrated

Through this project, I gained hands-on experience with:

- AWS API automation using Python and Boto3
- AWS network infrastructure discovery
- VPCs, subnets, and Internet Gateways
- API pagination
- Security Group analysis
- Security policy compliance checking
- CloudWatch network monitoring
- Basic anomaly detection
- CSV reporting
- AWS resource quota monitoring
- Linux command-line operations

## Conclusion

This project helped me understand how cloud infrastructure management can be automated using Python.

Instead of manually reviewing individual resources through the AWS Management Console, I used Boto3 to collect infrastructure information, detect security configuration issues, monitor network activity, and generate operational reports.

The project strengthened my foundational knowledge of AWS networking, cloud security, infrastructure monitoring, and automation.

**Project Type:** Guided Hands-on Lab  
**Platform:** Pluralsight  
**Focus:** AWS Networking, Cloud Automation, Security Auditing  
**Language:** Python 3

---

*Completed as part of my Cloud Computing and DevOps learning journey.*
