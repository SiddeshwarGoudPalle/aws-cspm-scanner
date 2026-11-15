# aws-cspm-scanner

A small, read-only AWS cloud security posture (CSPM) scanner written in Python with boto3. It checks a handful of common misconfigurations and writes the findings to JSON.

## Checks

| ID | What it flags |
|----|---------------|
| S3-001 | S3 bucket without a full public access block |
| EC2-001 | Security group open to 0.0.0.0/0 or ::/0 on SSH, RDP, MySQL, PostgreSQL, MSSQL, Redis, MongoDB (or all traffic) |
| IAM-001 | IAM user with console access and no MFA device |
| CT-001 | No active multi-region CloudTrail trail |

## Run

```bash
pip install -r requirements.txt
python scanner.py --profile myprofile --region us-east-1 --output findings.json
python test_scanner.py   # unit tests for the rule logic, no AWS needed
```

Exit code is 1 when any HIGH or CRITICAL finding exists, so it can gate a CI job.

## Permissions

Read-only is enough: `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `ec2:DescribeSecurityGroups`, `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`. The AWS managed `SecurityAudit` policy also covers these.

## Notes

- `sample_output.txt` shows the output format with made-up names.
- Scope is deliberately small. For full coverage use a CNAPP/CSPM platform such as Wiz, Prowler or ScoutSuite.
