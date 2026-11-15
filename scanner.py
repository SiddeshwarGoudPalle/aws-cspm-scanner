#!/usr/bin/env python3
"""Small read-only AWS CSPM scanner.

Checks:
  S3-001  bucket without a full public access block
  EC2-001 security group open to 0.0.0.0/0 or ::/0 on a sensitive port
  IAM-001 console user without MFA
  CT-001  no active multi-region CloudTrail trail

Usage:
  python scanner.py [--profile NAME] [--region us-east-1] [--output findings.json]
Needs read-only AWS credentials (see README for the IAM policy).
"""
import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                   1433: "MSSQL", 6379: "Redis", 27017: "MongoDB"}
PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def finding(check, severity, resource, message):
    return {"check": check, "severity": severity, "resource": resource, "message": message}


def pab_is_complete(cfg):
    """True only if all four public access block settings are enabled."""
    return bool(cfg) and all(cfg.get(k) for k in PAB_KEYS)


def sg_exposed_ports(permissions):
    """Return {port: name} of sensitive ports a rule set exposes to the internet."""
    exposed = {}
    for perm in permissions:
        open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if not (open_v4 or open_v6):
            continue
        if perm.get("IpProtocol") == "-1":
            return {0: "ALL TRAFFIC"}
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if lo is None or hi is None:
            continue
        for port, name in SENSITIVE_PORTS.items():
            if lo <= port <= hi:
                exposed[port] = name
    return exposed


def check_s3(session):
    s3 = session.client("s3")
    out = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                cfg = None
            else:
                out.append(finding("S3-001", "INFO", name, "could not read: " + str(e)))
                continue
        if not pab_is_complete(cfg):
            out.append(finding("S3-001", "HIGH", name, "public access block is missing or incomplete"))
    return out


def check_security_groups(session):
    ec2 = session.client("ec2")
    out = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for port, name in sg_exposed_ports(sg.get("IpPermissions", [])).items():
                sev = "CRITICAL" if port == 0 else "HIGH"
                out.append(finding("EC2-001", sev, sg["GroupId"],
                                   f"{sg.get('GroupName')} allows {name} from the internet"))
    return out


def check_iam_mfa(session):
    iam = session.client("iam")
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue  # no console password
                raise
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                out.append(finding("IAM-001", "HIGH", name, "console user has no MFA device"))
    return out


def check_cloudtrail(session):
    ct = session.client("cloudtrail")
    for t in ct.describe_trails()["trailList"]:
        if t.get("IsMultiRegionTrail"):
            if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                return []
    return [finding("CT-001", "HIGH", "account", "no active multi-region CloudTrail trail")]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--output", default="findings.json")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    findings = []
    for fn in (check_s3, check_security_groups, check_iam_mfa, check_cloudtrail):
        try:
            findings += fn(session)
        except ClientError as e:
            findings.append(finding("ERROR", "INFO", fn.__name__, str(e)))

    report = {"scanned_at": datetime.now(timezone.utc).isoformat(),
              "region": args.region, "count": len(findings), "findings": findings}
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    for x in findings:
        print(f"[{x['severity']}] {x['check']} {x['resource']}: {x['message']}")
    print(f"{len(findings)} finding(s) written to {args.output}")
    return 1 if any(x["severity"] in ("HIGH", "CRITICAL") for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
