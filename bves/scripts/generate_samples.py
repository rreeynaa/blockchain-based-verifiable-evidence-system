"""Generate deterministic simulated AWS CloudTrail intrusion logs into ./samples."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
T0 = datetime(2026, 3, 14, 2, 11, 0, tzinfo=timezone.utc)
ACCT = "123456789012"


def rec(n: int, name: str, source: str, ident: dict, ip: str, **extra) -> dict:
    """Build one CloudTrail record."""
    base = {
        "eventVersion": "1.08",
        "userIdentity": ident,
        "eventTime": (T0 + timedelta(seconds=37 * n)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11 Linux/6.1",
        "requestID": f"req-{n:04d}-{100000 + n}",
        "eventID": f"00000000-0000-4000-8000-{n:012d}",
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCT,
    }
    base.update(extra)
    return base


def iam(user: str) -> dict:
    return {"type": "IAMUser", "userName": user, "accountId": ACCT,
            "arn": f"arn:aws:iam::{ACCT}:user/{user}", "principalId": f"AIDA{user.upper()[:8]:0<8}EXAMPLE"}


ROOT = {"type": "Root", "accountId": ACCT, "arn": f"arn:aws:iam::{ACCT}:root", "principalId": ACCT}


def failed_logins() -> list[dict]:
    ip = "203.0.113.45"
    return [
        rec(i, "ConsoleLogin", "signin.amazonaws.com", iam("admin-backup"), ip,
            eventType="AwsConsoleSignIn",
            responseElements={"ConsoleLogin": "Failure"},
            errorMessage="Failed authentication",
            additionalEventData={"MFAUsed": "No", "LoginTo": "https://console.aws.amazon.com/"})
        for i in range(6)
    ]


def priv_esc() -> list[dict]:
    ip, me = "198.51.100.23", iam("dev-intern")
    return [
        rec(0, "CreateAccessKey", "iam.amazonaws.com", me, ip,
            requestParameters={"userName": "dev-intern"},
            responseElements={"accessKey": {"accessKeyId": "AKIAEXAMPLEKEY0001", "status": "Active"}}),
        rec(1, "AttachUserPolicy", "iam.amazonaws.com", me, ip,
            requestParameters={"userName": "dev-intern",
                               "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        rec(2, "PutUserPolicy", "iam.amazonaws.com", me, ip,
            requestParameters={"userName": "dev-intern", "policyName": "inline-admin",
                               "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}),
        rec(3, "UpdateAssumeRolePolicy", "iam.amazonaws.com", me, ip,
            requestParameters={"roleName": "OrganizationAccountAccessRole"}),
    ]


def s3_exfil() -> list[dict]:
    ip, me = "192.0.2.77", iam("svc-reporting")
    out = [rec(0, "ListBuckets", "s3.amazonaws.com", me, ip)]
    for i in range(1, 6):
        out.append(rec(i, "GetObject", "s3.amazonaws.com", me, ip,
                       requestParameters={"bucketName": "prod-customer-data",
                                          "key": f"exports/customers-part-{i:03d}.csv"},
                       additionalEventData={"bytesTransferredOut": 524288000 + i * 1000}))
    out.append(rec(6, "PutBucketPolicy", "s3.amazonaws.com", me, ip,
                   requestParameters={"bucketName": "prod-customer-data",
                                      "policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'}))
    return out


def root_usage() -> list[dict]:
    ip = "45.155.205.10"
    return [
        rec(0, "ConsoleLogin", "signin.amazonaws.com", ROOT, ip, eventType="AwsConsoleSignIn",
            responseElements={"ConsoleLogin": "Success"},
            additionalEventData={"MFAUsed": "No", "LoginTo": "https://console.aws.amazon.com/"}),
        rec(1, "CreateUser", "iam.amazonaws.com", ROOT, ip, requestParameters={"userName": "backdoor-user"}),
        rec(2, "StopLogging", "cloudtrail.amazonaws.com", ROOT, ip,
            requestParameters={"name": f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/management-events"}),
        rec(3, "DeleteTrail", "cloudtrail.amazonaws.com", ROOT, ip,
            requestParameters={"name": "management-events"}),
    ]


def main() -> None:
    """Write the four sample files."""
    OUT.mkdir(exist_ok=True)
    for name, fn in {
        "failed_console_logins.json": failed_logins,
        "privilege_escalation.json": priv_esc,
        "s3_exfiltration.json": s3_exfil,
        "root_account_usage.json": root_usage,
    }.items():
        (OUT / name).write_text(json.dumps({"Records": fn()}, indent=2, sort_keys=True) + "\n")
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
