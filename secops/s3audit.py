"""AWS S3 security audit.

Checks every bucket in the account for: public access block, default
encryption and versioning, and prints a list of findings.
Requires AWS credentials (boto3 default credential chain).
"""
import argparse
import sys

from botocore.exceptions import ClientError


def audit_bucket(s3, name):
    """Return a list of finding strings for one bucket."""
    findings = []

    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if not all(cfg.values()):
            findings.append("public access block is only partially enabled")
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append("no public access block configured")
        else:
            raise

    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append("default encryption is not enabled")
        else:
            raise

    if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
        findings.append("versioning is not enabled")

    return findings


def audit_all(s3):
    report = {}
    for bucket in s3.list_buckets()["Buckets"]:
        issues = audit_bucket(s3, bucket["Name"])
        if issues:
            report[bucket["Name"]] = issues
    return report


def render_report(report):
    if not report:
        return "All buckets passed the audit."
    lines = ["S3 findings:"]
    for bucket, issues in sorted(report.items()):
        for issue in issues:
            lines.append(f"- {bucket}: {issue}")
    return "\n".join(lines)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    import boto3  # imported here so the module can be tested without AWS set up

    report = audit_all(boto3.client("s3"))
    print(render_report(report))
    return 1 if report else 0


if __name__ == "__main__":
    sys.exit(main())
