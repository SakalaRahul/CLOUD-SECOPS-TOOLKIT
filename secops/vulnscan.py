"""Dependency vulnerability scanner.

Reads a requirements.txt file, queries the OSV.dev database for known
vulnerabilities in each pinned package and prints a triage report.
Exit code is 1 when vulnerabilities are found, so it can gate a CI pipeline.
"""
import argparse
import json
import sys
import urllib.request

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def parse_requirements(text):
    """Return a list of (name, version) for pinned requirements (name==version)."""
    packages = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "==" not in line:
            continue
        name, version = line.split("==", 1)
        packages.append((name.strip().lower(), version.strip()))
    return packages


def build_query(packages):
    return {
        "queries": [
            {"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
            for n, v in packages
        ]
    }


def query_osv(packages, opener=urllib.request.urlopen):
    """Send one batched query to OSV and return the list of per-package results."""
    body = json.dumps(build_query(packages)).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with opener(req, timeout=30) as resp:
        return json.load(resp)["results"]


def triage(packages, results):
    """Combine packages with OSV results into a list of findings."""
    findings = []
    for (name, version), result in zip(packages, results):
        ids = [v["id"] for v in result.get("vulns", [])]
        if ids:
            findings.append({"package": name, "version": version, "advisories": ids})
    return findings


def render_report(findings):
    if not findings:
        return "No known vulnerabilities found."
    lines = ["Vulnerable dependencies:"]
    for f in findings:
        lines.append(
            f"- {f['package']}=={f['version']}: {', '.join(f['advisories'])}"
        )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("requirements", help="path to requirements.txt")
    args = parser.parse_args(argv)
    with open(args.requirements) as fh:
        packages = parse_requirements(fh.read())
    if not packages:
        print("No pinned packages found.")
        return 0
    findings = triage(packages, query_osv(packages))
    print(render_report(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
