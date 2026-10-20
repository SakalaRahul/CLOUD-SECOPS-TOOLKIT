# Cloud SecOps Toolkit

[![CI](https://github.com/SakalaRahul/cloud-secops-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SakalaRahul/cloud-secops-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

A small Python toolkit that automates two everyday security and operations tasks:

1. **Dependency vulnerability scanning**: find known vulnerabilities in the packages a project depends on.
2. **AWS S3 security auditing**: find S3 buckets with weak security settings.

Both tools return a non-zero exit code when they find problems, so they can be used as a quality gate in a CI/CD pipeline.

## Features

| Tool | What it does |
|------|--------------|
| `secops/vulnscan.py` | Reads a pinned `requirements.txt`, sends one batched request to the [OSV.dev](https://osv.dev) vulnerability API, and prints a triage report listing each vulnerable package with its advisory IDs. |
| `secops/s3audit.py` | Uses `boto3` to check every S3 bucket in an AWS account for a missing public access block, missing default encryption and disabled versioning. |
| GitHub Actions CI | On every push and pull request: lints the code, runs the unit tests and scans the project's own dependencies. |

## Tech stack

Python, boto3, AWS S3, REST API (OSV.dev), unittest with mocking, GitHub Actions

## Project structure

```
cloud-secops-toolkit/
├── secops/
│   ├── vulnscan.py        # dependency vulnerability scanner
│   └── s3audit.py         # AWS S3 security audit
├── tests/
│   └── test_secops.py     # unit tests (no AWS account or network needed)
├── .github/workflows/
│   └── ci.yml             # lint + test + vulnerability scan
├── requirements.txt
└── README.md
```

## Getting started

### Prerequisites

- Python 3.10 or newer
- For the S3 audit only: an AWS account and credentials with read-only S3 access

### Installation

```bash
git clone https://github.com/SakalaRahul/cloud-secops-toolkit.git
cd cloud-secops-toolkit
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### 1. Scan dependencies for vulnerabilities

```bash
python -m secops.vulnscan requirements.txt
```

Only pinned packages (`name==version`) are checked. Example output:

```
Vulnerable dependencies:
- requests==2.19.0: <advisory IDs from OSV>
```

When nothing is found it prints `No known vulnerabilities found.` and exits with code `0`. If vulnerabilities are found, it exits with code `1`.

### 2. Audit S3 buckets

Configure AWS credentials first (for example with `aws configure`), then run:

```bash
python -m secops.s3audit
```

Example output:

```
S3 findings:
- my-bucket: no public access block configured
- my-bucket: default encryption is not enabled
- my-bucket: versioning is not enabled
```

The audit only reads bucket settings and never changes anything. It exits with code `1` if any bucket has findings.

**Checks performed**

| Check | Why it matters |
|-------|----------------|
| Public access block | Prevents buckets and objects from being exposed publicly by mistake |
| Default encryption | Ensures data is encrypted at rest |
| Versioning | Allows recovery from accidental deletes or overwrites |

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The tests mock the OSV API and the AWS S3 client, so they run without internet access or AWS credentials.

## CI/CD pipeline

The workflow in `.github/workflows/ci.yml` runs on every push to `main` and on every pull request:

1. Check out the code and set up Python 3.12
2. Install dependencies
3. Lint with `flake8`
4. Run the unit tests
5. Scan this project's own dependencies with `vulnscan`

The build fails if any step fails, including when a vulnerable dependency is found.

## Design notes

- **Batched API call:** `vulnscan` sends all packages to OSV in a single request instead of one request per package.
- **Testable by design:** the HTTP opener and the boto3 client are passed into the functions, so tests can replace them with mocks.
- **CI friendly:** both tools use exit codes so pipelines can block risky changes automatically.
- **Least privilege:** the S3 audit needs read-only permissions only.

## Possible improvements

- Add severity scoring (CVSS) to the vulnerability report
- Support more manifest formats (`pom.xml`, `package.json`)
- Add more AWS checks (security groups, IAM access keys, unencrypted EBS volumes)
- Export reports as JSON or HTML
- Run the audits on a schedule with AWS Lambda

## Author

**Rahul Sakala**
[GitHub](https://github.com/SakalaRahul) | [LinkedIn](https://linkedin.com/in/24rahul) | sakalarahul438@gmail.com
