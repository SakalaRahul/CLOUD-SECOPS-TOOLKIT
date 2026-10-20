# Cloud SecOps Toolkit

Small Python automation toolkit for day-to-day security and operations tasks.

- `secops/vulnscan.py` reads a pinned `requirements.txt`, queries the
  [OSV.dev](https://osv.dev) vulnerability database in one batched call and
  prints a triage report. Exits with code 1 when vulnerabilities are found, so it
  can fail a CI pipeline.
- `secops/s3audit.py` uses boto3 to audit every S3 bucket in an AWS account for
  missing public access block, default encryption and versioning.
- `.github/workflows/ci.yml` runs lint, unit tests and the vulnerability scan on
  every push and pull request.

## Usage

```bash
pip install -r requirements.txt
python -m secops.vulnscan requirements.txt
python -m secops.s3audit          # needs AWS credentials configured
python -m unittest discover -s tests -v
```

## Tech

Python, boto3, AWS S3, REST API (OSV.dev), unittest and mocking, GitHub Actions.
