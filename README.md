# TrustVault

A document platform where the wrong person cannot reach a file, and where you can prove who did.
Flask + PostgreSQL (RDS) + S3, deployed on EC2 inside a VPC. Written for the TrustVault challenge.

**Live URL:** `https://<ELASTIC-IP>`  (self-signed certificate: accept the browser warning)

| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.demo | *(printed by `seed.py`; paste here)* |
| Owner | owner@trustvault.demo | *(…)* |
| Second owner | owner2@trustvault.demo | *(…)* |
| Viewer | viewer@trustvault.demo | *(…)* |

## Roles
| Role | Can do |
|---|---|
| **admin** | Create, disable and enable users. See all activity, permission changes and document **metadata**. Verify the audit chain. **Cannot read, download, edit or delete any document** unless an owner grants access (audited). |
| **owner** | Upload, search, and manage own documents. Grant and revoke read or edit to named people. Delete own documents. |
| **viewer** | Search and open only documents explicitly granted to them (read, or edit if given). Cannot upload or share. |

## Permission model (in my own words)
Per-document grants only. A document is reachable by its **owner** (level 3: read, edit, delete, share) or by a
user with an **active grant** (`read` = 1, `edit` = 2). Nothing else: no folders, no groups, no inheritance, no
admin override. Categories are labels and never grant anything. One function, `authorize()` in `app/authz.py`,
decides, using the database, on every request. A refused request returns **404** (so ids cannot be probed) and is
written to the audit trail. See `THREATS.md` for the trade-offs.

## Layout
```
app/            Flask app (authz.py = the gate, audit.py = hash chain, auth.py = sessions/CSRF/default-deny)
db/schema.sql   Tables, append-only triggers, least-privilege grants
scripts/        seed.py, anchor.py (hourly), setup_test_db.sh
tests/          Cross-user matrix, auth, uploads, audit tamper tests
deploy/         nginx, systemd service + anchor timer
```

## Deploy from a clean clone (EC2, Amazon Linux 2023)
Prerequisites (done in the AWS console): VPC, security groups, S3 buckets, IAM role on the instance, RDS,
`migrator` and `app_user` database roles, and `/etc/trustvault.env` (see variable names below).
```bash
sudo dnf install -y python3.12 python3.12-pip nginx git postgresql15
cd /opt/trustvault && git clone <YOUR-REPO-URL> .
python3.12 -m venv venv && venv/bin/pip install -r requirements.txt

# 1. schema (as migrator)
sudo bash -c 'set -a; . /etc/trustvault.env; set +a; psql "$MIGRATOR_URL" -f db/schema.sql'

# 2. seed accounts (prints each password ONCE; copy them somewhere safe)
sudo bash -c 'set -a; . /etc/trustvault.env; set +a; PYTHONDONTWRITEBYTECODE=1 venv/bin/python scripts/seed.py'

# 3. TLS certificate (self-signed; use certbot instead if you have a domain)
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=trustvault" \
  -keyout /etc/nginx/ssl/trustvault.key -out /etc/nginx/ssl/trustvault.crt

# 4. nginx + services
sudo cp deploy/nginx.conf /etc/nginx/conf.d/trustvault.conf
sudo cp deploy/trustvault_proxy.conf /etc/nginx/trustvault_proxy.conf
sudo cp deploy/trustvault.service deploy/trustvault-anchor.service deploy/trustvault-anchor.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trustvault trustvault-anchor.timer nginx
```
Then open `https://<ELASTIC-IP>/login`. Check: `curl -k https://localhost/healthz` prints `ok`.

`/etc/trustvault.env` variables: `DATABASE_URL` (app_user), `MIGRATOR_URL`, `S3_BUCKET`, `ANCHOR_BUCKET`,
`AWS_REGION`, `SECRET_KEY`. No AWS keys: the instance role supplies credentials.

## Running the tests
Tests need a Postgres database with the schema and two logins (app_user and the table owner). On the RDS setup:
```bash
RDS=<endpoint> ./scripts/setup_test_db.sh          # creates trustvault_test
export TEST_DATABASE_URL='postgresql://app_user:...@<endpoint>:5432/trustvault_test?sslmode=require'
export TEST_MIGRATOR_URL='postgresql://migrator:...@<endpoint>:5432/trustvault_test?sslmode=require'
venv/bin/pytest -v
```
Tests use a local temp folder for files, so no S3 is touched. The audit tests that simulate a database owner
editing history run inside a transaction that is rolled back.

**Mutation check:** comment out `abort(404)` in `authorize()` (or change `NEEDS["delete"]` to 1). The cross-user
tests in `tests/test_access.py` must fail. If they still pass, they are not testing anything.

## Not built (on purpose)
Folders/groups/inheritance, presigned URLs, external sharing links, antivirus, MFA, password reset, versions
and recovery UI, ownership transfer, LLM suggestions. Reasons are in `THREATS.md`.
