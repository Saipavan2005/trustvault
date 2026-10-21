# THREATS

Written as I built it. "Closed" means a test in `tests/` covers it. "Accepted" means I know and chose not to fix it.

## Access to documents
| # | Threat | What I did | Status |
|---|---|---|---|
| 1 | Guess or change a document id (IDOR) | Random UUIDs, and `authorize()` queries owner and active grant on every request. Refusals return 404, identical for missing, deleted and forbidden. | Closed (`test_stranger_is_refused…`, `test_unknown_and_forbidden_look_identical`) |
| 2 | A route that forgets the check | One gate function. All document routes call it. A test walks every route as every kind of stranger. | Closed |
| 3 | List and search leak other people's files | Filtering is inside the SQL (`owner = me OR active grant`), including wildcard-escaped search. | Closed |
| 4 | Read grant used to edit, delete or share | Per-action level table. | Closed |
| 5 | Link or session kept after access is removed | No presigned URLs; the app streams after a fresh DB check. Sessions are server-side rows. Revocation applies on the next request. | Closed (`test_revoke_is_immediate`) |
| 6 | Revoke a grant that belongs to a different document | The revoke query is bound to the document id that passed `authorize()`. | Closed |
| 7 | Admin reads everything | Admin has no implicit access and no content endpoint. Admin sees metadata only. | Closed. Accepted: admin sees names, owners and categories. |
| 8 | Mass assignment (`owner_id`, `role`) | Handlers read a fixed list of form fields. Owner always comes from the session. | Closed |
| 9 | Direct S3 access | Block Public Access, TLS-only, bucket policy denies everyone except the EC2 role, role has no delete or list. | Closed (infrastructure; verify in console) |
| 10 | Deleted file still served | `deleted_at` is checked in the gate. | Closed |

## Accounts and sessions
| # | Threat | What I did | Status |
|---|---|---|---|
| 11 | Brute force | Lockout after 5 failures (15 min), nginx rate limit on `/login`, generic error, equal timing for unknown emails. | Closed. Accepted: a lockout can be used to annoy a known user. |
| 12 | Ex-employee session still works | Disabling deletes their sessions; the gate also requires `active`. | Closed |
| 13 | Session fixation, theft | New random id at login, only a hash stored, `HttpOnly; Secure; SameSite=Lax`, 30 min idle and 8 h absolute limits. | Closed |
| 14 | CSRF | Per-session token required on every non-GET by the global gate; login uses a signed token. | Closed |
| 15 | XSS | Jinja auto-escaping, CSP with `script-src 'none'` (the app uses no JavaScript). | Closed |
| 16 | No MFA | Not built. | **Accepted**, would be first on my list |
| 17 | No password change or reset | Admin sets the initial password; users cannot change it. | **Unfinished** |

## Uploads
| # | Threat | What I did | Status |
|---|---|---|---|
| 18 | HTML or script disguised as PDF, double extensions, SVG | Extension allowlist, magic-byte check, Office files must be real zips with the right folders. | Closed |
| 19 | Path traversal in filenames | The name is display metadata only. The S3 key is a random UUID. | Closed |
| 20 | Browser runs a downloaded file | `Content-Disposition: attachment`, `application/octet-stream`, `nosniff`. | Closed |
| 21 | Oversize and empty uploads | 10 MB cap (app and nginx). | Closed. Accepted: files are held in memory, which is fine at 10 MB on two workers. |
| 22 | Malware inside an allowed file | No antivirus. | **Accepted**; ClamAV is the fix |

## Audit trail
| # | Threat | What I did | Status |
|---|---|---|---|
| 23 | App edits or deletes history | `app_user` has INSERT and SELECT only on `audit_log`, plus triggers that block UPDATE, DELETE and TRUNCATE. | Closed (`test_app_role_cannot_update…`) |
| 24 | DB owner edits history | Each row hashes the previous one. Hourly, the chain head goes to an S3 bucket with Object Lock in Compliance mode. | Mostly closed (`test_tampering…`, `test_deleted_tail…`). **Accepted:** someone with the master credentials can rewrite rows written after the last anchor, and the window is up to one hour. |
| 25 | Refused attempts missing from the record | The gate audits denials, on a separate connection so the 404 rollback cannot erase them. | Closed |
| 26 | Action succeeds but the audit write fails | Audit failure raises, the request fails, the main transaction rolls back. | Closed. Note: "allowed" is written before the action completes, so it records intent. A crash in between leaves an "allowed" row with no effect. Applied changes also write `edit_applied` and `delete_applied`. |
| 27 | A compromised app **forges** new audit rows | The chain stops edits and removals, not additions by a process that is allowed to insert. | **Accepted** |
| 28 | The anchors table could be edited by a DB owner | The hash is read from S3, so editing the table can hide an anchor but not forge one. Hiding one is a gap. | **Accepted** |
| 29 | Admins act unseen | Admin actions (viewing activity, user changes, verify) are themselves audited. Alert shows users with 5+ refusals in 10 minutes. | Closed |

## Infrastructure
| # | Threat | What I did | Status |
|---|---|---|---|
| 30 | Stolen instance credentials | Role limited to two buckets, no delete, IMDSv2 required with hop limit 1. | Closed |
| 31 | Database exposed | Private subnets, not publicly accessible, only reachable from the web security group. | Closed |
| 32 | Forged client IP in the audit log | nginx overwrites `X-Forwarded-For`; gunicorn listens on 127.0.0.1 only. | Closed |
| 33 | Self-signed certificate | Users must click through a warning. | **Accepted** for the demo; use a domain and certbot |
| 34 | Single instance, no HA, no backups beyond RDS snapshots | Free-tier cost trade-off. | **Accepted** |
| 35 | Soft delete keeps data forever; old file versions stay in S3 | The role cannot delete objects on purpose. No retention policy. | **Accepted** |
| 36 | Documents are encrypted with the bucket key, not per-owner keys | SSE-S3. | **Accepted** |
| 37 | A user who can legitimately read can copy or screenshot | Out of scope for any document system. | **Accepted** |
| 38 | Ownership of a leaver's documents | No transfer feature. | **Unfinished** |
