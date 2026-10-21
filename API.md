# API: who may call what

Browser-form app. Every endpoint except the three public ones needs a valid session (else redirect to `/login`).
Every non-GET also needs the session's CSRF token. "Document access" is decided by `authorize()` on every call.
A refused document request returns **404** and is audited.

| Method and path | Who is allowed | Notes |
|---|---|---|
| `GET /login`, `POST /login` | Anyone | Signed login token, lockout after 5 failures |
| `GET /healthz` | Anyone | Returns `ok` |
| `GET /static/*` | Anyone | CSS only |
| `POST /logout` | Any signed-in user | Deletes the session |
| `GET /documents` | Any signed-in user | Only own and actively granted documents. Filters: `q`, `owner`, `category`, `from`, `to` |
| `POST /documents` | role `owner` | Upload, validated. Others get 404 |
| `GET /documents/<id>` | Document owner, or a grant (read or edit) | Owner also sees grants and suggestions |
| `GET /documents/<id>/download` | Document owner, or a grant (read or edit) | Streamed via the app, never a presigned URL |
| `POST /documents/<id>/edit` | Document owner, or an **edit** grant | Name, category, replace file |
| `POST /documents/<id>/delete` | Document owner only | Soft delete |
| `POST /documents/<id>/grants` | Document owner only | Grant `read` or `edit` to an active user |
| `POST /documents/<id>/grants/<gid>/revoke` | Document owner only | Grant must belong to this document |
| `GET /admin/users`, `POST /admin/users` | role `admin` | Create users |
| `POST /admin/users/<id>/disable`, `/enable` | role `admin` | Disable ends sessions at once |
| `GET /admin/activity`, `/admin/permissions` | role `admin` | Audit views, `outcome` filter, `page` |
| `GET /admin/documents` | role `admin` | Metadata only |
| `POST /admin/verify` | role `admin` | Recomputes the hash chain and checks S3 anchors |
