# PROMPTS

**This file must be YOUR record, written as you go, with real dates and commit links.** The entries below are
the format and a checklist of mistakes to look for. Replace them with what actually happened to you.
Entries that say "it was fine" score nothing.

## Entry format (need at least 5; at least 2 about authorisation, access control or the audit trail)
### YYYY-MM-DD: <short title>
- **Asked:** the prompt, or a fair summary
- **Produced:** what the tool gave you
- **Wrong:** specifically what was wrong, and how you found out (test, code reading, attack)
- **Did instead:** what you changed, with `commit <hash/link>`

## Things AI tends to get wrong here (verify each in the code, then write up the ones you really hit)
1. Checks permission on the list page but not on the download or edit route.
2. Hands out presigned S3 URLs that keep working after revocation.
3. Returns 403 for forbidden and 404 for missing, which tells an attacker which ids exist.
4. Writes the audit row after the action, or on the same transaction that a 404 rolls back, so refusals vanish.
5. Trusts a client-supplied `owner_id`, `role` or `document_id` in a request body.
6. Audit "protection" that is only an app-level rule, with no database privilege or trigger behind it.
7. Tests that only check the happy path, or that still pass when you delete an authorisation check.

## Reusable context (edit and keep what you actually used)
```
You are helping build TrustVault. Rules: the server decides access on every request through one function
(authorize). Admin has no implicit document access. Denials return 404 and are audited. No presigned URLs.
The audit table is append-only (privileges + trigger + hash chain + external anchor). Never widen access
automatically: suggestions are shown, a person confirms, both are audited. Write a test for every rule.
```
