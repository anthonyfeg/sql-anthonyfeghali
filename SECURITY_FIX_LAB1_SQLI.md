# Lab 1 — SQL Injection: Fix

**Course:** 503M Software Security · **Application:** Meridian Service Desk
**Vulnerability class:** SQL Injection (CWE-89)

## Where the bug was

`src/helpdesk/views/staff.py` → `advanced_ticket_search()` (endpoint
`GET /tickets/search/?q=<term>`, staff-only).

The view built the SQL statement by **string concatenation**, splicing the raw
`q` parameter straight into the query text:

```python
term = request.GET.get("q", "")
sql = (
    "SELECT id, title, submitter_email, status "
    "FROM helpdesk_ticket "
    "WHERE title LIKE '%" + term + "%' "   # <-- attacker-controlled text becomes SQL
    "ORDER BY created DESC"
)
with connection.cursor() as cursor:
    cursor.execute(sql)                    # <-- executed as one blob
```

Because `term` is placed *inside the single-quoted literal*, a `'` in the input
closes the string and everything after it is parsed as SQL. On PostgreSQL this
allowed (all confirmed against the running app as agent `rmasri`):

| Obj | Payload (`q=`) | Effect |
|----|----------------|--------|
| 1 | `zznomatch' OR id=3 -- ` | returns ticket #3 though the term matches nothing |
| 2 | `' OR 1=1 -- ` | returns every ticket |
| 3 | `zzu' UNION SELECT id, username, password, 0 FROM auth_user -- ` | dumps every staff username + PBKDF2 password hash |
| 4 | `zznomatch' OR (ascii(substr((SELECT password FROM auth_user WHERE username='admin'),{i},1))>{n}) -- ` | boolean-blind, recovers the full admin hash one character at a time |
| 5 | `%' AND CAST((SELECT pg_sleep(1.5) FROM auth_user WHERE username='admin' AND ascii(substr(password,{i},1))>{n}) AS text)='zz' -- ` | time-based blind, identical responses; answer read from response time |

## The fix

Never build SQL by concatenation. Pass the user value as a **bound parameter**
so the database driver (psycopg2) transmits it as *data*, which can never change
the parsed structure of the statement. The `LIKE` wildcards are added to the
parameter *value*, and the user's own `%`/`_` are escaped so the search still
behaves as a plain substring search.

```python
escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
pattern = f"%{escaped}%"
sql = (
    "SELECT id, title, submitter_email, status "
    "FROM helpdesk_ticket "
    "WHERE title LIKE %s ESCAPE '\\' "      # <-- placeholder, not concatenation
    "ORDER BY created DESC"
)
with connection.cursor() as cursor:
    cursor.execute(sql, [pattern])          # <-- value bound separately
```

`%s` here is psycopg2's parameter placeholder, **not** Python string formatting.
The value in the `params` list is sent to the server out-of-band and is never
interpreted as SQL.

> Equivalent idiomatic alternative (also safe): drop raw SQL entirely and use the
> Django ORM — `Ticket.objects.filter(title__icontains=term).order_by("-created")`.
> The ORM parameterizes automatically. The bound-parameter fix above was chosen to
> keep the change minimal and the before/after diff obvious.

## Scope note

Only the SQL-injection sink was changed. Other deliberately planted flaws in this
teaching build (e.g. the `mark_safe()` reflected-XSS handling in the same view)
belong to other labs and were intentionally left untouched.

## Verification

After the change, re-running every objective against the live app:

* legitimate search (`q=Invoice`) still returns the expected ticket;
* objectives 1–3 return **0 rows** ("No matches.");
* the objective-4 boolean oracle is always false (no bit leaks);
* the objective-5 payload never sleeps (≈0.02 s);
* `q=%` returns 0 rows — the wildcard is neutralised.

See the full lab report for before/after evidence.
