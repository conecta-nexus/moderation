# Moderation

## Audit log

`apps.moderation.models.AuditLog` records an administrative action and its
justification. Pass the authenticated Auth user's UUID and email as the actor.
User and challenge UUIDs are stored without foreign keys to external services.
The actor role must be `ADMIN`, and the IP address and justification are required.

Use `AuditLog.objects.create(...)` for one audit record or plain
`bulk_create(...)` for a validated batch. These APIs allow inserts only.
Database uniqueness enforces safe behavior when two writers supply the same
UUID. Bulk conflict options are rejected. PostgreSQL also rejects update,
delete, truncate, and upserts that request an update on the audit table.

The trigger protects the history while the schema and its privileges stay in
place. Migration and infrastructure operators with rights to change the
schema or drop the database still control those objects. In production use a
separate runtime role with only the permissions it needs, such as audit-table
`INSERT` and `SELECT`, and keep DDL privileges with a migration role.

The table orders by newest timestamp and UUID. One index supports time ranges
and newest-first listing. Composite indexes support actor, action and target
type filters with time ranges, and a target UUID index supports exact lookup.
Email and justification substring searches can use a later query benchmark to
decide whether a trigram index is warranted.

## Database and verification

Set `DATABASE_URL` to a PostgreSQL connection URL. The existing Compose stack
supplies the URL for `db_moderation`. The Django settings also read an ignored
local `.env` and honor environment values first. Use PostgreSQL 16 for
integration verification.

```sh
uv sync --locked
uv run python manage.py check
uv run python manage.py makemigrations --check --dry-run
uv run python manage.py migrate
```

For tests, point `DATABASE_URL` to a disposable PostgreSQL instance and use a
database role that can create a test database. Django tests use transaction
rollback for per-case isolation. The suite tests migration reversal, so keep
it on the disposable instance. The migration can reverse an empty audit table
and will refuse reversal if audit rows exist.

```sh
uv run python manage.py test
uv run coverage run --source=apps.moderation --omit="*/tests/*" manage.py test
uv run coverage report -m
```

## Audit consultation

The Moderation service exposes its Django Admin for read-only audit consultation.
A user must have a native Django session and be active staff with the
`moderation.view_auditlog` permission. A Django superuser can consult audit
records. The `AuditLog` admin disallows writes for every account. Platform
JWT roles belong to the future REST API and are separate from Django session
credentials.

The changelist provides action and target-type filters, UTC date bounds, and
search by email, justification, or complete target UUID. The start date includes
its midnight. The end date includes the selected calendar day and excludes the
following midnight. Either date is optional. Invalid or reversed ranges display
form errors and return an empty list.

### Deployment modes

`FORCE_SCRIPT_NAME` is a process-wide Django setting, so standalone and
Gateway-mounted URL layouts require separate deployment configurations and are
not served simultaneously by the same process.

1. **Mode A — Standalone service (`/admin/`)**:
   - Leave `FORCE_SCRIPT_NAME` unset or empty (or `/` which normalizes to
     unmounted `None`).
   - Leave `CSRF_TRUSTED_ORIGINS` empty for same-origin direct access.
   - Set `ALLOWED_HOSTS` to the direct service hostnames (for example
     `localhost,127.0.0.1`).
   - Django Admin is served at `/admin/` and static assets at `/static/`.

2. **Mode B — Gateway-mounted service (`/services/moderation/admin/`)**:
   - Set `FORCE_SCRIPT_NAME=/services/moderation` (must start with a single `/`,
     without backslashes, percent-encoded characters, scheme, host, query,
     fragment, whitespace, control characters, dot segments, or `//`; a single
     trailing slash such as `/services/moderation/` is normalized to
     `/services/moderation`).
   - Set `ALLOWED_HOSTS` to the hostnames forwarded by the proxy (for example
     `localhost,127.0.0.1,moderation,gateway` in local Compose, or the Cloud Run
     service/proxy hostname in production; never `*` in production).
   - Set `CSRF_TRUSTED_ORIGINS` explicitly to valid `http://` or `https://`
     scheme-and-host origins (DNS hostnames, IPv4, or bracketed IPv6, with
     optional numeric port `1..65535`; wildcards, credentials, paths, queries,
     fragments, whitespace, control characters, and backslashes are rejected):
     - Local HTTP Gateway: `CSRF_TRUSTED_ORIGINS=http://localhost:8080` (do not
       use this development origin in production).
     - Production HTTPS Gateway: `CSRF_TRUSTED_ORIGINS=https://<gateway-host>`.

### Security, cookies, static resources, and proxy assumptions

- **Secrets, container image defaults, and HTTPS**: The Docker image does not
  override `DEBUG` or `ALLOWED_HOSTS`, so without explicit deployment
  environment variables Django defaults to `DEBUG=False`, restricted
  `ALLOWED_HOSTS` (`localhost,127.0.0.1,[::1]`), `SESSION_COOKIE_SECURE=True`,
  and `CSRF_COOKIE_SECURE=True` (HTTPS required). `SECRET_KEY` and
  `DATABASE_URL` are supplied by the deployment environment. Local HTTP development explicitly enables
  `DEBUG=True` and sets `ALLOWED_HOSTS` / `CSRF_TRUSTED_ORIGINS` only via the
  ignored local `.env` or Compose overrides.
- **Cookies**: Session and CSRF cookies use isolated names
  (`moderation_sessionid` and `moderation_csrftoken`), `HttpOnly=True` for the
  session cookie, and `SameSite=Lax`. When `FORCE_SCRIPT_NAME` is set, both
  cookie paths are scoped to `<FORCE_SCRIPT_NAME>/` (for example
  `/services/moderation/`); otherwise they default to `/`.
- **Reverse-proxy assumptions and trust boundary**:
  - The local Nginx Gateway (`location /services/moderation/`) strips
    `/services/moderation/` before proxying to Moderation and forwards
    `Host $host` without `:8080`, `X-Forwarded-Host $host`, and
    `X-Forwarded-Port $server_port` (`80`). Because `Origin: http://localhost:8080`
    includes the external port while `Host` does not, Django requires explicit
    `CSRF_TRUSTED_ORIGINS=http://localhost:8080`.
  - The Cloud Run Nginx template sets `Host $proxy_host` and overwrites
    `X-Forwarded-Proto $scheme` (which is `http` inside the Cloud Run Gateway
    container after Google Front End TLS termination).
  - Accordingly, `USE_X_FORWARDED_HOST`, `USE_X_FORWARDED_PORT`, and
    `SECURE_PROXY_SSL_HEADER` remain disabled (`False`/`None`) so Moderation
    never trusts arbitrary forwarded headers. Origin validation uses explicit
    `CSRF_TRUSTED_ORIGINS` alongside Django's CSRF middleware and token checks.
- **Static resource delivery**:
  - `STATIC_URL` is calculated from the validated `FORCE_SCRIPT_NAME`. It is
    `/static/` in standalone mode and `/services/moderation/static/` in Gateway
    mode, including when Django initializes before any request sets the
    context-local script prefix.
  - In `DEBUG=True` with `runserver`, Django's `StaticFilesHandler` inspects the
    stripped `PATH_INFO` (`/static/...`) against `settings.STATIC_URL`
    (`/services/moderation/static/`), so `config/urls.py` registers
    `staticfiles_urlpatterns("/static/")` only while `DEBUG=True`.
  - In production (`DEBUG=False`), `staticfiles_urlpatterns` is disabled and
    `DEBUG` must not be enabled to serve assets. Run
    `uv run python manage.py collectstatic --noinput` to populate `STATIC_ROOT`
    (`staticfiles/`) and serve those files at `<FORCE_SCRIPT_NAME>/static/`
    from the reverse proxy, CDN, or object storage.
- **Health and future REST API (`MODERATION-TASK-04`) routing**:
  - `GET /` and `GET /health/` remain available at both direct paths and
    `/services/moderation/` / `/services/moderation/health/` via Nginx prefix
    stripping.
  - Gateway's `/api/v1/moderation(s)?` routes proxy *without* stripping the
    path prefix. Under a process-wide `FORCE_SCRIPT_NAME=/services/moderation`,
    Django still matches `PATH_INFO` (`/api/v1/moderation/...`), **but**
    `request.path`, `reverse()`, and `request.build_absolute_uri()` (used by
    DRF pagination `next`/`previous` links) prepend `FORCE_SCRIPT_NAME` and use
    `request.get_host()`. Future `MODERATION-TASK-04` pagination should avoid
    `build_absolute_uri()` under a mounted prefix (for example, emit relative or
    page-metadata links, or deploy Admin and API on separate processes/origins).
