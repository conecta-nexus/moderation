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
uv run pytest -k 'test_audit_log_list'
uv run pytest
uv run coverage run --source=apps.moderation --omit="*/tests/*" manage.py test
uv run coverage report -m
```

## Audit consultation

The Moderation service exposes its Django Admin for read-only audit consultation.
A user must have a native Django session and be active staff with the
`moderation.view_auditlog` permission. A Django superuser can consult audit
records. The `AuditLog` admin disallows writes for every account. Django Admin
session credentials are separate from the REST API's platform JWTs.

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
- **Health and REST API routing**:
  - `GET /` and `GET /health/` remain available at both direct paths and
    `/services/moderation/` / `/services/moderation/health/` via Nginx prefix
    stripping.
  - Gateway's `/api/v1/moderation(s)?` routes proxy *without* stripping the
    path prefix. Under a process-wide `FORCE_SCRIPT_NAME=/services/moderation`,
    Django still matches `PATH_INFO` (`/api/v1/moderation/...`), **but**
    `request.path` and `reverse()` prepend `FORCE_SCRIPT_NAME`. API pagination
    builds root-relative links from `PATH_INFO` so the login and static mount
    settings do not affect the REST API route.

## Audit log REST API

`GET /api/v1/moderation/audit-logs/` requires an Auth-issued RS256 access token
with role `ADMIN` and scope `audit:read`. Send it as `Authorization: Bearer <token>`.
Moderation checks the signature and claims even behind Gateway. A missing or
invalid token returns 401 with a Bearer challenge. A valid token without the
required role or scope returns 403. The service also supports HEAD and OPTIONS.

| Query parameter | Contract |
| --- | --- |
| `page` | Positive integer, default 1. A positive page beyond the result set returns 404. |
| `page_size` | Integer from 1 to 100, default 20. Larger values return 400. |
| `action_type` | `CHALLENGE_SUSPEND`, `USER_SUSPEND`, or `CONTENT_FLAG`. |
| `actor_id` | Exact UUID match. |
| `start_date` | UTC calendar date in `YYYY-MM-DD`. Starts at inclusive midnight. |
| `end_date` | UTC calendar date in `YYYY-MM-DD`. Includes the whole day by excluding the next midnight. The maximum end date is `9999-12-30`. |

Date bounds can be used independently. Filters combine with AND. Known invalid
parameters, including a reversed date range, return 400 with errors keyed by
field. Unknown parameters are ignored. Repeating a supported parameter returns
400 for that parameter.

The JSON response contains `count`, `next`, `previous`, and `results`. Results
are ordered by descending timestamp and descending UUID for equal timestamps.
Navigation links are root-relative and retain the submitted query. Resolve
them against the public API origin before passing them to a client that
automatically prepends `/api/v1`. An empty first page returns 200 with
`{"count":0,"next":null,"previous":null,"results":[]}`.

Each result returns `id`, `actor_id`, `actor_email`, `actor_role`, `action_type`,
`target_id`, `target_type`, `justification`, `ip_address`, and `created_at`.
The timestamp uses ISO 8601 UTC and the enum values and justification retain
their stored content.

### Local Auth public key with Docker Compose

Run these PowerShell commands from the Conecta Nexus workspace root with the
local Compose stack running. Auth's existing `auth/certs/jwt_public.pem` must
be the public key provisioned for this environment. The root `compose.yaml`
mounts the Moderation source at `/app` and reads `moderation/.env`. Add the key
as a separate read-only mount in an ignored overlay.

```powershell
$keyOverlay = '.env.local/moderation-audit-key.compose.yaml'
if (-not (Test-Path -LiteralPath 'auth/certs/jwt_public.pem' -PathType Leaf)) {
    throw 'Provision the public PEM from the trusted local Auth deployment first.'
}
New-Item -ItemType Directory -Force '.env.local' | Out-Null
git check-ignore -q -- $keyOverlay
if ($LASTEXITCODE -ne 0) { throw 'The local Compose overlay must be ignored.' }
if (Test-Path -LiteralPath $keyOverlay) {
    throw 'Inspect the existing overlay before reusing or editing it.'
}
@'
services:
  moderation:
    environment:
      JWT_PUBLIC_KEY: ""
      JWT_PUBLIC_KEY_PATH: /run/conecta-keys/jwt_public.pem
    volumes:
      - type: bind
        source: ./auth/certs/jwt_public.pem
        target: /run/conecta-keys/jwt_public.pem
        read_only: true
        bind:
          create_host_path: false
'@ | Set-Content -LiteralPath $keyOverlay -Encoding ascii
```

Use the same project name and ordered Compose files already used to launch the
stack, and append the new overlay last. The example below uses the default
project name and the root Compose file alone as its starting point. When using
an existing development override, keep it in the argument list before
`$keyOverlay`. Confirm that the Moderation service points to its intended local
database before recreating it.

```powershell
$stack = @('compose', '-f', 'compose.yaml', '-f', $keyOverlay)
docker @stack config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Invalid Compose configuration.' }
docker @stack up -d --no-deps --build moderation
if ($LASTEXITCODE -ne 0) { throw 'Moderation did not start.' }
```

The overlay selects the file through `JWT_PUBLIC_KEY_PATH` and clears any
inline key inherited from `moderation/.env` because a nonempty
`JWT_PUBLIC_KEY` takes precedence. For deployments injecting an inline PEM,
omit these overlay overrides and provide the public PEM as `JWT_PUBLIC_KEY`
in the deployment environment. The inline setting accepts PEM line breaks or
literal `\n` separators. Relative file paths resolve from `/app` in Docker.
Keep the Auth issuer and audiences unless your trusted deployment specifies
others. The defaults are `JWT_ISSUER=https://auth.conectanexus.ufps.edu.co` and
`JWT_AUDIENCES=conecta-nexus-gateway,conecta-nexus-services`. Restart Moderation
after replacing a key. An absent, invalid or unrelated key prevents JWT
authentication.

Compare the configured public key with the running Auth service through the
trusted Compose network. The check uses the effective Django settings and
prints only a public-key fingerprint. Use the configured Auth service hostname
if it differs from the root Compose service name `auth`.

```powershell
$moderationContainer = 'conecta-moderation'
@'
import hashlib
import json
import os
from urllib.request import urlopen

import django
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

def fingerprint(key):
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

if settings.JWT_PUBLIC_KEY:
    local_pem = settings.JWT_PUBLIC_KEY.replace("\\n", "\n").encode()
else:
    local_pem = (settings.BASE_DIR / settings.JWT_PUBLIC_KEY_PATH).read_bytes()
with urlopen("http://auth:8000/api/v1/auth/certs", timeout=5) as response:
    certificate = json.load(response)
if (certificate["alg"], certificate["kty"], certificate["use"]) != ("RS256", "RSA", "sig"):
    raise SystemExit("Unexpected Auth certificate metadata.")
local = fingerprint(load_pem_public_key(local_pem))
remote = fingerprint(load_pem_public_key(certificate["public_key"].encode()))
if local != remote:
    raise SystemExit("Moderation and Auth public keys differ.")
print("Matching Auth public key (SPKI SHA-256):", local)
'@ | docker exec -i $moderationContainer python -
if ($LASTEXITCODE -ne 0) { throw 'Public-key verification failed.' }
```

### Run the official pytest selector safely in Docker

This PowerShell procedure runs the official selector inside the existing
Moderation container. A distinct Compose project supplies a disposable
PostgreSQL 16 instance on the same Docker network, with no published port or
persisted data. The random ID names both the Compose service and its container,
so the disposable database does not register the shared `postgres` hostname.
Only the test process receives its connection URL and temporary uv environment.
Run it after the application container is up.

```powershell
$moderationContainer = 'conecta-moderation'
$inspect = docker inspect --format '{{json .NetworkSettings.Networks}}' $moderationContainer
if ($LASTEXITCODE -ne 0) { throw 'Moderation is not running.' }
$networks = @(($inspect | ConvertFrom-Json).PSObject.Properties.Name)
if ($networks.Count -ne 1) { throw 'Select the Compose network attached to Moderation.' }

$id = 'moderation-verify-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$verifyFile = Join-Path ([IO.Path]::GetTempPath()) ($id + '.yaml')
$venv = "/tmp/$id-venv"
$priorUrl = $env:DATABASE_URL
$dbPassword = [Guid]::NewGuid().ToString('N')
$env:MODERATION_VERIFY_DB_CONTAINER = $id
$env:MODERATION_VERIFY_DB_PASSWORD = $dbPassword
$env:MODERATION_VERIFY_NETWORK = $networks[0]
$verifyStack = @('compose', '-p', $id, '-f', $verifyFile)
$started = $false
try {
    $verifyConfig = @'
services:
  __MODERATION_VERIFY_SERVICE__:
    image: postgres:16-alpine
    container_name: ${MODERATION_VERIFY_DB_CONTAINER}
    environment:
      POSTGRES_DB: moderation_verify
      POSTGRES_PASSWORD: ${MODERATION_VERIFY_DB_PASSWORD}
    tmpfs: [/var/lib/postgresql/data]
    healthcheck:
      test: [CMD, pg_isready, -h, '127.0.0.1', -U, postgres, -d, moderation_verify]
      interval: 2s
      timeout: 2s
      retries: 20
networks:
  default:
    external: true
    name: ${MODERATION_VERIFY_NETWORK}
'@
    $verifyConfig.Replace('__MODERATION_VERIFY_SERVICE__', $id) |
        Set-Content -LiteralPath $verifyFile -Encoding ascii
    docker @verifyStack up -d --wait --wait-timeout 60
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL did not become ready.' }
    $started = $true
    $dsn = [UriBuilder]::new('postgresql', $id, 5432, 'moderation_verify')
    $dsn.UserName = 'postgres'
    $dsn.Password = $dbPassword
    $env:DATABASE_URL = $dsn.Uri.AbsoluteUri
    docker exec -e DATABASE_URL -e "UV_PROJECT_ENVIRONMENT=$venv" $moderationContainer uv run pytest -k 'test_audit_log_list'
    if ($LASTEXITCODE -ne 0) { throw 'Audit log pytest selector failed.' }
} finally {
    if ($started) {
        docker exec $moderationContainer python -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" $venv
    }
    if (Test-Path -LiteralPath $verifyFile) {
        docker @verifyStack down
        Remove-Item -LiteralPath $verifyFile
    }
    $env:DATABASE_URL = $priorUrl
    Remove-Item Env:MODERATION_VERIFY_DB_CONTAINER,Env:MODERATION_VERIFY_DB_PASSWORD,Env:MODERATION_VERIFY_NETWORK -ErrorAction SilentlyContinue
}
```

Pytest creates a test database in this disposable instance and runs the
inherited migrations, including the append-only trigger. The verification
stack cleanup removes only its own temporary container. The live Moderation
database and running service environment are separate.
