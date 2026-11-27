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
