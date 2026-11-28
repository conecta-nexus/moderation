#!/usr/bin/env bash
set -e

echo "[moderation-entrypoint] Applying Django database migrations..."
if python manage.py migrate --noinput; then
    echo "[moderation-entrypoint] Database migrations applied successfully."
else
    echo "[moderation-entrypoint] WARNING: Django migrations failed or database connection is pending. Continuing startup..."
fi

exec "$@"
