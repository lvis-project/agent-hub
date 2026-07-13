#!/bin/sh
set -eu

echo "[entrypoint] applying migrations"
node /app/dist/cli/migrate.js
echo "[entrypoint] starting Agent Hub"
exec "$@"
