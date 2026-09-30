# Database Schema Migrations

VAPTForge uses SQLite `PRAGMA user_version` as a lightweight schema-version marker.

On database open:

1. VAPTForge reads the current schema version.
2. A database newer than the running application is rejected.
3. Pending migrations are applied in ascending order.
4. The schema version is advanced after each successful migration.

This makes an existing v0.5 database upgradeable without deleting assessments or findings.

Check a database with:

```bash
vaptforge db-status --db data/vaptforge.db
```

Migration definitions live in `src/vaptforge/persistence/migrations.py`. New migrations must be append-only: never rewrite the meaning of a released migration version.

Schema v3 adds durable assessment jobs, a worker lease, and job-linked scanner runs. It rebuilds the v2 scanner-run table to allow queued runs without a start timestamp, preserving older audit records. The migration and schema-version update are transactional.
