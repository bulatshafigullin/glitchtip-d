# glitchtip-d

GlitchTip-style error tracking in D (vibe.d + PostgreSQL). Sentry SDK compatible ingestion, web UI at `/`.

    dub build --compiler=ldc2
    ./glitchtip-d

The first account to register becomes superuser; further sign-ups need `ENABLE_REGISTRATION=true`
(or an admin adds members to an organization after they register).

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://$USER@/glitchtip_d?host=/tmp` | Postgres URL via [postgrex-d](https://github.com/bulatshafigullin/postgrex-d) (no libpq); unix socket dir in `host=`, or use `postgres://user@host:5432/db` for TCP |
| `PORT` | `8000` | HTTP port |
| `PUBLIC_URL` | `http://localhost:$PORT` | host used in DSNs; `https://` makes cookies `Secure` |
| `BIND_ADDRESS` | `0.0.0.0` | interface to listen on; use `127.0.0.1` behind a reverse proxy |
| `TRUST_PROXY` | `false` | believe `X-Real-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` from the proxy (client IP, `Secure` cookies). Only enable when the app port is not reachable except through the proxy |
| `KEY_CACHE_SECONDS` | `30` | how long ingest caches DSN key lookups (0 disables) |
| `GC_STATS_INTERVAL` | `0` | log garbage-collector activity (collections, pause totals, heap) every N seconds |
| `ENABLE_REGISTRATION` | `false` | allow open sign-up after the first user |
| `WORKERS` | `2` | background threads draining the ingest queue |
| `MAX_ATTACHMENT_BYTES` | `1048576` | larger envelope attachments are dropped (stored in Postgres) |
| `RETENTION_DAYS` | `90` | default event retention (per-project override in the UI/API) |
| `CLEANUP_INTERVAL_MINUTES` | `60` | how often retention cleanup runs |

## Compatibility notes

- **Ingest:** `store` and `envelope` with CORS, per-key rate limits (`429` + `Retry-After`; counters live in
  process memory, so they are per server instance) and allowed origins. Envelope items `event`, `user_report`
  and `attachment` are stored; `session`, `transaction`, `client_report`, `check_in` and others are accepted and
  dropped. Not implemented: legacy base64 `store` bodies, `/security/`, `/minidump/`, OTLP.
- **Grouping:** exception type + in-app stack (module/function, no line numbers, bundle hashes stripped), message
  templates, custom `fingerprint` with `{{ default }}`. Issues can be merged; merged fingerprints keep routing.
- **API:** Sentry-style `/api/0/organizations/:org/...`, `/projects/:org/:project/...`, `/teams/:org/:team/...`
  (issues with search query language, bulk update/merge/delete, comments, events, tags, environments, stats,
  releases and deploys, DSN keys, teams, user feedback, attachments). Not implemented: source maps, debug files.
- **Access:** with `openMembership` (default) every org member sees every project; turn it off and members only see
  projects assigned to one of their teams. Owners/admins always see everything.
- **Tests:** `tests/api_smoke.py` needs a fresh database and `ENABLE_REGISTRATION=true`.

## Deployment behind nginx

Build and install steps (Docker and bare metal): see [DEPLOY.md](DEPLOY.md).

See `deploy/nginx.conf`. Run the app with `TRUST_PROXY=true BIND_ADDRESS=127.0.0.1 PUBLIC_URL=https://your.host`.
nginx must set `X-Real-IP $remote_addr` (overwriting, not appending) and `X-Forwarded-Proto $scheme`, keep
`client_max_body_size` at the app's 20 MiB limit, and must not add CORS headers (the app answers ingest preflights).
SDK events with `user.ip_address: "{{auto}}"` get the client address stored.

## Ingest pipeline and memory

Events are not parsed on the HTTP thread: the raw payload goes into `ingest_queue` (Postgres validates the JSON
and picks the event id). Workers claim batches of 50 with `FOR UPDATE SKIP LOCKED` and read only a small projection
of each event (type, frames, message, tags: cut out in SQL by `projectionSql` in `source/worker.d`). If you change
what `derive`/`extractMeta` read, update `projectionSql` too.

A batch is stored in a fixed number of statements (`storeEvents` in `source/ingest.d`): duplicates are dropped,
events are grouped by fingerprint, each distinct issue is upserted once (`count += n`) in a fixed
(project, fingerprint) order, and the full payloads are copied from the queue rows inside Postgres. That fixed order is
what keeps concurrent workers from deadlocking on hot issues; do not reorder those statements. Lock conflicts retry
without counting against an event; any other batch failure is retried row by row, and a row that still fails is
dropped after 5 attempts. `events.data` and `ingest_queue.payload` use lz4 compression when the server has it.
Compressed request bodies are inflated in chunks and rejected above 20 MiB (413). DSN keys are cached for
`KEY_CACHE_SECONDS` (default 30) on the HTTP thread; changes made through this instance apply immediately,
other instances after the TTL.

    dub build -c bench --compiler=ldc2 -b release && ./glitchtip-bench      # bytes allocated per pipeline step
    python3 tests/load.py 3000 8                                             # end-to-end load (fresh DB, registration on)
    WORKERS=4 ... ; python3 tests/pipeline_test.py                           # batching, dedupe, merge, poison-row checks
    GC_STATS_INTERVAL=5 ./glitchtip-d                                        # collector activity in the log

## Running on Debian with systemd

    deploy/Dockerfile.build      builds the binary inside Debian 13 so it matches the host's libc/OpenSSL
    deploy/glitchtip.service     hardened systemd unit (runs as the `glitchtip` user, loopback only)
    deploy/env.example           /etc/glitchtip/env
    deploy/nginx.conf            reverse proxy

The service connects to the local Postgres over the unix socket with peer authentication: create an OS user and a
database role with the same name (`useradd --system glitchtip`; `createuser glitchtip`; `createdb -O glitchtip glitchtip`),
no password and no `pg_hba.conf` change. Build: `docker build -f deploy/Dockerfile.build --target out --output type=local,dest=out .`.

Passwords can be reset in SQL: `update users set password_hash = crypt('new password', gen_salt('bf', 10)) where email = '...';`
Users change their own under Settings.

### Migrating from Metric (`deploy/metric-import.sh`)

Carries over organizations, users, memberships, projects and every DSN key; events, issues and releases are not imported.
Each project keeps the id of its original GlitchTip DSN and Metric's own project id becomes an alias (`project_aliases`),
so `/api/<either id>/store/` works with any of the project's keys. Users get random temporary passwords
(`/root/glitchtip-initial-passwords.txt`, mode 600). Rollback: point nginx back at the old upstream and start the old container.
