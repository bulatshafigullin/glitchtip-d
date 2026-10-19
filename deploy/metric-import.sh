#!/bin/bash
# One-off migration from a "Metric" server (Sentry-compatible, Postgres schema `metric`) into this app:
# organizations, users, memberships, projects and every DSN key. Events, issues and releases are NOT carried over.
#
# - Projects keep the id of their original GlitchTip DSN (the one SDKs already use); Metric's own project id
#   becomes an alias, so both /api/<old id>/ and /api/<metric id>/ resolve. All three keys per project
#   (original, migrated, default) are imported, the original one first.
# - Roles: 0 owner, 1 admin, 2+ member. Owners become instance superusers.
# - Passwords cannot be carried over (Metric stores argon2id or none): every user gets a random temporary
#   password, written to $PASSWORDS (mode 600). Users change it under Settings.
#
# Run as root on the server:  METRIC_URI=postgres://... NEW_DB=glitchtip ./metric-import.sh
set -euo pipefail
: "${METRIC_URI:?postgres URI of the Metric database}"
NEW_DB=${NEW_DB:-glitchtip}
PASSWORDS=${PASSWORDS:-/root/glitchtip-initial-passwords.txt}
NEW_PSQL=${NEW_PSQL:-sudo -u glitchtip psql}   # how to reach the new database (override for rehearsals)
new() { $NEW_PSQL -X -q -At -v ON_ERROR_STOP=1 "$NEW_DB" "$@"; }
old() { psql -X -q -At -v ON_ERROR_STOP=1 "$METRIC_URI" "$@"; }

if [ "$(new -c 'select count(*) from users')" != "0" ] && [ -z "${FORCE:-}" ]; then
  echo "target database already has users; refusing to import twice (FORCE=1 to override)" >&2; exit 1
fi

new <<'SQL'
drop schema if exists mig cascade;
create schema mig;
create table mig.users (mid bigint, email text, disabled boolean);
create table mig.orgs (mid bigint, slug text, name text);
create table mig.memberships (org_mid bigint, user_mid bigint, role int);
create table mig.projects (mid int, org_mid bigint, slug text, name text, legacy_id int, source_key text, target_key text);
create table mig.keys (project_mid int, key text, label text);
SQL
old -c "copy (select id, email, disabled_at is not null from metric.users order by id) to stdout" | new -c "copy mig.users from stdin"
old -c "copy (select id, slug, display_name from metric.organizations order by id) to stdout" | new -c "copy mig.orgs from stdin"
old -c "copy (select organization_id, user_id, role from metric.organization_memberships) to stdout" | new -c "copy mig.memberships from stdin"
old -c "copy (select p.id, p.organization_id, p.slug, p.display_name, substring(d.dsn from '/([0-9]+)\$')::int, encode(d.source_key,'hex'), encode(d.target_key,'hex')
               from metric.projects p left join metric.dsn_mappings d on d.project_id = p.id
               where p.deleted_at is null and p.state = 0 order by p.id) to stdout" | new -c "copy mig.projects from stdin"
old -c "copy (select project_id, encode(key,'hex'), label from metric.project_keys where state = 0 order by project_id, created_at) to stdout" | new -c "copy mig.keys from stdin"

new <<'SQL'
begin;
insert into users (email, password_hash, is_superuser)
  select email, '!', false from mig.users where not disabled order by mid;        -- '!' never matches: temp passwords come next
insert into organizations (name, slug) select name, slug from mig.orgs order by mid;
insert into org_members (organization_id, user_id, role)
  select o.id, u.id, case m.role when 0 then 'owner' when 1 then 'admin' else 'member' end
  from mig.memberships m
  join mig.orgs mo on mo.mid = m.org_mid join organizations o on o.slug = mo.slug
  join mig.users mu on mu.mid = m.user_mid join users u on lower(u.email) = lower(mu.email);
update users set is_superuser = true where id in (
  select u.id from mig.memberships m join mig.users mu on mu.mid = m.user_mid join users u on lower(u.email) = lower(mu.email) where m.role = 0);
insert into projects (id, name, slug, organization_id)
  select coalesce(p.legacy_id, p.mid), p.name, p.slug, o.id
  from mig.projects p join mig.orgs mo on mo.mid = p.org_mid join organizations o on o.slug = mo.slug order by p.mid;
do $$ begin perform setval('projects_id_seq', (select max(id) from projects)); end $$;
insert into project_aliases (alias_id, project_id)
  select p.mid, p.legacy_id from mig.projects p where p.legacy_id is not null and p.legacy_id <> p.mid;
-- key order matters: the first active key is the DSN the UI shows, so the original GlitchTip key goes first
insert into project_keys (project_id, public_key, label)
  select coalesce(p.legacy_id, p.mid), p.source_key::uuid, 'GlitchTip (original)' from mig.projects p where p.source_key is not null order by p.mid;
insert into project_keys (project_id, public_key, label)
  select coalesce(p.legacy_id, p.mid), k.key::uuid, k.label from mig.keys k join mig.projects p on p.mid = k.project_mid
  where k.key::uuid not in (select public_key from project_keys) order by p.mid, (k.label = 'default'), k.label;
commit;
SQL

: > "$PASSWORDS"; chmod 600 "$PASSWORDS"
for email in $(new -c "select email from users order by id"); do
  pw=$(openssl rand -hex 8)
  printf "update users set password_hash = crypt(:'pw', gen_salt('bf', 10)) where email = :'email';\n" | new -v pw="$pw" -v email="$email"
  printf '%s\t%s\n' "$email" "$pw" >> "$PASSWORDS"
done
new -c "drop schema mig cascade" >/dev/null
echo "imported: $(new -c "select count(*) from users") users, $(new -c "select count(*) from organizations") orgs, $(new -c "select count(*) from org_members") memberships, $(new -c "select count(*) from projects") projects, $(new -c "select count(*) from project_keys") keys, $(new -c "select count(*) from project_aliases") aliases"
echo "temporary passwords: $PASSWORDS"
