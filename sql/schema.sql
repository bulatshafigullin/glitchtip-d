create table if not exists projects (
    id          serial primary key,
    name        text not null,
    slug        text not null unique,
    platform    text,
    created_at  timestamptz not null default now()
);

create table if not exists project_keys (
    id          serial primary key,
    project_id  int not null references projects(id) on delete cascade,
    public_key  uuid not null unique default gen_random_uuid(),
    label       text not null default 'Default',
    is_active   boolean not null default true,
    created_at  timestamptz not null default now()
);

create table if not exists issues (
    id          bigserial primary key,
    project_id  int not null references projects(id) on delete cascade,
    fingerprint uuid not null,
    title       text not null,
    culprit     text,
    level       text not null default 'error',
    status      text not null default 'unresolved' check (status in ('unresolved','resolved','ignored')),
    count       int not null default 1,
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now(),
    unique (project_id, fingerprint)
);
create index if not exists issues_project_last_seen on issues(project_id, last_seen desc);

create table if not exists events (
    id          bigserial primary key,
    event_id    uuid not null,
    issue_id    bigint not null references issues(id) on delete cascade,
    project_id  int not null references projects(id) on delete cascade,
    data        jsonb not null,
    received_at timestamptz not null default now(),
    unique (project_id, event_id)
);
create index if not exists events_issue_received on events(issue_id, received_at desc);

create extension if not exists pgcrypto;

create table if not exists users (
    id            serial primary key,
    email         text not null,
    password_hash text not null,
    is_superuser  boolean not null default false,
    created_at    timestamptz not null default now()
);
create unique index if not exists users_email_lower on users (lower(email));

create table if not exists organizations (
    id         serial primary key,
    name       text not null,
    slug       text not null unique,
    created_at timestamptz not null default now()
);

create table if not exists org_members (
    organization_id int not null references organizations(id) on delete cascade,
    user_id         int not null references users(id) on delete cascade,
    role            text not null default 'member' check (role in ('owner','admin','member')),
    primary key (organization_id, user_id)
);

alter table projects add column if not exists organization_id int references organizations(id) on delete cascade;

-- Session and API tokens are stored as sha256 digests, never in clear text.
create table if not exists sessions (
    token_hash text primary key,
    user_id    int not null references users(id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create table if not exists api_tokens (
    id         serial primary key,
    user_id    int not null references users(id) on delete cascade,
    token_hash text not null unique,
    label      text not null,
    created_at timestamptz not null default now(),
    last_used  timestamptz
);

-- Project slugs are unique per organization, not globally.
alter table projects drop constraint if exists projects_slug_key;
create unique index if not exists projects_org_slug on projects (organization_id, slug);

-- Ingest hands events to background workers through this table.
create table if not exists ingest_queue (
    id         bigserial primary key,
    project_id int not null,
    payload    jsonb not null,
    attempts   int not null default 0,
    created_at timestamptz not null default now()
);

-- Per-project override of the global RETENTION_DAYS (null = use global).
alter table projects add column if not exists retention_days int check (retention_days is null or retention_days between 1 and 3650);
create index if not exists events_received_at on events (received_at);

-- ---- DSN keys: rate limits and allowed origins ----
alter table project_keys add column if not exists rate_limit_count  int check (rate_limit_count is null or rate_limit_count > 0);
alter table project_keys add column if not exists rate_limit_window int check (rate_limit_window is null or rate_limit_window between 1 and 86400);
alter table project_keys add column if not exists allowed_origins text[] not null default '{}';

-- ---- event metadata used for search and filters ----
alter table events add column if not exists environment text;
alter table events add column if not exists release     text;
alter table events add column if not exists tags        jsonb not null default '{}';
create index if not exists events_tags on events using gin (tags jsonb_path_ops);
create index if not exists events_project_received on events (project_id, received_at desc);

-- ---- assignment, merge aliases, comments ----
alter table issues add column if not exists assigned_to int references users(id) on delete set null;

-- A merged issue's fingerprint keeps routing new events to the surviving issue.
create table if not exists issue_fingerprints (
    project_id  int    not null references projects(id) on delete cascade,
    fingerprint uuid   not null,
    issue_id    bigint not null references issues(id) on delete cascade,
    primary key (project_id, fingerprint)
);
create index if not exists issue_fingerprints_issue on issue_fingerprints (issue_id);

create table if not exists issue_comments (
    id         serial primary key,
    issue_id   bigint not null references issues(id) on delete cascade,
    user_id    int references users(id) on delete set null,
    text       text not null,
    created_at timestamptz not null default now()
);
create index if not exists issue_comments_issue on issue_comments (issue_id);

-- ---- user feedback and attachments ----
create table if not exists user_feedback (
    id         serial primary key,
    project_id int not null references projects(id) on delete cascade,
    event_id   uuid not null,
    name       text,
    email      text,
    comments   text not null,
    created_at timestamptz not null default now()
);
create index if not exists user_feedback_project on user_feedback (project_id, created_at desc);

create table if not exists event_attachments (
    id           bigserial primary key,
    project_id   int not null references projects(id) on delete cascade,
    event_id     uuid not null,
    name         text not null,
    content_type text,
    size         int not null,
    data         bytea not null,
    created_at   timestamptz not null default now()
);
create index if not exists event_attachments_event on event_attachments (project_id, event_id);

-- ---- teams ----
alter table organizations add column if not exists open_membership boolean not null default true;

create table if not exists teams (
    id              serial primary key,
    organization_id int  not null references organizations(id) on delete cascade,
    slug            text not null,
    name            text not null,
    created_at      timestamptz not null default now(),
    unique (organization_id, slug)
);
create table if not exists team_members (
    team_id int not null references teams(id) on delete cascade,
    user_id int not null references users(id) on delete cascade,
    primary key (team_id, user_id)
);
create table if not exists project_teams (
    project_id int not null references projects(id) on delete cascade,
    team_id    int not null references teams(id) on delete cascade,
    primary key (project_id, team_id)
);

-- ---- releases ----
create table if not exists releases (
    id              serial primary key,
    organization_id int  not null references organizations(id) on delete cascade,
    version         text not null,
    ref             text,
    url             text,
    date_released   timestamptz,
    created_at      timestamptz not null default now(),
    unique (organization_id, version)
);
create table if not exists release_projects (
    release_id int not null references releases(id) on delete cascade,
    project_id int not null references projects(id) on delete cascade,
    primary key (release_id, project_id)
);
create table if not exists deploys (
    id            serial primary key,
    release_id    int  not null references releases(id) on delete cascade,
    environment   text not null,
    name          text,
    url           text,
    date_started  timestamptz,
    date_finished timestamptz not null default now()
);

-- ---- raw ingest: Postgres validates the payload and picks the event id ----
alter table ingest_queue add column if not exists event_id  uuid;
alter table ingest_queue add column if not exists client_ip text;

-- 32 hex characters (dashes optional) -> uuid, anything else -> null
create or replace function gt_valid_event_id(text) returns uuid language sql immutable as $$
    select case when replace($1, '-', '') ~ '^[0-9a-fA-F]{32}$' then replace($1, '-', '')::uuid end
$$;

-- lz4 compresses the big jsonb payloads about as well as pglz at a third less CPU. Only where the
-- server was built with it, and only once (altering the column takes a brief exclusive lock).
do $$
begin
    if exists (select 1 from pg_settings where name = 'default_toast_compression' and 'lz4' = any(enumvals)) then
        if exists (select 1 from pg_attribute where attrelid = 'events'::regclass and attname = 'data' and attcompression <> 'l') then
            alter table events alter column data set compression lz4;
        end if;
        if exists (select 1 from pg_attribute where attrelid = 'ingest_queue'::regclass and attname = 'payload' and attcompression <> 'l') then
            alter table ingest_queue alter column payload set compression lz4;
        end if;
    end if;
end $$;

-- Fingerprints are md5 digests, i.e. exactly 128 bits: stored as uuid they take 16 bytes instead of
-- 33, compare without locale collation and index smaller. Converts databases created with text columns
-- (lossless: the 32 hex digits become the uuid).
do $$
begin
    if (select data_type from information_schema.columns
        where table_schema = current_schema() and table_name = 'issues' and column_name = 'fingerprint') = 'text' then
        alter table issues alter column fingerprint type uuid using fingerprint::uuid;
    end if;
    if (select data_type from information_schema.columns
        where table_schema = current_schema() and table_name = 'issue_fingerprints' and column_name = 'fingerprint') = 'text' then
        alter table issue_fingerprints alter column fingerprint type uuid using fingerprint::uuid;
    end if;
end $$;

-- Extra project ids that resolve to a project at ingest. Lets DSNs issued under another id scheme
-- (e.g. after migrating from another Sentry-compatible server) keep working: /api/<alias>/store/.
create table if not exists project_aliases (
    alias_id   int primary key,
    project_id int not null references projects(id) on delete cascade
);
create index if not exists project_aliases_project on project_aliases (project_id);
