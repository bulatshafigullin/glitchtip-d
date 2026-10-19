module sentry_api;

// Sentry-compatible, organization/project-scoped endpoints: issue search and bulk
// edits, comments, events, tags, environments, stats, user feedback, attachments.

import vibe.vibe;
import std.json : parseJSON;
import std.conv : to, ConvException;
import std.string : strip, startsWith, join, replace;
import std.array : array;
import std.algorithm : min, max, map;
import std.base64 : Base64;
import std.datetime : Clock, UTC;
import postgrex : PgConnection;
import db;
import auth;
import search;
import ingest : storeUserReport;
import api;
import intake : invalidateKeyCache;

// ---- helpers -----------------------------------------------------------------

Json jsonBody(HTTPServerRequest req) @trusted
{
    Json j;
    try
        j = req.json;
    catch (Exception)
        fail(400, "Expected a JSON body.");
    if (j.type != Json.Type.object)
        fail(400, "Expected a JSON object.");
    return j;
}

/// Role of the caller in the organization; 404 when not a member, 403 below `minRank`.
string requireOrg(Auth a, string slug, int minRank = 1) @trusted
{
    auto role = orgRole(a, slug);
    if (role is null)
        fail(404, "Not found.");
    if (roleRank(role) < minRank)
        fail(403, "Admin role required.");
    return role;
}

/// Resolves `org/project` slugs to a project id the caller can see.
string resolveProject(Auth a, string org, string proj, out string role) @trusted
{
    auto rows = query(`select p.id::text from projects p join organizations o on o.id = p.organization_id
        where o.slug = $1 and p.slug = $2`, [org, proj]);
    if (!rows.length)
        fail(404, "Not found.");
    role = projectRole(a, rows[0][0]);
    if (role is null)
        fail(404, "Not found.");
    return rows[0][0];
}

string resolveProject(Auth a, string org, string proj) @trusted
{
    string role;
    return resolveProject(a, org, proj, role);
}

long toLong(string s, long dflt) nothrow
{
    try
        return s.to!long;
    catch (Exception)
        return dflt;
}

string flag(bool b)
{
    return b ? "true" : "false";
}

bool isUuidLike(string s)
{
    import std.ascii : isHexDigit;
    import std.algorithm : all;
    auto t = s.replace("-", "");
    return t.length == 32 && t.all!isHexDigit;
}

/// Unwraps the `[ {...} ]` produced by json_agg when exactly one row is expected.
string firstOf(string arrayJson)
{
    auto s = arrayJson.strip;
    return s.length > 2 ? s[1 .. $ - 1] : "null";
}

// ---- root --------------------------------------------------------------------

void apiRoot(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    auto a = authenticate(req);
    if (!a.ok)
        return res.sendJson(`{"version":"0","auth":null,"user":null}`);
    res.sendJson(`{"version":"0","auth":{"kind":"` ~ (a.viaSession ? "session" : "token") ~ `"},"user":` ~ queryJson(meSql, [a.userId]) ~ `}`);
}

// ---- organization --------------------------------------------------------------

void getOrg(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto role = requireOrg(a, req.params["org"]);
    res.sendJson(queryJson(`select json_build_object('name', name, 'slug', slug, 'openMembership', open_membership,
        'dateCreated', created_at, 'role', $2::text)::text from organizations where slug = $1`, [req.params["org"], role]));
}

void updateOrg(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org, 2);
    auto j = jsonBody(req);
    string name = j["name"].type == Json.Type.string ? j["name"].get!string.strip : null;
    if (j["name"].type != Json.Type.undefined && !name.length)
        fail(400, "Name must be a non-empty string.");
    string open = j["openMembership"].type == Json.Type.bool_ ? flag(j["openMembership"].get!bool) : null;
    query("update organizations set name = coalesce($2, name), open_membership = coalesce($3::boolean, open_membership) where slug = $1",
            [org, name, open]);
    getOrg(req, res, a);
}

void orgProjects(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    res.sendJson(queryJson(projectsSql("and o.slug = $5"), [flag(a.superuser), a.userId] ~ dsnParts() ~ [req.params["org"]]));
}

// ---- projects ------------------------------------------------------------------

string projectJson(Auth a, string pid) @trusted
{
    return firstOf(queryJson(projectsSql("and p.id = $5::int"), [flag(a.superuser), a.userId] ~ dsnParts() ~ [pid]));
}

void getProject(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(projectJson(a, resolveProject(a, req.params["org"], req.params["proj"])));
}

void updateProject(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    string role;
    auto pid = resolveProject(a, req.params["org"], req.params["proj"], role);
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    auto j = jsonBody(req);
    if (j["name"].type == Json.Type.string && j["name"].get!string.strip.length)
        query("update projects set name = $2 where id = $1::int", [pid, j["name"].get!string.strip]);
    if (j["platform"].type == Json.Type.string)
        query("update projects set platform = $2 where id = $1::int", [pid, j["platform"].get!string]);
    // retentionDays: integer 1..3650, or null to fall back to the server default
    auto r = j["retentionDays"];
    if (r.type == Json.Type.int_ && r.get!long >= 1 && r.get!long <= 3650)
        query("update projects set retention_days = $2::int where id = $1::int", [pid, r.get!long.to!string]);
    else if (r.type == Json.Type.null_)
        query("update projects set retention_days = null where id = $1::int", [pid]);
    else if (r.type != Json.Type.undefined)
        fail(400, "retentionDays must be an integer between 1 and 3650, or null.");
    res.sendJson(projectJson(a, pid));
}

void deleteProject(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    string role;
    auto pid = resolveProject(a, req.params["org"], req.params["proj"], role);
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    query("delete from projects where id = $1::int", [pid]);
    invalidateKeyCache();
    res.statusCode = 204;
    res.writeBody("");
}

// ---- issue search and bulk edits ---------------------------------------------------

/// FROM/WHERE for issues of an organization (optionally one project) the caller can see.
/// Filters come from `query`, `project`, `environment` request parameters.
private string issueScope(ref Q q, Auth a, HTTPServerRequest req, string org, string projSlug, bool defaultUnresolved)
{
    auto u = q.add(a.userId);
    auto s = q.add(flag(a.superuser));
    string sql = " from issues i join projects p on p.id = i.project_id join organizations o on o.id = p.organization_id"
        ~ " where o.slug = " ~ q.add(org) ~ " and " ~ accessCond(u, s);
    if (projSlug.length)
        sql ~= " and p.slug = " ~ q.add(projSlug);

    string[] pids;
    foreach (v; req.query.getAll("project"))
        if (isId(v))
            pids ~= q.add(v) ~ "::int";
    if (pids.length)
        sql ~= " and p.id in (" ~ pids.join(",") ~ ")";

    string[] envs;
    foreach (v; req.query.getAll("environment"))
        envs ~= q.add(v);
    if (envs.length)
        sql ~= " and exists (select 1 from events e where e.issue_id = i.id and e.environment in (" ~ envs.join(",") ~ "))";

    // no `query` parameter at all means the default view: unresolved issues
    bool hasQuery = req.query.getAll("query").length > 0;
    sql ~= issueFilter(q, req.query.get("query", ""), a.userId, defaultUnresolved && !hasQuery);
    return sql;
}

private void listIssuesIn(Auth a, string org, string projSlug, HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    Q q;
    auto scope_ = issueScope(q, a, req, org, projSlug, true);
    auto limit = min(max(toLong(req.query.get("limit", "25"), 25), 1), 100);
    auto offset = max(toLong(req.query.get("offset", req.query.get("cursor", "0")), 0), 0);
    res.headers["X-Hits"] = query("select count(*)::text" ~ scope_, q.args)[0][0];
    res.sendJson(queryJson(`select coalesce(json_agg(t), '[]')::text from (select ` ~ issueCols ~ scope_
        ~ ` order by ` ~ orderBy(req.query.get("sort", "date")) ~ ` limit ` ~ limit.to!string ~ ` offset ` ~ offset.to!string ~ `) t`, q.args));
}

void orgIssues(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    listIssuesIn(a, req.params["org"], null, req, res);
}

void projectIssues(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    resolveProject(a, req.params["org"], req.params["proj"]);
    listIssuesIn(a, req.params["org"], req.params["proj"], req, res);
}

/// Assignee of an issue update, constrained to members of the organization.
private string orgAssignee(Auth a, string org, Json v) @trusted
{
    if (v.type == Json.Type.null_)
        return null;
    if (v.type != Json.Type.string)
        fail(400, "assignedTo must be null, \"me\" or an email address.");
    auto who = v.get!string;
    if (who == "me")
        return a.userId;
    auto rows = query(`select u.id::text from users u join org_members m on m.user_id = u.id
        join organizations o on o.id = m.organization_id where o.slug = $1 and lower(u.email) = lower($2)`, [org, who]);
    if (!rows.length)
        fail(404, "No such member in this organization.");
    return rows[0][0];
}

/// Selection for bulk operations: explicit `id` parameters, or an explicit `query`.
private string bulkScope(ref Q q, Auth a, HTTPServerRequest req, string org, string projSlug) @trusted
{
    string[] ids;
    foreach (v; req.query.getAll("id"))
        if (isId(v) && ids.length < 1000)
            ids ~= q.add(v) ~ "::bigint";
    if (!ids.length && req.query.getAll("query").length == 0)
        fail(400, "Select issues with id=... or a query=... parameter.");
    auto sql = issueScope(q, a, req, org, projSlug, false);
    if (ids.length)
        sql ~= " and i.id in (" ~ ids.join(",") ~ ")";
    return sql;
}

/// Merges the issues into the one with the most events; their fingerprints keep
/// routing new events to the survivor.
private string mergeIssues(string scope_, string[] args) @trusted
{
    string parent;
    string[] children;
    pool().transaction((PgConnection c) @trusted {
        auto rows = query(c, `select i.id::text, i.fingerprint, i.project_id::text ` ~ scope_ ~ ` order by i.count desc, i.id for update of i`, args);
        if (rows.length < 2)
            fail(400, "Select at least two issues to merge.");
        foreach (r; rows)
            if (r[2] != rows[0][2])
                fail(400, "Only issues of the same project can be merged.");
        parent = rows[0][0];
        foreach (r; rows[1 .. $])
        {
            query(c, `insert into issue_fingerprints (project_id, fingerprint, issue_id) values ($1::int, $2, $3::bigint)
                on conflict (project_id, fingerprint) do update set issue_id = excluded.issue_id`, [r[2], r[1], parent]);
            query(c, "update issue_fingerprints set issue_id = $1::bigint where issue_id = $2::bigint", [parent, r[0]]);
            query(c, "update events set issue_id = $1::bigint where issue_id = $2::bigint", [parent, r[0]]);
            query(c, "update issue_comments set issue_id = $1::bigint where issue_id = $2::bigint", [parent, r[0]]);
            query(c, `update issues t set count = t.count + s.count, first_seen = least(t.first_seen, s.first_seen),
                last_seen = greatest(t.last_seen, s.last_seen) from issues s where t.id = $1::bigint and s.id = $2::bigint`, [parent, r[0]]);
            query(c, "delete from issues where id = $1::bigint", [r[0]]);
            children ~= r[0];
        }
    });
    return `{"merge":{"parent":"` ~ parent ~ `","children":[` ~ children.map!(x => `"` ~ x ~ `"`).join(",") ~ `]}}`;
}

private void bulkUpdateIn(Auth a, string org, string projSlug, HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    requireOrg(a, org);
    auto j = jsonBody(req);
    Q q;
    auto scope_ = bulkScope(q, a, req, org, projSlug);

    if (j["merge"].type == Json.Type.bool_ ? j["merge"].get!bool : j["merge"].type == Json.Type.int_ && j["merge"].get!long != 0)
        return res.sendJson(mergeIssues(scope_, q.args));

    string[] sets;
    string out_ = `{`;
    if (j["status"].type == Json.Type.string)
    {
        auto status = j["status"].get!string;
        if (status != "unresolved" && status != "resolved" && status != "ignored")
            fail(400, "Invalid status.");
        sets ~= "status = " ~ q.add(status);
        out_ ~= `"status":"` ~ status ~ `",`;
    }
    if (j["assignedTo"].type != Json.Type.undefined)
    {
        auto uid = orgAssignee(a, org, j["assignedTo"]);
        sets ~= uid is null ? "assigned_to = null" : "assigned_to = " ~ q.add(uid) ~ "::int";
    }
    if (!sets.length)
        fail(400, "Nothing to update.");
    auto n = query("with u as (update issues set " ~ sets.join(", ") ~ " where id in (select i.id " ~ scope_
            ~ ") returning 1) select count(*)::text from u", q.args)[0][0];
    res.sendJson(out_ ~ `"updated":` ~ n ~ `}`);
}

private void bulkDeleteIn(Auth a, string org, string projSlug, HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    requireOrg(a, org, 2);
    Q q;
    auto scope_ = bulkScope(q, a, req, org, projSlug);
    query("delete from issues where id in (select i.id " ~ scope_ ~ ")", q.args);
    res.statusCode = 204;
    res.writeBody("");
}

void orgBulkUpdate(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    bulkUpdateIn(a, req.params["org"], null, req, res);
}

void orgBulkDelete(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    bulkDeleteIn(a, req.params["org"], null, req, res);
}

void projectBulkUpdate(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    resolveProject(a, req.params["org"], req.params["proj"]);
    bulkUpdateIn(a, req.params["org"], req.params["proj"], req, res);
}

void projectBulkDelete(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    resolveProject(a, req.params["org"], req.params["proj"]);
    bulkDeleteIn(a, req.params["org"], req.params["proj"], req, res);
}

// ---- single issue extras -------------------------------------------------------------

void listComments(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', c.id, 'text', c.text,
        'dateCreated', c.created_at, 'user', (select json_build_object('id', u.id, 'email', u.email) from users u where u.id = c.user_id))
        order by c.id), '[]')::text from issue_comments c where c.issue_id = $1::bigint`, [id]));
}

void addComment(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    auto text = body_(req, "text").strip;
    if (!text.length || text.length > 10_000)
        fail(400, "Comment must be 1 to 10000 characters.");
    auto cid = query("insert into issue_comments (issue_id, user_id, text) values ($1::bigint, $2::int, $3) returning id::text",
            [id, a.userId, text])[0][0];
    res.sendJson(queryJson(`select json_build_object('id', c.id, 'text', c.text, 'dateCreated', c.created_at,
        'user', json_build_object('id', u.id, 'email', u.email))::text from issue_comments c join users u on u.id = c.user_id
        where c.id = $1::int`, [cid]), 201);
}

void deleteComment(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    auto role = issueRole(a, id);
    auto cid = req.params["comment_id"];
    if (!isId(cid))
        fail(404, "Not found.");
    // authors can delete their own comments; admins can delete any
    auto rows = query(`delete from issue_comments where id = $1::int and issue_id = $2::bigint
        and (user_id = $3::int or $4::boolean) returning 1`, [cid, id, a.userId, flag(roleRank(role) >= 2)]);
    if (!rows.length)
        fail(404, "Not found.");
    res.statusCode = 204;
    res.writeBody("");
}

void issueTags(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    res.sendJson(queryJson(`with ev as (select tags from events where issue_id = $1::bigint order by received_at desc limit 1000),
        cnt as (select key, value, count(*) c from ev, jsonb_each_text(ev.tags) group by key, value),
        ranked as (select key, value, c, sum(c) over (partition by key) tot,
                          row_number() over (partition by key order by c desc, value) rn from cnt)
        select coalesce(json_agg(json_build_object('key', key, 'name', key, 'totalValues', tot, 'topValues', tops) order by key), '[]')::text
        from (select key, max(tot) tot, json_agg(json_build_object('value', value, 'count', c) order by c desc, value) tops
              from ranked where rn <= 10 group by key) s`, [id]));
}

void latestIssueEvent(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    auto j = queryJson(`select coalesce((select row_to_json(t)::text from (
        select event_id as "eventID", issue_id::text as "issueId", received_at as "dateReceived", environment, release, tags, data
        from events where issue_id = $1::bigint order by received_at desc limit 1) t), 'null')`, [id]);
    if (j == "null")
        fail(404, "Not found.");
    res.sendJson(j);
}

// ---- project events, tags, environments -------------------------------------------------

void projectEvents(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    Q q;
    string sql = " from events e join issues i on i.id = e.issue_id where e.project_id = " ~ q.add(pid) ~ "::int";
    foreach (v; req.query.getAll("environment"))
        sql ~= " and e.environment = " ~ q.add(v);
    foreach (v; req.query.getAll("release"))
        sql ~= " and e.release = " ~ q.add(v);
    auto full = req.query.get("full", "") == "1";
    res.sendJson(queryJson(`select coalesce(json_agg(t), '[]')::text from (
        select e.event_id as "eventID", e.issue_id::text as "issueId", i.title, e.received_at as "dateReceived",
               e.environment, e.release, e.tags` ~ (full ? ", e.data" : "") ~ sql
        ~ ` order by e.received_at desc limit 100) t`, q.args));
}

void projectEvent(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    auto eid = req.params["event_id"];
    if (!isUuidLike(eid))
        fail(404, "Not found.");
    auto j = queryJson(`select coalesce((select row_to_json(t)::text from (
        select e.event_id as "eventID", e.issue_id::text as "issueId", e.received_at as "dateReceived", e.environment, e.release, e.tags, e.data,
               coalesce((select json_agg(json_build_object('id', a.id::text, 'name', a.name, 'type', a.content_type, 'size', a.size) order by a.id)
                         from event_attachments a where a.project_id = e.project_id and a.event_id = e.event_id), '[]'::json) as attachments
        from events e where e.project_id = $1::int and e.event_id = $2::uuid) t), 'null')`, [pid, eid]);
    if (j == "null")
        fail(404, "Not found.");
    res.sendJson(j);
}

void downloadAttachment(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    auto eid = req.params["event_id"];
    auto aid = req.params["attachment_id"];
    if (!isUuidLike(eid) || !isId(aid))
        fail(404, "Not found.");
    auto rows = query(`select name, encode(data, 'base64') from event_attachments
        where id = $1::bigint and project_id = $2::int and event_id = $3::uuid`, [aid, pid, eid]);
    if (!rows.length)
        fail(404, "Not found.");
    string safe;
    foreach (ch; rows[0][0])
        safe ~= (ch == '"' || ch == '\\' || ch < ' ' || ch == 127) ? '_' : ch;
    // uploaded content is untrusted: never let a browser sniff or render it
    res.headers["Content-Disposition"] = `attachment; filename="` ~ safe ~ `"`;
    res.headers["X-Content-Type-Options"] = "nosniff";
    res.writeBody(Base64.decode(rows[0][1].replace("\n", "")), "application/octet-stream");
}

void projectEnvironments(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', environment, 'name', environment) order by environment), '[]')::text
        from (select distinct environment from events where project_id = $1::int and environment is not null) s`, [pid]));
}

void projectTags(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    res.sendJson(queryJson(`with ev as (select tags from events where project_id = $1::int order by received_at desc limit 5000)
        select coalesce(json_agg(json_build_object('key', key, 'name', key, 'totalValues', n) order by key), '[]')::text
        from (select key, count(*) n from ev, jsonb_object_keys(ev.tags) key group by key) s`, [pid]));
}

void projectTagValues(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    res.sendJson(queryJson(`with ev as (select tags from events where project_id = $1::int order by received_at desc limit 5000)
        select coalesce(json_agg(json_build_object('value', v, 'count', n) order by n desc, v), '[]')::text
        from (select ev.tags ->> $2::text v, count(*) n from ev where ev.tags ? $2::text group by 1 order by 2 desc limit 100) s`,
            [pid, req.params["key"]]));
}

// ---- stats ---------------------------------------------------------------------------------

private void statsIn(Auth a, string org, string projSlug, HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    auto resolution = req.query.get("resolution", "1h");
    string unit, step;
    long stepSeconds;
    if (resolution == "1h")
    {
        unit = "hour";
        step = "1 hour";
        stepSeconds = 3600;
    }
    else if (resolution == "1d")
    {
        unit = "day";
        step = "1 day";
        stepSeconds = 86_400;
    }
    else
        fail(400, "resolution must be 1h or 1d.");
    immutable now = Clock.currTime(UTC()).toUnixTime;
    auto until = toLong(req.query.get("until", ""), now);
    auto since = toLong(req.query.get("since", ""), until - (unit == "hour" ? 86_400 : 30 * 86_400));
    since = max(since, until - 1000 * stepSeconds); // at most 1000 buckets

    Q q;
    auto u = q.add(a.userId);
    auto s = q.add(flag(a.superuser));
    auto o = q.add(org);
    auto un = q.add(unit);
    auto from = q.add(since.to!string);
    auto to_ = q.add(until.to!string);
    auto stp = q.add(step);
    string projCond = projSlug.length ? " and p.slug = " ~ q.add(projSlug) : "";
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_array(extract(epoch from b.t)::bigint, coalesce(c.n, 0)) order by b.t), '[]')::text
        from generate_series(date_trunc(` ~ un ~ `::text, to_timestamp(` ~ from ~ `::bigint)), to_timestamp(` ~ to_ ~ `::bigint), ` ~ stp ~ `::interval) as b(t)
        left join (
            select date_trunc(` ~ un ~ `::text, e.received_at) d, count(*) n
            from events e join projects p on p.id = e.project_id join organizations o on o.id = p.organization_id
            where o.slug = ` ~ o ~ ` and ` ~ accessCond(u, s) ~ projCond ~ `
              and e.received_at >= to_timestamp(` ~ from ~ `::bigint) and e.received_at <= to_timestamp(` ~ to_ ~ `::bigint)
            group by 1) c on c.d = b.t`, q.args));
}

void orgStats(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    statsIn(a, req.params["org"], null, req, res);
}

void projectStats(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    resolveProject(a, req.params["org"], req.params["proj"]);
    statsIn(a, req.params["org"], req.params["proj"], req, res);
}

// ---- user feedback -----------------------------------------------------------------------------

void listFeedback(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    res.sendJson(queryJson(`select coalesce(json_agg(t), '[]')::text from (
        select f.id, f.event_id as "eventID", f.name, f.email, f.comments, f.created_at as "dateCreated",
               (select e.issue_id::text from events e where e.project_id = f.project_id and e.event_id = f.event_id) as "issueId"
        from user_feedback f where f.project_id = $1::int order by f.created_at desc limit 100) t`, [pid]));
}

void addFeedback(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    auto j = jsonBody(req);
    storeUserReport(pid.to!int, parseJSON(j.toString));
    res.sendJson(`{"ok":true}`, 201);
}

void registerSentryRoutes(URLRouter router)
{
    router.get("/api/0/", &apiRoot);

    router.get("/api/0/organizations/:org/", authed(&getOrg));
    router.put("/api/0/organizations/:org/", authed(&updateOrg));
    router.get("/api/0/organizations/:org/projects/", authed(&orgProjects));
    router.get("/api/0/organizations/:org/issues/", authed(&orgIssues));
    router.put("/api/0/organizations/:org/issues/", authed(&orgBulkUpdate));
    router.delete_("/api/0/organizations/:org/issues/", authed(&orgBulkDelete));
    router.get("/api/0/organizations/:org/stats/", authed(&orgStats));

    router.get("/api/0/projects/:org/:proj/", authed(&getProject));
    router.put("/api/0/projects/:org/:proj/", authed(&updateProject));
    router.delete_("/api/0/projects/:org/:proj/", authed(&deleteProject));
    router.get("/api/0/projects/:org/:proj/issues/", authed(&projectIssues));
    router.put("/api/0/projects/:org/:proj/issues/", authed(&projectBulkUpdate));
    router.delete_("/api/0/projects/:org/:proj/issues/", authed(&projectBulkDelete));
    router.get("/api/0/projects/:org/:proj/events/", authed(&projectEvents));
    router.get("/api/0/projects/:org/:proj/events/:event_id/", authed(&projectEvent));
    router.get("/api/0/projects/:org/:proj/events/:event_id/attachments/:attachment_id/", authed(&downloadAttachment));
    router.get("/api/0/projects/:org/:proj/environments/", authed(&projectEnvironments));
    router.get("/api/0/projects/:org/:proj/tags/", authed(&projectTags));
    router.get("/api/0/projects/:org/:proj/tags/:key/values/", authed(&projectTagValues));
    router.get("/api/0/projects/:org/:proj/stats/", authed(&projectStats));
    router.get("/api/0/projects/:org/:proj/user-feedback/", authed(&listFeedback));
    router.post("/api/0/projects/:org/:proj/user-feedback/", authed(&addFeedback));

    router.get("/api/0/issues/:id/comments/", authed(&listComments));
    router.post("/api/0/issues/:id/comments/", authed(&addComment));
    router.delete_("/api/0/issues/:id/comments/:comment_id/", authed(&deleteComment));
    router.get("/api/0/issues/:id/tags/", authed(&issueTags));
    router.get("/api/0/issues/:id/events/latest/", authed(&latestIssueEvent));
}
