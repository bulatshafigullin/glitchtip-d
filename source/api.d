module api;

import vibe.vibe;
import std.conv : to;
import std.regex : replaceAll, regex;
import std.string : toLower, strip, startsWith, indexOf, lastIndexOf;
import std.uuid : randomUUID;
import db;
import auth;
import search;

string publicUrl;
bool secureCookies;
bool trustProxy; // TRUST_PROXY: believe X-Forwarded-Proto / X-Real-IP / X-Forwarded-For from the reverse proxy
bool registrationOpen;

alias Handler = void function(HTTPServerRequest, HTTPServerResponse, Auth) @trusted;

void sendJson(HTTPServerResponse res, string json, int status = 200) @trusted
{
    res.statusCode = status;
    res.writeBody(json, "application/json");
}

void fail(int status, string detail)
{
    throw new HTTPStatusException(status, detail);
}

/// True when the client reached us over HTTPS: PUBLIC_URL says so, or the connection is TLS,
/// or (only with TRUST_PROXY) the proxy says so. Controls the `Secure` cookie flag.
bool isSecure(HTTPServerRequest req) @trusted
{
    return secureCookies || req.tls || (trustProxy && req.headers.get("X-Forwarded-Proto", "") == "https");
}

private bool ipLike(string s)
{
    import std.ascii : isHexDigit;
    if (s.length == 0 || s.length > 45)
        return false;
    foreach (ch; s)
        if (!(isHexDigit(ch) || ch == '.' || ch == ':'))
            return false;
    return true;
}

/// The client's address. Behind a trusted proxy that is `X-Real-IP` (nginx sets it from
/// `$remote_addr`, so clients cannot forge it) or else the last `X-Forwarded-For` entry,
/// the one the proxy itself appended. Without TRUST_PROXY the headers are ignored.
string clientIp(HTTPServerRequest req) @trusted
{
    if (trustProxy)
    {
        auto real_ = req.headers.get("X-Real-IP", "").strip;
        if (ipLike(real_))
            return real_;
        auto xff = req.headers.get("X-Forwarded-For", "");
        auto comma = xff.lastIndexOf(',');
        auto last = (comma >= 0 ? xff[comma + 1 .. $] : xff).strip;
        if (ipLike(last))
            return last;
    }
    // (`req.peer` includes the port, the address alone does not)
    auto addr = req.clientAddress.toAddressString();
    if (addr.startsWith("::ffff:") && addr[7 .. $].indexOf(':') < 0)
        addr = addr[7 .. $];
    return ipLike(addr) ? addr : null;
}

/// Wraps a handler with authentication and CSRF protection.
HTTPServerRequestDelegate authed(Handler h)
{
    return (HTTPServerRequest req, HTTPServerResponse res) @trusted {
        auto a = authenticate(req);
        if (!a.ok)
            fail(401, "Authentication credentials were not provided.");
        if (a.viaSession && !csrfOk(req))
            fail(403, "Missing X-Requested-With header.");
        h(req, res, a);
    };
}

string body_(HTTPServerRequest req, string key, bool required = true) @trusted
{
    Json j;
    try
        j = req.json;
    catch (Exception)
        fail(400, "Expected a JSON body.");
    if (j.type != Json.Type.object || j[key].type != Json.Type.string)
    {
        if (required)
            fail(400, "Field '" ~ key ~ "' is required.");
        return null;
    }
    return j[key].get!string;
}

string slugify(string s)
{
    auto r = s.toLower.replaceAll(regex("[^a-z0-9]+"), "-").strip("-");
    return r.length ? r : "org";
}

/// Returns a unique organization slug derived from the name.
string uniqueOrgSlug(string name) @trusted
{
    auto base = slugify(name);
    auto slug = base;
    while (query("select 1 from organizations where slug = $1", [slug]).length)
        slug = base ~ "-" ~ newToken()[0 .. 4];
    return slug;
}

string createOrg(string name, string ownerId) @trusted
{
    auto slug = uniqueOrgSlug(name);
    auto id = query("insert into organizations (name, slug) values ($1, $2) returning id::text", [name, slug])[0][0];
    query("insert into org_members (organization_id, user_id, role) values ($1::int, $2::int, 'owner')", [id, ownerId]);
    return slug;
}

// ---- auth ------------------------------------------------------------------

enum meSql = `select json_build_object(
    'id', u.id, 'email', u.email, 'isSuperuser', u.is_superuser,
    'organizations', coalesce((select json_agg(json_build_object('name', o.name, 'slug', o.slug, 'role', m.role) order by o.id)
        from org_members m join organizations o on o.id = m.organization_id where m.user_id = u.id), '[]'::json))::text
    from users u where u.id = $1::int`;

void register(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    if (!csrfOk(req))
        fail(403, "Missing X-Requested-With header.");
    auto email = body_(req, "email").strip;
    auto password = body_(req, "password");
    if (email.indexOf('@') < 1 || email.length > 254)
        fail(400, "A valid email is required.");
    if (password.length < 8)
        fail(400, "Password must be at least 8 characters.");

    auto first = query("select count(*) = 0 from users")[0][0] == "t";
    if (!first && !registrationOpen)
        fail(403, "Registration is closed.");
    if (query("select 1 from users where lower(email) = lower($1)", [email]).length)
        fail(409, "Email already registered.");

    auto uid = query(`insert into users (email, password_hash, is_superuser)
        values ($1, crypt($2, gen_salt('bf', 10)), $3::boolean) returning id::text`,
            [email, password, first ? "true" : "false"])[0][0];
    auto slug = createOrg(email[0 .. email.indexOf('@')] ~ "'s org", uid);
    if (first) // adopt projects created before accounts existed
        query("update projects set organization_id = (select id from organizations where slug = $1) where organization_id is null", [slug]);
    startSession(res, uid, isSecure(req));
    res.sendJson(queryJson(meSql, [uid]), 201);
}

void login(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    if (!csrfOk(req))
        fail(403, "Missing X-Requested-With header.");
    auto rows = query("select id::text from users where lower(email) = lower($1) and password_hash = crypt($2, password_hash)",
            [body_(req, "email").strip, body_(req, "password")]);
    if (!rows.length)
        fail(401, "Invalid email or password.");
    startSession(res, rows[0][0], isSecure(req));
    res.sendJson(queryJson(meSql, [rows[0][0]]));
}

void logout(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    if (!csrfOk(req))
        fail(403, "Missing X-Requested-With header.");
    if (auto tok = sessionCookie in req.cookies)
        query("delete from sessions where token_hash = encode(digest($1, 'sha256'), 'hex')", [*tok]);
    res.setCookie(sessionCookie, "", "/").maxAge = 0;
    res.sendJson(`{"ok":true}`);
}

/// Changes the caller's password (current one required) and signs out every other session.
void changePassword(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto current = body_(req, "currentPassword");
    auto next = body_(req, "newPassword");
    if (next.length < 8)
        fail(400, "Password must be at least 8 characters.");
    if (!query("select 1 from users where id = $1::int and password_hash = crypt($2, password_hash)", [a.userId, current]).length)
        fail(403, "Current password is incorrect.");
    query("update users set password_hash = crypt($2, gen_salt('bf', 10)) where id = $1::int", [a.userId, next]);
    string keep = null;
    if (auto tok = sessionCookie in req.cookies)
        keep = *tok;
    query("delete from sessions where user_id = $1::int and ($2::text is null or token_hash <> encode(digest($2, 'sha256'), 'hex'))", [a.userId, keep]);
    res.sendJson(`{"ok":true}`);
}

void me(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(queryJson(meSql, [a.userId]));
}

// ---- organizations -----------------------------------------------------------

void listOrgs(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('name', o.name, 'slug', o.slug,
        'role', coalesce(m.role, 'owner')) order by o.id), '[]')::text
        from organizations o left join org_members m on m.organization_id = o.id and m.user_id = $1::int
        where $2::boolean or m.user_id is not null`, [a.userId, a.superuser ? "true" : "false"]));
}

void createOrganization(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto name = body_(req, "name").strip;
    if (!name.length)
        fail(400, "Name is required.");
    auto slug = createOrg(name, a.userId);
    res.sendJson(`{"slug":"` ~ slug ~ `"}`, 201);
}

void listMembers(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto slug = req.params["slug"];
    if (orgRole(a, slug) is null)
        fail(404, "Not found.");
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', u.id, 'email', u.email, 'role', m.role) order by u.id), '[]')::text
        from org_members m join users u on u.id = m.user_id join organizations o on o.id = m.organization_id
        where o.slug = $1`, [slug]));
}

void addMember(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto slug = req.params["slug"];
    auto role = orgRole(a, slug);
    if (role is null)
        fail(404, "Not found.");
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    auto newRole = body_(req, "role", false);
    if (newRole is null)
        newRole = "member";
    if (roleRank(newRole) == 0 || (newRole == "owner" && role != "owner"))
        fail(400, "Invalid role.");
    auto rows = query(`insert into org_members (organization_id, user_id, role)
        select o.id, u.id, $3 from organizations o, users u where o.slug = $1 and lower(u.email) = lower($2)
        on conflict (organization_id, user_id) do update set role = excluded.role returning user_id::text`,
            [slug, body_(req, "email").strip, newRole]);
    if (!rows.length)
        fail(404, "No user with that email. They must register first.");
    res.sendJson(`{"ok":true}`);
}

// ---- projects ----------------------------------------------------------------

string projectsSql(string where_)
{
    return `select coalesce(json_agg(t order by t.id), '[]')::text from (
        select p.id, p.name, p.slug, p.platform, p.retention_days as "retentionDays", o.slug as organization,
            p.created_at as "dateCreated",
            (select $3 || '://' || replace(k.public_key::text, '-', '') || '@' || $4 || '/' || p.id from project_keys k
             where k.project_id = p.id and k.is_active order by k.id limit 1) as dsn,
            (select count(*) from issues i where i.project_id = p.id and i.status = 'unresolved') as "unresolvedCount",
            coalesce((select json_agg(json_build_object('slug', t.slug, 'name', t.name) order by t.id)
                      from project_teams pt join teams t on t.id = pt.team_id where pt.project_id = p.id), '[]'::json) as teams
        from projects p join organizations o on o.id = p.organization_id
        where ` ~ accessCond("$2", "$1") ~ `
        ` ~ where_ ~ `) t`;
}

string[] dsnParts()
{
    return [publicUrl.startsWith("https") ? "https" : "http", publicUrl.replaceAll(regex("^https?://"), "")];
}

void listProjects(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(queryJson(projectsSql(""), [a.superuser ? "true" : "false", a.userId] ~ dsnParts()));
}

/// Creates a project with a default DSN key in the organization; returns its id.
string createProjectIn(string orgSlug, string name, string platform) @trusted
{
    auto slug = slugify(name);
    while (query("select 1 from projects p join organizations o on o.id = p.organization_id where o.slug = $1 and p.slug = $2",
            [orgSlug, slug]).length)
        slug = slugify(name) ~ "-" ~ newToken()[0 .. 4];
    auto id = query(`insert into projects (name, slug, platform, organization_id)
        select $1, $2, $3, id from organizations where slug = $4 returning id::text`,
            [name, slug, platform, orgSlug])[0][0];
    query("insert into project_keys (project_id) values ($1::int)", [id]);
    return id;
}

void createProject(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto name = body_(req, "name").strip;
    auto orgSlug = body_(req, "organization");
    auto platform = body_(req, "platform", false);
    auto role = orgRole(a, orgSlug);
    if (role is null)
        fail(404, "Organization not found.");
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    if (!name.length)
        fail(400, "Name is required.");
    auto id = createProjectIn(orgSlug, name, platform);
    auto list = queryJson(projectsSql("and p.id = $5::int"), [a.superuser ? "true" : "false", a.userId] ~ dsnParts() ~ [id]).strip;
    res.sendJson(list[1 .. $ - 1], 201); // single-element array -> object
}

// ---- issues & events ---------------------------------------------------------

/// Looks up the issue's project and the caller's role in it; 404s on no access.
string issueRole(Auth a, string issueId) @trusted
{
    auto pid = isId(issueId) ? issueProject(issueId) : null;
    auto role = pid is null ? null : projectRole(a, pid);
    if (role is null)
        fail(404, "Not found.");
    return role;
}

void getIssue(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    res.sendJson(queryJson(`select row_to_json(t)::text from (select ` ~ issueCols
        ~ ` from issues i join projects p on p.id = i.project_id where i.id = $1::bigint) t`, [id]));
}

void updateIssue(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    Json j;
    try
        j = req.json;
    catch (Exception)
        fail(400, "Expected a JSON body.");
    if (j.type != Json.Type.object)
        fail(400, "Expected a JSON object.");
    if (j["status"].type == Json.Type.string)
    {
        auto status = j["status"].get!string;
        if (status != "unresolved" && status != "resolved" && status != "ignored")
            fail(400, "Invalid status.");
        query("update issues set status = $2 where id = $1::bigint", [id, status]);
    }
    if (j["assignedTo"].type != Json.Type.undefined)
    {
        auto pid = issueProject(id);
        query("update issues set assigned_to = $2::int where id = $1::bigint", [id, resolveAssignee(a, pid, j["assignedTo"])]);
    }
    res.sendJson(queryJson(`select row_to_json(t)::text from (select ` ~ issueCols
        ~ ` from issues i join projects p on p.id = i.project_id where i.id = $1::bigint) t`, [id]));
}

/// Maps an `assignedTo` value (null, "me" or an email) to a user id of the
/// project's organization; null means unassigned.
string resolveAssignee(Auth a, string projectId, Json v) @trusted
{
    if (v.type == Json.Type.null_)
        return null;
    if (v.type != Json.Type.string)
        fail(400, "assignedTo must be null, \"me\" or an email address.");
    auto who = v.get!string;
    if (who == "me")
        return a.userId;
    auto rows = query(`select u.id::text from users u
        join org_members m on m.user_id = u.id join projects p on p.organization_id = m.organization_id
        where p.id = $1::int and lower(u.email) = lower($2)`, [projectId, who]);
    if (!rows.length)
        fail(404, "No such member in this organization.");
    return rows[0][0];
}

void deleteIssue(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    if (roleRank(issueRole(a, id)) < 2)
        fail(403, "Admin role required.");
    query("delete from issues where id = $1::bigint", [id]);
    res.sendJson(`{"ok":true}`);
}

void listIssueEvents(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    issueRole(a, id);
    res.sendJson(queryJson(`select coalesce(json_agg(t), '[]')::text from (
        select event_id as "eventID", received_at as "dateReceived", environment, release, tags
        from events where issue_id = $1::bigint order by received_at desc limit 100) t`, [id]));
}

void getEvent(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    string[][] rows;
    try
        rows = query("select project_id::text from events where event_id = $1::uuid limit 1", [req.params["event_id"]]);
    catch (Exception)
        fail(404, "Not found.");
    if (!rows.length || projectRole(a, rows[0][0]) is null)
        fail(404, "Not found.");
    res.sendJson(queryJson(`select row_to_json(t)::text from (
        select event_id as "eventID", issue_id::text as "issueId", received_at as "dateReceived", data
        from events where event_id = $1::uuid limit 1) t`, [req.params["event_id"]]));
}

// ---- API tokens --------------------------------------------------------------

void listTokens(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', id, 'label', label,
        'dateCreated', created_at, 'lastUsed', last_used) order by id), '[]')::text
        from api_tokens where user_id = $1::int`, [a.userId]));
}

void createToken(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto label = body_(req, "label").strip;
    if (!label.length)
        fail(400, "Label is required.");
    auto token = "gt_" ~ newToken();
    auto id = query("insert into api_tokens (user_id, token_hash, label) values ($1::int, encode(digest($2, 'sha256'), 'hex'), $3) returning id::text",
            [a.userId, token, label])[0][0];
    // The clear-text token is shown exactly once.
    res.sendJson(`{"id":` ~ id ~ `,"token":"` ~ token ~ `"}`, 201);
}

void deleteToken(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto id = req.params["id"];
    if (!isId(id))
        fail(404, "Not found.");
    auto rows = query("delete from api_tokens where id = $1::int and user_id = $2::int returning 1", [id, a.userId]);
    if (!rows.length)
        fail(404, "Not found.");
    res.sendJson(`{"ok":true}`);
}

void registerRoutes(URLRouter router)
{
    router.post("/api/0/auth/register/", &register);
    router.post("/api/0/auth/login/", &login);
    router.post("/api/0/auth/logout/", &logout);
    router.get("/api/0/auth/me/", authed(&me));
    router.post("/api/0/auth/password/", authed(&changePassword));

    router.get("/api/0/organizations/", authed(&listOrgs));
    router.post("/api/0/organizations/", authed(&createOrganization));
    router.get("/api/0/organizations/:slug/members/", authed(&listMembers));
    router.post("/api/0/organizations/:slug/members/", authed(&addMember));

    router.get("/api/0/projects/", authed(&listProjects));
    router.post("/api/0/projects/", authed(&createProject));

    router.get("/api/0/issues/:id/", authed(&getIssue));
    router.put("/api/0/issues/:id/", authed(&updateIssue));
    router.delete_("/api/0/issues/:id/", authed(&deleteIssue));
    router.get("/api/0/issues/:id/events/", authed(&listIssueEvents));
    router.get("/api/0/events/:event_id/", authed(&getEvent));

    router.get("/api/0/api-tokens/", authed(&listTokens));
    router.post("/api/0/api-tokens/", authed(&createToken));
    router.delete_("/api/0/api-tokens/:id/", authed(&deleteToken));
}
