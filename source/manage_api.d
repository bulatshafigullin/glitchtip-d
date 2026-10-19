module manage_api;

// Sentry-compatible management endpoints: DSN keys, teams and releases.

import vibe.vibe;
import std.conv : to;
import std.string : strip, join, replace;
import std.algorithm : min, max;
import db;
import auth;
import search;
import api;
import intake : invalidateKeyCache;
import sentry_api : jsonBody, requireOrg, resolveProject, firstOf, flag, toLong, isUuidLike;

// ---- DSN keys --------------------------------------------------------------------------------

enum keyJson = `json_build_object(
    'id', replace(k.public_key::text, '-', ''), 'public', replace(k.public_key::text, '-', ''), 'label', k.label,
    'isActive', k.is_active, 'dateCreated', k.created_at, 'allowedOrigins', to_json(k.allowed_origins),
    'rateLimit', case when k.rate_limit_count is null then null
                      else json_build_object('count', k.rate_limit_count, 'window', k.rate_limit_window) end,
    'dsn', json_build_object('public', $1 || '://' || replace(k.public_key::text, '-', '') || '@' || $2 || '/' || k.project_id))`;

private string keyOfProject(string pid, string pubKey = null) @trusted
{
    auto d = dsnParts();
    return queryJson(`select coalesce(json_agg(` ~ keyJson ~ ` order by k.id), '[]')::text from project_keys k
        where k.project_id = $3::int and ($4::text is null or k.public_key = $4::uuid)`, [d[0], d[1], pid, pubKey]);
}

void listKeys(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    res.sendJson(keyOfProject(resolveProject(a, req.params["org"], req.params["proj"])));
}

void getKey(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = resolveProject(a, req.params["org"], req.params["proj"]);
    if (!isUuidLike(req.params["key"]))
        fail(404, "Not found.");
    auto j = keyOfProject(pid, req.params["key"]);
    if (j.strip == "[]")
        fail(404, "Not found.");
    res.sendJson(firstOf(j));
}

/// Applies label / isActive / rateLimit / allowedOrigins from the request body.
private void applyKeyFields(string keyId, Json j) @trusted
{
    Q q;
    string[] sets;
    if (j["label"].type == Json.Type.string && j["label"].get!string.strip.length)
        sets ~= "label = " ~ q.add(j["label"].get!string.strip);
    if (j["isActive"].type == Json.Type.bool_)
        sets ~= "is_active = " ~ q.add(flag(j["isActive"].get!bool)) ~ "::boolean";
    auto rl = j["rateLimit"];
    if (rl.type == Json.Type.null_)
        sets ~= "rate_limit_count = null, rate_limit_window = null";
    else if (rl.type == Json.Type.object)
    {
        auto count = rl["count"], window = rl["window"];
        if (count.type != Json.Type.int_ || window.type != Json.Type.int_
            || count.get!long < 1 || count.get!long > 1_000_000_000 || window.get!long < 1 || window.get!long > 86_400)
            fail(400, "rateLimit needs count >= 1 and window between 1 and 86400 seconds.");
        sets ~= "rate_limit_count = " ~ q.add(count.get!long.to!string) ~ "::int";
        sets ~= "rate_limit_window = " ~ q.add(window.get!long.to!string) ~ "::int";
    }
    else if (rl.type != Json.Type.undefined)
        fail(400, "rateLimit must be an object or null.");
    auto ao = j["allowedOrigins"];
    if (ao.type == Json.Type.array)
    {
        string[] items;
        foreach (o; ao)
        {
            if (o.type != Json.Type.string || o.get!string.length > 200 || items.length >= 50)
                fail(400, "allowedOrigins must be up to 50 strings of at most 200 characters.");
            items ~= q.add(o.get!string.strip) ~ "::text";
        }
        sets ~= items.length ? "allowed_origins = array[" ~ items.join(",") ~ "]" : "allowed_origins = '{}'";
    }
    else if (ao.type != Json.Type.undefined)
        fail(400, "allowedOrigins must be an array of strings.");
    if (sets.length)
        query("update project_keys set " ~ sets.join(", ") ~ " where id = " ~ q.add(keyId) ~ "::int", q.args);
    invalidateKeyCache();
}

private string adminProject(HTTPServerRequest req, Auth a) @trusted
{
    string role;
    auto pid = resolveProject(a, req.params["org"], req.params["proj"], role);
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    return pid;
}

void createKey(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = adminProject(req, a);
    auto j = jsonBody(req);
    auto rows = query("insert into project_keys (project_id) values ($1::int) returning id::text, public_key::text", [pid]);
    applyKeyFields(rows[0][0], j);
    res.sendJson(firstOf(keyOfProject(pid, rows[0][1])), 201);
}

/// Looks up a key (by public key) in a project; returns [row id, public key].
private string[] findKey(string pid, string pubKey) @trusted
{
    if (!isUuidLike(pubKey))
        fail(404, "Not found.");
    auto rows = query("select id::text, public_key::text from project_keys where project_id = $1::int and public_key = $2::uuid", [pid, pubKey]);
    if (!rows.length)
        fail(404, "Not found.");
    return rows[0];
}

void updateKey(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = adminProject(req, a);
    auto k = findKey(pid, req.params["key"]);
    applyKeyFields(k[0], jsonBody(req));
    res.sendJson(firstOf(keyOfProject(pid, k[1])));
}

void rotateKey(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = adminProject(req, a);
    auto k = findKey(pid, req.params["key"]);
    auto fresh = query("update project_keys set public_key = gen_random_uuid() where id = $1::int returning public_key::text", [k[0]])[0][0];
    invalidateKeyCache();
    res.sendJson(firstOf(keyOfProject(pid, fresh)));
}

void deleteKey(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto pid = adminProject(req, a);
    auto k = findKey(pid, req.params["key"]);
    query("delete from project_keys where id = $1::int", [k[0]]);
    invalidateKeyCache();
    res.statusCode = 204;
    res.writeBody("");
}

// ---- teams ---------------------------------------------------------------------------------------

private enum teamJson = `json_build_object('slug', t.slug, 'name', t.name, 'dateCreated', t.created_at,
    'memberCount', (select count(*) from team_members m where m.team_id = t.id),
    'isMember', exists (select 1 from team_members m where m.team_id = t.id and m.user_id = $2::int),
    'projects', coalesce((select json_agg(p.slug order by p.id) from project_teams pt join projects p on p.id = pt.project_id
                          where pt.team_id = t.id), '[]'::json))`;

private string teamsOf(string org, string userId, string teamSlug = null) @trusted
{
    return queryJson(`select coalesce(json_agg(` ~ teamJson ~ ` order by t.id), '[]')::text from teams t
        join organizations o on o.id = t.organization_id where o.slug = $1 and ($3::text is null or t.slug = $3)`, [org, userId, teamSlug]);
}

private string teamId(string org, string slug) @trusted
{
    auto rows = query("select t.id::text from teams t join organizations o on o.id = t.organization_id where o.slug = $1 and t.slug = $2", [org, slug]);
    if (!rows.length)
        fail(404, "Not found.");
    return rows[0][0];
}

void listTeams(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    res.sendJson(teamsOf(req.params["org"], a.userId));
}

private string uniqueTeamSlug(string org, string base) @trusted
{
    auto slug = base;
    while (query("select 1 from teams t join organizations o on o.id = t.organization_id where o.slug = $1 and t.slug = $2", [org, slug]).length)
        slug = base ~ "-" ~ newToken()[0 .. 4];
    return slug;
}

void createTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org, 2);
    auto j = jsonBody(req);
    auto name = j["name"].type == Json.Type.string ? j["name"].get!string.strip : "";
    if (!name.length || name.length > 100)
        fail(400, "Name must be 1 to 100 characters.");
    auto base = j["slug"].type == Json.Type.string && slugify(j["slug"].get!string).length ? slugify(j["slug"].get!string) : slugify(name);
    auto slug = uniqueTeamSlug(org, base);
    query("insert into teams (organization_id, slug, name) select id, $2, $3 from organizations where slug = $1", [org, slug, name]);
    res.sendJson(firstOf(teamsOf(org, a.userId, slug)), 201);
}

void getTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    teamId(req.params["org"], req.params["team"]);
    res.sendJson(firstOf(teamsOf(req.params["org"], a.userId, req.params["team"])));
}

void updateTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org, 2);
    auto id = teamId(org, req.params["team"]);
    auto j = jsonBody(req);
    if (j["name"].type != Json.Type.string || !j["name"].get!string.strip.length)
        fail(400, "Name is required.");
    query("update teams set name = $2 where id = $1::int", [id, j["name"].get!string.strip]);
    res.sendJson(firstOf(teamsOf(org, a.userId, req.params["team"])));
}

void deleteTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"], 2);
    query("delete from teams where id = $1::int", [teamId(req.params["org"], req.params["team"])]);
    res.statusCode = 204;
    res.writeBody("");
}

void teamMembers(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    auto id = teamId(req.params["org"], req.params["team"]);
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', u.id, 'email', u.email, 'role', om.role) order by u.id), '[]')::text
        from team_members tm join users u on u.id = tm.user_id
        join teams t on t.id = tm.team_id
        left join org_members om on om.user_id = u.id and om.organization_id = t.organization_id
        where tm.team_id = $1::int`, [id]));
}

/// Joins (POST) or leaves (DELETE) a team. Admins can do it for anyone; members
/// can manage themselves when the organization has open membership.
private void membership(HTTPServerRequest req, HTTPServerResponse res, Auth a, bool join) @trusted
{
    auto org = req.params["org"];
    auto role = requireOrg(a, org);
    auto uid = req.params["user_id"] == "me" ? a.userId : req.params["user_id"];
    if (!isId(uid))
        fail(404, "Not found.");
    auto open = query("select open_membership::text from organizations where slug = $1", [org])[0][0] == "true";
    if (roleRank(role) < 2 && !(uid == a.userId && open))
        fail(403, "Admin role required.");
    auto tid = teamId(org, req.params["team"]);
    if (!query(`select 1 from org_members m join organizations o on o.id = m.organization_id
                where o.slug = $1 and m.user_id = $2::int`, [org, uid]).length)
        fail(404, "Not an organization member.");
    if (join)
        query("insert into team_members (team_id, user_id) values ($1::int, $2::int) on conflict do nothing", [tid, uid]);
    else
        query("delete from team_members where team_id = $1::int and user_id = $2::int", [tid, uid]);
    res.sendJson(firstOf(teamsOf(org, a.userId, req.params["team"])), join ? 201 : 200);
}

void joinTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    membership(req, res, a, true);
}

void leaveTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    membership(req, res, a, false);
}

void teamProjects(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    auto id = teamId(req.params["org"], req.params["team"]);
    res.sendJson(queryJson(projectsSql("and exists (select 1 from project_teams pt where pt.project_id = p.id and pt.team_id = $5::int)"),
            [flag(a.superuser), a.userId] ~ dsnParts() ~ [id]));
}

/// Sentry-style: creating a project under a team also assigns the team.
void createTeamProject(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org, 2);
    auto id = teamId(org, req.params["team"]);
    auto name = body_(req, "name").strip;
    if (!name.length)
        fail(400, "Name is required.");
    auto platform = body_(req, "platform", false);
    auto pid = createProjectIn(org, name, platform);
    query("insert into project_teams (project_id, team_id) values ($1::int, $2::int)", [pid, id]);
    res.sendJson(firstOf(queryJson(projectsSql("and p.id = $5::int"), [flag(a.superuser), a.userId] ~ dsnParts() ~ [pid])), 201);
}

private void projectTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a, bool add) @trusted
{
    auto org = req.params["org"];
    string role;
    auto pid = resolveProject(a, org, req.params["proj"], role);
    if (roleRank(role) < 2)
        fail(403, "Admin role required.");
    auto tid = teamId(org, req.params["team"]);
    if (add)
        query("insert into project_teams (project_id, team_id) values ($1::int, $2::int) on conflict do nothing", [pid, tid]);
    else
        query("delete from project_teams where project_id = $1::int and team_id = $2::int", [pid, tid]);
    res.sendJson(firstOf(queryJson(projectsSql("and p.id = $5::int"), [flag(a.superuser), a.userId] ~ dsnParts() ~ [pid])), add ? 201 : 200);
}

void addProjectTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    projectTeam(req, res, a, true);
}

void removeProjectTeam(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    projectTeam(req, res, a, false);
}

// ---- releases --------------------------------------------------------------------------------------

private string releasesOf(Auth a, string org, string ver, string search, long limit) @trusted
{
    Q q;
    auto o = q.add(org);
    auto u = q.add(a.userId);
    auto s = q.add(flag(a.superuser));
    auto cond = " and (" ~ q.add(ver) ~ "::text is null or r.version = " ~ q.add(ver) ~ ")"
        ~ " and (" ~ q.add(search) ~ "::text is null or r.version ilike '%' || " ~ q.add(likeEscape(search)) ~ " || '%')";
    // a release is visible when it has no projects yet or at least one the caller can see
    return queryJson(`select coalesce(json_agg(t order by t."dateCreated" desc), '[]')::text from (
        select r.version, r.ref, r.url, r.created_at as "dateCreated", r.date_released as "dateReleased",
            coalesce((select json_agg(json_build_object('slug', p.slug, 'name', p.name) order by p.id)
                      from release_projects rp join projects p on p.id = rp.project_id
                      where rp.release_id = r.id and ` ~ accessCond(u, s) ~ `), '[]'::json) as projects,
            (select count(*) from deploys d where d.release_id = r.id) as "deployCount",
            (select row_to_json(x) from (select d.environment, d.name, d.date_finished as "dateFinished" from deploys d
                                         where d.release_id = r.id order by d.date_finished desc limit 1) x) as "lastDeploy"
        from releases r join organizations o on o.id = r.organization_id
        where o.slug = ` ~ o ~ cond ~ `
          and (not exists (select 1 from release_projects rp where rp.release_id = r.id)
               or exists (select 1 from release_projects rp join projects p on p.id = rp.project_id
                          where rp.release_id = r.id and ` ~ accessCond(u, s) ~ `))
        order by r.created_at desc limit ` ~ limit.to!string ~ `) t`, q.args);
}

void listReleases(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    auto search = req.query.get("query", "");
    res.sendJson(releasesOf(a, req.params["org"], null, search.length ? search : null, min(max(toLong(req.query.get("limit", "25"), 25), 1), 100)));
}

private string releaseId(string org, string ver) @trusted
{
    auto rows = query("select r.id::text from releases r join organizations o on o.id = r.organization_id where o.slug = $1 and r.version = $2",
            [org, ver]);
    if (!rows.length)
        fail(404, "Not found.");
    return rows[0][0];
}

private string optString(Json j, string key, size_t max)
{
    if (j[key].type != Json.Type.string)
        return null;
    auto v = j[key].get!string;
    if (v.length > max)
        fail(400, "Field '" ~ key ~ "' is too long.");
    return v.length ? v : null;
}

private void linkReleaseProjects(Auth a, string org, string rid, Json projects) @trusted
{
    if (projects.type == Json.Type.undefined)
        return;
    if (projects.type != Json.Type.array)
        fail(400, "projects must be an array of project slugs.");
    foreach (sl; projects)
    {
        if (sl.type != Json.Type.string)
            fail(400, "projects must be an array of project slugs.");
        auto pid = resolveProject(a, org, sl.get!string);
        query("insert into release_projects (release_id, project_id) values ($1::int, $2::int) on conflict do nothing", [rid, pid]);
    }
}

void createRelease(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org);
    auto j = jsonBody(req);
    auto ver = optString(j, "version", 200);
    if (!ver.length)
        fail(400, "version is required.");
    string released = optString(j, "dateReleased", 40);
    string[][] rows;
    try
        rows = query(`insert into releases (organization_id, version, ref, url, date_released)
            select id, $2, $3, $4, $5::timestamptz from organizations where slug = $1
            on conflict (organization_id, version) do update set ref = coalesce(excluded.ref, releases.ref),
                url = coalesce(excluded.url, releases.url), date_released = coalesce(excluded.date_released, releases.date_released)
            returning id::text`, [org, ver, optString(j, "ref", 200), optString(j, "url", 500), released]);
    catch (Exception)
        fail(400, "Invalid dateReleased.");
    linkReleaseProjects(a, org, rows[0][0], j["projects"]);
    res.sendJson(firstOf(releasesOf(a, org, ver, null, 1)), 201);
}

void getRelease(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    releaseId(req.params["org"], req.params["version"]);
    res.sendJson(firstOf(releasesOf(a, req.params["org"], req.params["version"], null, 1)));
}

void updateRelease(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    auto org = req.params["org"];
    requireOrg(a, org);
    auto rid = releaseId(org, req.params["version"]);
    auto j = jsonBody(req);
    try
        query(`update releases set ref = coalesce($2, ref), url = coalesce($3, url), date_released = coalesce($4::timestamptz, date_released)
            where id = $1::int`, [rid, optString(j, "ref", 200), optString(j, "url", 500), optString(j, "dateReleased", 40)]);
    catch (Exception)
        fail(400, "Invalid dateReleased.");
    linkReleaseProjects(a, org, rid, j["projects"]);
    res.sendJson(firstOf(releasesOf(a, org, req.params["version"], null, 1)));
}

void deleteRelease(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"], 2);
    query("delete from releases where id = $1::int", [releaseId(req.params["org"], req.params["version"])]);
    res.statusCode = 204;
    res.writeBody("");
}

void listDeploys(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    auto rid = releaseId(req.params["org"], req.params["version"]);
    res.sendJson(queryJson(`select coalesce(json_agg(json_build_object('id', d.id::text, 'environment', d.environment, 'name', d.name,
        'url', d.url, 'dateStarted', d.date_started, 'dateFinished', d.date_finished) order by d.date_finished desc), '[]')::text
        from deploys d where d.release_id = $1::int`, [rid]));
}

void createDeploy(HTTPServerRequest req, HTTPServerResponse res, Auth a) @trusted
{
    requireOrg(a, req.params["org"]);
    auto rid = releaseId(req.params["org"], req.params["version"]);
    auto j = jsonBody(req);
    auto env = optString(j, "environment", 64);
    if (!env.length)
        fail(400, "environment is required.");
    string[][] rows;
    try
        rows = query(`insert into deploys (release_id, environment, name, url, date_started, date_finished)
            values ($1::int, $2, $3, $4, $5::timestamptz, coalesce($6::timestamptz, now()))
            returning json_build_object('id', id::text, 'environment', environment, 'name', name, 'url', url,
                'dateStarted', date_started, 'dateFinished', date_finished)::text`,
                [rid, env, optString(j, "name", 200), optString(j, "url", 500), optString(j, "dateStarted", 40), optString(j, "dateFinished", 40)]);
    catch (Exception)
        fail(400, "Invalid date.");
    res.sendJson(rows[0][0], 201);
}

void registerManageRoutes(URLRouter router)
{
    router.get("/api/0/projects/:org/:proj/keys/", authed(&listKeys));
    router.post("/api/0/projects/:org/:proj/keys/", authed(&createKey));
    router.get("/api/0/projects/:org/:proj/keys/:key/", authed(&getKey));
    router.put("/api/0/projects/:org/:proj/keys/:key/", authed(&updateKey));
    router.delete_("/api/0/projects/:org/:proj/keys/:key/", authed(&deleteKey));
    router.post("/api/0/projects/:org/:proj/keys/:key/rotate/", authed(&rotateKey));

    router.get("/api/0/organizations/:org/teams/", authed(&listTeams));
    router.post("/api/0/organizations/:org/teams/", authed(&createTeam));
    router.get("/api/0/teams/:org/:team/", authed(&getTeam));
    router.put("/api/0/teams/:org/:team/", authed(&updateTeam));
    router.delete_("/api/0/teams/:org/:team/", authed(&deleteTeam));
    router.get("/api/0/teams/:org/:team/members/", authed(&teamMembers));
    router.get("/api/0/teams/:org/:team/projects/", authed(&teamProjects));
    router.post("/api/0/teams/:org/:team/projects/", authed(&createTeamProject));
    router.post("/api/0/organizations/:org/members/:user_id/teams/:team/", authed(&joinTeam));
    router.delete_("/api/0/organizations/:org/members/:user_id/teams/:team/", authed(&leaveTeam));
    router.post("/api/0/projects/:org/:proj/teams/:team/", authed(&addProjectTeam));
    router.delete_("/api/0/projects/:org/:proj/teams/:team/", authed(&removeProjectTeam));

    router.get("/api/0/organizations/:org/releases/", authed(&listReleases));
    router.post("/api/0/organizations/:org/releases/", authed(&createRelease));
    router.get("/api/0/organizations/:org/releases/:version/", authed(&getRelease));
    router.put("/api/0/organizations/:org/releases/:version/", authed(&updateRelease));
    router.delete_("/api/0/organizations/:org/releases/:version/", authed(&deleteRelease));
    router.get("/api/0/organizations/:org/releases/:version/deploys/", authed(&listDeploys));
    router.post("/api/0/organizations/:org/releases/:version/deploys/", authed(&createDeploy));
}
