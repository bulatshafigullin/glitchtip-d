module auth;

import vibe.http.server;
import vibe.http.common;
import vibe.data.json;
import std.string : startsWith, toLower, strip;
import std.algorithm : canFind;
import db;

enum sessionCookie = "gt_session";

struct Auth
{
    bool ok;
    string userId;
    bool superuser;
    bool viaSession;
}

/// Hex-encoded 32 random bytes from the database CSPRNG.
string newToken() @trusted
{
    return query("select encode(gen_random_bytes(32), 'hex')")[0][0];
}

/// Resolves the caller from a Bearer API token or the session cookie.
Auth authenticate(HTTPServerRequest req) @trusted
{
    Auth a;
    auto header = req.headers.get("Authorization", "");
    if (header.startsWith("Bearer "))
    {
        auto rows = query(`update api_tokens t set last_used = now()
            from users u where u.id = t.user_id and t.token_hash = encode(digest($1, 'sha256'), 'hex')
            returning u.id::text, u.is_superuser::text`, [header[7 .. $].strip]);
        if (rows.length)
            a = Auth(true, rows[0][0], rows[0][1] == "true", false);
        return a;
    }
    if (auto tok = sessionCookie in req.cookies)
    {
        auto rows = query(`select u.id::text, u.is_superuser::text from sessions s
            join users u on u.id = s.user_id
            where s.token_hash = encode(digest($1, 'sha256'), 'hex') and s.expires_at > now()`, [*tok]);
        if (rows.length)
            a = Auth(true, rows[0][0], rows[0][1] == "true", true);
    }
    return a;
}

/// Cross-site forms cannot set custom headers, so requiring one on every
/// state-changing cookie-authenticated request blocks CSRF.
bool csrfOk(HTTPServerRequest req)
{
    return req.method == HTTPMethod.GET || req.method == HTTPMethod.HEAD
        || req.headers.get("X-Requested-With", "").length > 0;
}

string startSession(HTTPServerResponse res, string userId, bool secure) @trusted
{
    auto token = newToken();
    query(`insert into sessions (token_hash, user_id, expires_at)
        values (encode(digest($1, 'sha256'), 'hex'), $2::int, now() + interval '30 days')`, [token, userId]);
    auto c = res.setCookie(sessionCookie, token, "/");
    c.httpOnly = true;
    c.secure = secure;
    c.sameSite = Cookie.SameSite.lax;
    c.maxAge = 30 * 24 * 3600;
    return token;
}

int roleRank(string role)
{
    switch (role)
    {
    case "owner": return 3;
    case "admin": return 2;
    case "member": return 1;
    default: return 0;
    }
}

/// The caller's role in the organization owning the project, or null when the
/// project is not visible: members of non-open organizations only see projects
/// assigned to one of their teams.
string projectRole(Auth a, string projectId) @trusted
{
    auto rows = query(`select coalesce(
            (select m.role from org_members m
             join projects p on p.organization_id = m.organization_id
             join organizations o on o.id = m.organization_id
             where p.id = $1::int and m.user_id = $2::int
               and (m.role in ('owner', 'admin') or o.open_membership or exists (
                    select 1 from project_teams pt join team_members tm on tm.team_id = pt.team_id
                    where pt.project_id = p.id and tm.user_id = $2::int))),
            case when $3::boolean and exists (select 1 from projects where id = $1::int) then 'owner' end)`,
            [projectId, a.userId, a.superuser ? "true" : "false"]);
    return rows[0][0];
}

/// The caller's role in the organization with this slug, or null.
string orgRole(Auth a, string slug) @trusted
{
    auto rows = query(`select coalesce(
            (select m.role from org_members m join organizations o on o.id = m.organization_id
             where o.slug = $1 and m.user_id = $2::int),
            case when $3::boolean and exists (select 1 from organizations where slug = $1) then 'owner' end)`,
            [slug, a.userId, a.superuser ? "true" : "false"]);
    return rows[0][0];
}

/// Project that owns an issue, or null.
string issueProject(string issueId) @trusted
{
    auto rows = query("select project_id::text from issues where id = $1::bigint", [issueId]);
    return rows.length ? rows[0][0] : null;
}

bool isId(string s)
{
    import std.ascii : isDigit;
    import std.algorithm : all;
    return s.length > 0 && s.length < 18 && s.all!isDigit;
}
