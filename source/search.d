module search;

import std.array : replace;
import std.conv : to;
import std.string : strip, toLower, indexOf;
import std.algorithm : canFind;

/// Collects positional SQL parameters; `add` returns the placeholder.
struct Q
{
    string[] args;

    string add(string v)
    {
        args ~= v;
        return "$" ~ args.length.to!string;
    }
}

/// Issue columns shared by every issue listing. Needs `issues i join projects p`.
enum issueCols = `i.id::text as id, i.title, i.culprit, i.level, i.status, i.count::text as count,
    i.first_seen as "firstSeen", i.last_seen as "lastSeen", i.project_id as "projectId", p.slug as "projectSlug",
    (select u.email from users u where u.id = i.assigned_to) as "assignedTo",
    (select count(*) from issue_comments c where c.issue_id = i.id) as "numComments"`;

/// SQL condition (alias `p` = projects) that is true when the user may see the
/// project: superusers, org owners/admins, any member of an open-membership org,
/// or members of a team the project is assigned to. `u` and `s` are placeholders.
string accessCond(string u, string s)
{
    return "(" ~ s ~ "::boolean or exists (select 1 from org_members m join organizations o on o.id = m.organization_id"
        ~ " where m.organization_id = p.organization_id and m.user_id = " ~ u ~ "::int"
        ~ " and (m.role in ('owner','admin') or o.open_membership or exists (select 1 from project_teams pt"
        ~ " join team_members tm on tm.team_id = pt.team_id where pt.project_id = p.id and tm.user_id = " ~ u ~ "::int))))";
}

struct Token
{
    bool negated;
    string key; // null for free text
    string value;
}

/// Splits `is:unresolved !level:info release:"1.0 beta" some text` into tokens.
Token[] tokenize(string s)
{
    Token[] tokens;
    size_t i = 0;
    immutable n = s.length;

    string readValue()
    {
        if (i < n && s[i] == '"')
        {
            auto start = ++i;
            while (i < n && s[i] != '"')
                i++;
            auto v = s[start .. i];
            if (i < n)
                i++;
            return v;
        }
        auto start = i;
        while (i < n && s[i] != ' ')
            i++;
        return s[start .. i];
    }

    while (i < n && tokens.length < 20)
    {
        while (i < n && s[i] == ' ')
            i++;
        if (i >= n)
            break;
        Token t;
        if (s[i] == '!' && i + 1 < n)
        {
            t.negated = true;
            i++;
        }
        auto start = i;
        while (i < n && s[i] != ' ' && s[i] != ':' && s[i] != '"')
            i++;
        if (i < n && s[i] == ':' && i > start)
        {
            t.key = s[start .. i].toLower;
            i++;
            t.value = readValue();
        }
        else
        {
            i = start;
            t.value = readValue();
        }
        if (t.value.length > 200)
            t.value = t.value[0 .. 200];
        if (t.value.length)
            tokens ~= t;
    }
    return tokens;
}

string likeEscape(string s)
{
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
}

/// `exists (events ...)` condition for a tag-style filter on the issue's events.
private string eventCond(ref Q q, string key, string value, bool neg)
{
    string col;
    if (key == "environment")
        col = "e.environment";
    else if (key == "release")
        col = "e.release";
    else
        col = "e.tags ->> " ~ q.add(key) ~ "::text";
    string cmp = value.canFind('*')
        ? col ~ " ilike " ~ q.add(likeEscape(value).replace("*", "%"))
        : col ~ " = " ~ q.add(value);
    return (neg ? "not " : "") ~ "exists (select 1 from events e where e.issue_id = i.id and " ~ cmp ~ ")";
}

/// Builds extra `and ...` conditions for an issue search (aliases `i`, `p`).
/// With `defaultUnresolved`, a query that has no `is:` token only shows unresolved issues.
string issueFilter(ref Q q, string queryText, string userId, bool defaultUnresolved)
{
    string sql;
    bool sawStatus;
    foreach (t; tokenize(queryText))
    {
        string cond;
        auto v = t.value;
        switch (t.key)
        {
        case null:
            auto pat = q.add("%" ~ likeEscape(v) ~ "%");
            cond = "(i.title ilike " ~ pat ~ " or i.culprit ilike " ~ pat ~ ")";
            if (t.negated)
                cond = "not " ~ cond;
            sql ~= " and " ~ cond;
            continue;
        case "is":
            if (v == "assigned")
                cond = "i.assigned_to is not null";
            else if (v == "unassigned")
                cond = "i.assigned_to is null";
            else if (v == "unresolved" || v == "resolved" || v == "ignored")
            {
                sawStatus = true;
                cond = "i.status = " ~ q.add(v);
            }
            else
                cond = "false";
            break;
        case "level":
            cond = "i.level = " ~ q.add(v.toLower);
            break;
        case "project":
            cond = "p.slug = " ~ q.add(v);
            break;
        case "assigned":
            if (v == "me")
                cond = "i.assigned_to = " ~ q.add(userId) ~ "::int";
            else if (v == "none" || v == "unassigned")
                cond = "i.assigned_to is null";
            else
                cond = "i.assigned_to = (select id from users where lower(email) = lower(" ~ q.add(v) ~ "))";
            break;
        case "has":
            if (v == "environment" || v == "release")
                cond = "exists (select 1 from events e where e.issue_id = i.id and e." ~ v ~ " is not null)";
            else
                cond = "exists (select 1 from events e where e.issue_id = i.id and e.tags ? " ~ q.add(v) ~ "::text)";
            break;
        default:
            sql ~= " and " ~ eventCond(q, t.key, v, t.negated);
            continue;
        }
        sql ~= " and " ~ (t.negated ? "not (" ~ cond ~ ")" : cond);
    }
    if (defaultUnresolved && !sawStatus)
        sql ~= " and i.status = 'unresolved'";
    return sql;
}

string orderBy(string sort)
{
    switch (sort)
    {
    case "new": return "i.first_seen desc";
    case "freq": return "i.count desc, i.last_seen desc";
    default: return "i.last_seen desc";
    }
}
