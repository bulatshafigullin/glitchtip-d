module ingest;

import std.json;
import std.digest.md : md5Of;
import std.digest : toHexString;
import std.string : indexOf, strip, split, startsWith, toLower, endsWith, replace;
import std.uuid : randomUUID;
import std.zlib : UnCompress, HeaderFormat;
import std.conv : to;
import std.algorithm : canFind, all, min;
import std.ascii : isHexDigit;
import std.array : appender;
import std.exception : assumeUnique;
import std.uni : icmp;
import postgrex : PgConnection;
import db;

__gshared long maxAttachmentBytes = 1024 * 1024;

/// Upper bound for a request body after decompression (also the HTTP request limit).
__gshared size_t maxBodyBytes = 20 * 1024 * 1024;

private bool[string] knownReleases; // thread-local cache of "projectId/release"

/// A decompressed body exceeded `maxBodyBytes`.
class PayloadTooLargeException : Exception
{
    this() { super("Payload too large."); }
}

/// Inflates `raw` in small chunks so a compression bomb is rejected as soon as the
/// output passes `maxBodyBytes`, instead of exhausting memory first.
private ubyte[] inflate(const(ubyte)[] raw, HeaderFormat format)
{
    enum chunk = 8192;
    auto u = new UnCompress(format);
    auto sink = appender!(ubyte[])();
    for (size_t i = 0; i < raw.length; i += chunk)
    {
        sink.put(cast(const(ubyte)[]) u.uncompress(raw[i .. i + chunk < raw.length ? i + chunk : raw.length]));
        if (sink.data.length > maxBodyBytes)
            throw new PayloadTooLargeException;
    }
    sink.put(cast(const(ubyte)[]) u.flush());
    if (sink.data.length > maxBodyBytes)
        throw new PayloadTooLargeException;
    return sink.data;
}

/// Decompresses a request body according to Content-Encoding. An uncompressed body
/// is returned as is (no copy).
ubyte[] decodeBody(ubyte[] raw, string encoding)
{
    // vibe.d may already have inflated the body, so sniff the gzip magic too.
    if (raw.length > 2 && icmp(encoding, "gzip") == 0 && raw[0] == 0x1f && raw[1] == 0x8b)
        return inflate(raw, HeaderFormat.gzip);
    if (raw.length > 2 && icmp(encoding, "deflate") == 0 && raw[0] == 0x78)
        return inflate(raw, HeaderFormat.deflate);
    return raw;
}

/// Extracts the public key from `X-Sentry-Auth` header or query value.
string parseSentryKey(string authHeader, string queryKey)
{
    if (queryKey.length)
        return queryKey;
    foreach (part; authHeader.split(","))
    {
        auto kv = part.strip;
        if (kv.startsWith("Sentry "))
            kv = kv[7 .. $];
        auto eq = kv.indexOf('=');
        if (eq > 0 && kv[0 .. eq].strip == "sentry_key")
            return kv[eq + 1 .. $].strip;
    }
    return null;
}

// ---- envelopes ----------------------------------------------------------------

struct EnvelopeItem
{
    string type;
    JSONValue header;
    const(char)[] payload;
}

struct Envelope
{
    JSONValue header;
    EnvelopeItem[] items;
}

/// Parses a Sentry envelope: a header line, then (item header, payload) pairs.
/// Throws on malformed input.
Envelope parseEnvelope(const(char)[] data)
{
    Envelope env;
    size_t pos = 0;

    const(char)[] nextLine()
    {
        auto nl = data[pos .. $].indexOf('\n');
        const(char)[] line;
        if (nl < 0)
        {
            line = data[pos .. $];
            pos = data.length;
        }
        else
        {
            line = data[pos .. pos + nl];
            pos += nl + 1;
        }
        return line;
    }

    env.header = parseJSON(nextLine());
    while (pos < data.length)
    {
        auto headerLine = nextLine();
        if (headerLine.strip.length == 0)
            continue;
        EnvelopeItem item;
        item.header = parseJSON(headerLine);
        item.type = jstr(item.header, "type");
        if (auto len = "length" in item.header)
        {
            if (len.type != JSONType.integer || len.integer < 0 || len.integer > data.length - pos)
                throw new Exception("bad item length");
            auto n = cast(size_t) len.integer;
            item.payload = data[pos .. pos + n];
            pos += n;
            if (pos < data.length && data[pos] == '\n')
                pos++;
        }
        else
            item.payload = nextLine();
        env.items ~= item;
    }
    return env;
}

// ---- event normalization -------------------------------------------------------------

/// String field of a JSON object, or `dflt`.
string jstr(JSONValue v, string key, string dflt = null)
{
    if (v.type != JSONType.object)
        return dflt;
    auto p = key in v;
    return p && p.type == JSONType.string ? p.str : dflt;
}

/// Cuts `s` to at most `n` bytes without splitting a UTF-8 sequence.
string truncate(string s, size_t n)
{
    if (s.length <= n)
        return s;
    while (n > 0 && (s[n] & 0xC0) == 0x80)
        n--;
    return s[0 .. n];
}

private JSONValue exceptionValues(JSONValue ev)
{
    if (auto ex = "exception" in ev)
    {
        JSONValue vals = *ex;
        if (vals.type == JSONType.object && "values" in vals)
            vals = vals["values"];
        if (vals.type == JSONType.array)
            return vals;
    }
    return JSONValue(cast(JSONValue[]) []);
}

/// Removes content hashes from bundle names (`main.3f9a2b1c.js` -> `main.js`): a `.`, `-`
/// or `_` followed by a run of at least 8 hex digits that ends at a `.` or the end.
/// Returns `f` itself (no allocation) when there is nothing to strip.
private string stripHashSegments(string f)
{
    char[] cleaned;
    size_t copied = 0;
    bool changed;
    for (size_t i = 0; i < f.length;)
    {
        if (f[i] == '.' || f[i] == '-' || f[i] == '_')
        {
            auto j = i + 1;
            while (j < f.length && isHexDigit(f[j]))
                j++;
            if (j - i - 1 >= 8 && (j == f.length || f[j] == '.'))
            {
                cleaned ~= f[copied .. i];
                copied = j;
                changed = true;
                i = j;
                continue;
            }
        }
        i++;
    }
    if (!changed)
        return f;
    cleaned ~= f[copied .. $];
    return assumeUnique(cleaned);
}

/// Strips query strings, hosts and bundle content hashes so deploys do not split issues.
string normalizeFilename(string f)
{
    foreach (c; ['?', '#'])
    {
        auto i = f.indexOf(c);
        if (i >= 0)
            f = f[0 .. i];
    }
    auto scheme = f.indexOf("://");
    if (scheme > 0 && scheme < 8)
    {
        auto slash = f[scheme + 3 .. $].indexOf('/');
        f = slash >= 0 ? f[scheme + 3 + slash .. $] : "";
    }
    return stripHashSegments(f);
}

private string frameKey(JSONValue f)
{
    auto file = normalizeFilename(jstr(f, "module", jstr(f, "filename", "?")));
    auto fn = jstr(f, "function", "?");
    auto key = file ~ "|" ~ fn;
    if (fn == "?" || fn.canFind("<anonymous>"))
        key ~= "|" ~ jstr(f, "context_line").strip;
    return key;
}

private JSONValue[] stackFrames(JSONValue exc)
{
    if (auto st = "stacktrace" in exc)
        if (st.type == JSONType.object && "frames" in *st && (*st)["frames"].type == JSONType.array)
            return (*st)["frames"].array;
    return null;
}

private bool inApp(JSONValue f)
{
    auto p = "in_app" in f;
    return p && p.type == JSONType.true_;
}

/// Replaces `%s`/`%d`/`%i`/`%r`/`%f` or `{}` placeholders with logentry params.
private string formatMessage(string msg, JSONValue params)
{
    if (params.type != JSONType.array)
        return msg;
    string r;
    size_t pi, i;
    string paramText(JSONValue p)
    {
        return p.type == JSONType.string ? p.str : p.toString;
    }
    while (i < msg.length)
    {
        bool isPct = msg[i] == '%' && i + 1 < msg.length && "sdirf".canFind(msg[i + 1]);
        bool isBrace = msg[i] == '{' && i + 1 < msg.length && msg[i + 1] == '}';
        if ((isPct || isBrace) && pi < params.array.length)
        {
            r ~= paramText(params.array[pi++]);
            i += 2;
        }
        else
            r ~= msg[i++];
    }
    return r;
}

struct Derived
{
    string fingerprint, title, culprit, level;
}

/// Computes grouping fingerprint, title, culprit and level for an event.
///
/// Like Sentry, exceptions group by the type plus the in-app stack (module and
/// function per frame, ignoring line numbers and bundle hashes); messages group
/// by their unformatted template so "user 1 not found" and "user 2 not found"
/// share an issue. A custom `fingerprint` may contain `{{ default }}`.
Derived derive(JSONValue ev)
{
    Derived d;
    d.level = jstr(ev, "level", "error");
    if (!["fatal", "error", "warning", "info", "debug"].canFind(d.level))
        d.level = "error";

    string basis, primaryType;
    auto excs = exceptionValues(ev);
    if (excs.array.length)
    {
        auto last = excs.array[$ - 1];
        primaryType = jstr(last, "type", "Error");
        auto value = jstr(last, "value", "");
        d.title = value.length ? primaryType ~ ": " ~ value : primaryType;

        foreach (exc; excs.array)
        {
            basis ~= jstr(exc, "type", "Error");
            auto frames = stackFrames(exc);
            JSONValue[] chosen;
            foreach (f; frames)
                if (f.type == JSONType.object && inApp(f))
                    chosen ~= f;
            if (!chosen.length)
                foreach (f; frames)
                    if (f.type == JSONType.object)
                        chosen ~= f;
            if (chosen.length)
            {
                // innermost 12 frames; the tail of the list is the call site
                foreach (f; chosen[chosen.length > 12 ? $ - 12 : 0 .. $])
                    basis ~= "\n" ~ frameKey(f);
            }
            else
                basis ~= "|" ~ jstr(exc, "value", "");
            basis ~= "\n--\n";
        }

        foreach_reverse (f; stackFrames(last))
            if (f.type == JSONType.object && (inApp(f) || d.culprit.length == 0))
            {
                d.culprit = jstr(f, "function", "?") ~ " in " ~ jstr(f, "module", jstr(f, "filename", "?"));
                if (inApp(f))
                    break;
            }
    }
    else
    {
        string tmpl = jstr(ev, "message");
        string formatted;
        if (auto le = "logentry" in ev)
        {
            tmpl = jstr(*le, "message", tmpl);
            formatted = jstr(*le, "formatted");
            if (!formatted.length && tmpl.length)
                formatted = formatMessage(tmpl, (*le).type == JSONType.object && "params" in *le ? (*le)["params"] : JSONValue.init);
        }
        if (auto m = "message" in ev)
            if (m.type == JSONType.object)
            {
                tmpl = jstr(*m, "message", tmpl);
                formatted = jstr(*m, "formatted", formatted);
            }
        if (!formatted.length)
            formatted = tmpl;
        d.title = formatted.length ? formatted : "<unlabeled event>";
        basis = tmpl.length ? tmpl : d.title;
    }
    if (!d.culprit.length)
        d.culprit = jstr(ev, "transaction", jstr(ev, "culprit"));

    auto defaultHash = md5Of(basis).toHexString.idup.toLower;
    d.fingerprint = defaultHash;

    if (auto fp = "fingerprint" in ev)
        if (fp.type == JSONType.array && fp.array.length)
        {
            string joined;
            bool custom;
            foreach (x; fp.array)
            {
                auto part = x.type == JSONType.string ? x.str : x.toString;
                switch (part.strip)
                {
                case "{{ default }}": part = defaultHash; break;
                case "{{ transaction }}": part = jstr(ev, "transaction"); custom = true; break;
                case "{{ type }}": part = primaryType; custom = true; break;
                case "{{ message }}": part = d.title; custom = true; break;
                default: custom = true; break;
                }
                joined ~= part ~ "|";
            }
            if (custom)
                d.fingerprint = md5Of(joined).toHexString.idup.toLower;
        }

    d.title = truncate(d.title, 255);
    d.culprit = truncate(d.culprit, 200);
    return d;
}

/// True for 32 hex characters (dashes ignored).
private bool validEventId(string id)
{
    auto s = id.replace("-", "");
    return s.length == 32 && s.all!isHexDigit;
}

struct EventMeta
{
    string environment, release;
    string tagsJson;
}

/// Environment, release and a flat tag object (SDK tags plus the built-ins).
EventMeta extractMeta(JSONValue ev)
{
    EventMeta m;
    m.environment = truncate(jstr(ev, "environment"), 64);
    m.release = truncate(jstr(ev, "release"), 200);
    if (!m.environment.length)
        m.environment = null;
    if (!m.release.length)
        m.release = null;

    JSONValue tags = parseJSON("{}");
    void put(string k, string v)
    {
        if (k.length && v.length && tags.object.length < 50)
            tags.object[truncate(k, 32)] = JSONValue(truncate(v, 200));
    }
    string text(JSONValue v)
    {
        return v.type == JSONType.string ? v.str : v.type == JSONType.integer || v.type == JSONType.float_
            || v.type == JSONType.true_ || v.type == JSONType.false_ ? v.toString : null;
    }
    if (auto t = "tags" in ev)
    {
        if (t.type == JSONType.object)
            foreach (k, v; t.object)
                put(k, text(v));
        else if (t.type == JSONType.array)
            foreach (pair; t.array)
                if (pair.type == JSONType.array && pair.array.length == 2 && pair.array[0].type == JSONType.string)
                    put(pair.array[0].str, text(pair.array[1]));
    }
    put("level", jstr(ev, "level"));
    put("environment", m.environment);
    put("release", m.release);
    put("server_name", jstr(ev, "server_name"));
    put("transaction", jstr(ev, "transaction"));
    if (auto u = "user" in ev)
        if (u.type == JSONType.object)
            put("user", jstr(*u, "email", jstr(*u, "username", jstr(*u, "id"))));
    m.tagsJson = tags.toString;
    return m;
}

// ---- storage ------------------------------------------------------------------------

/// Registers `release` for the project's organization (once per process and project).
/// `on conflict do nothing` keeps existing release rows unlocked, so concurrent workers
/// do not queue up behind each other on a popular release.
private void trackRelease(PgConnection c, int projectId, string release)
{
    auto key = projectId.to!string ~ "/" ~ release;
    if (key in knownReleases)
        return;
    query(c, `with p as (select organization_id from projects where id = $1::int),
        ins as (insert into releases (organization_id, version) select organization_id, $2 from p
                on conflict do nothing returning id),
        r as (select id from ins
              union all select r.id from releases r join p on p.organization_id = r.organization_id where r.version = $2)
        insert into release_projects (release_id, project_id) select id, $1::int from r on conflict do nothing`,
            [projectId.to!string, release]);
    if (knownReleases.length > 10_000)
        knownReleases = null;
    knownReleases[key] = true;
}

/// One claimed queue row: `projection` is the small JSON cut out of the payload (see worker.d).
struct QueuedEvent
{
    string queueId;
    int projectId;
    string eventId; // 32 hex characters
    string projection;
}

private struct Prepared
{
    string queueId;
    int projectId;
    string eventId;
    Derived derived;
    EventMeta meta;
    bool skip;
    string issueId;
}

private struct IssueGroup
{
    int projectId;
    string fingerprint, title, culprit, level;
    long events;
    string aliasIssue; // set when the fingerprint was merged into another issue
    string issueId;
}

private string[] sortedKeys(IssueGroup[string] groups)
{
    import std.algorithm : sort;
    auto keys = groups.keys;
    keys.sort();
    return keys;
}

/// Groups a batch of queued events into issues and stores them, in a fixed number of
/// statements however many events there are.
///
/// Events with the same fingerprint share one issue update (`count += n`), and issue rows
/// are always written in (project, fingerprint) order. Two workers therefore never wait
/// for each other in a cycle: a storm of one error costs one row update per batch, not one
/// per event, and a deadlock cannot form. The full payloads are copied from the queue rows
/// inside Postgres, so they never pass through D.
void storeEvents(PgConnection c, QueuedEvent[] batch)
{
    import std.algorithm : sort;
    if (batch.length == 0)
        return;

    auto items = new Prepared[](batch.length);
    foreach (i, ref q; batch)
    {
        auto ev = parseJSON(q.projection);
        items[i] = Prepared(q.queueId, q.projectId, q.eventId, derive(ev), extractMeta(ev));
    }

    // ---- skip duplicates: repeated within the batch, or already stored
    bool[string] seen;
    string[] checkProjects, checkEvents;
    foreach (ref it; items)
    {
        auto k = it.projectId.to!string ~ "|" ~ it.eventId;
        if (k in seen)
            it.skip = true;
        else
        {
            seen[k] = true;
            checkProjects ~= it.projectId.to!string;
            checkEvents ~= it.eventId;
        }
    }
    bool[string] stored;
    foreach (r; query(c, `select e.project_id, replace(e.event_id::text, '-', '')
            from events e join unnest($1::int[], $2::uuid[]) as t(p, ev) on e.project_id = t.p and e.event_id = t.ev`,
            [arrayLiteral(checkProjects), arrayLiteral(checkEvents)]))
        stored[r[0] ~ "|" ~ r[1]] = true;
    foreach (ref it; items)
        if (!it.skip && (it.projectId.to!string ~ "|" ~ it.eventId) in stored)
            it.skip = true;

    // ---- one group per distinct issue
    IssueGroup[string] groups;
    foreach (ref it; items)
    {
        if (it.skip)
            continue;
        auto k = it.projectId.to!string ~ "|" ~ it.derived.fingerprint;
        if (auto g = k in groups)
        {
            g.events++;
            g.level = it.derived.level;
        }
        else
            groups[k] = IssueGroup(it.projectId, it.derived.fingerprint, it.derived.title, it.derived.culprit, it.derived.level, 1);
    }
    if (groups.length == 0)
        return;

    // ---- merged fingerprints keep routing to the surviving issue
    {
        string[] ps, fs;
        foreach (k; sortedKeys(groups))
        {
            ps ~= groups[k].projectId.to!string;
            fs ~= groups[k].fingerprint;
        }
        foreach (r; query(c, `select f.project_id, replace(f.fingerprint::text, '-', ''), f.issue_id
                from issue_fingerprints f join unnest($1::int[], $2::uuid[]) as t(p, f) on f.project_id = t.p and f.fingerprint = t.f`,
                [arrayLiteral(ps), arrayLiteral(fs)]))
            groups[r[0] ~ "|" ~ r[1]].aliasIssue = r[2];
    }

    // ---- alias groups first (locked in id order), then fresh ones (in fingerprint order): every
    //      worker takes its locks in the same order
    {
        // several merged fingerprints can point at the same surviving issue: sum their events
        string[][string] keysByIssue;
        foreach (k; sortedKeys(groups))
            if (groups[k].aliasIssue !is null)
                keysByIssue[groups[k].aliasIssue] ~= k;
        if (keysByIssue.length)
        {
            auto sortedIds = keysByIssue.keys;
            sortedIds.sort!((x, y) => x.to!long < y.to!long);
            bool[string] alive;
            foreach (r; query(c, "select id from issues where id = any($1::bigint[]) order by id for update", [arrayLiteral(sortedIds)]))
                alive[r[0]] = true;
            string[] ids, counts, levels;
            foreach (id; sortedIds)
            {
                long total;
                string level;
                foreach (k; keysByIssue[id])
                {
                    if (id !in alive)
                    {
                        groups[k].aliasIssue = null; // the target issue is gone: treat as a fresh fingerprint
                        continue;
                    }
                    groups[k].issueId = id;
                    total += groups[k].events;
                    level = groups[k].level;
                }
                if (id in alive)
                {
                    ids ~= id;
                    counts ~= total.to!string;
                    levels ~= level;
                }
            }
            if (ids.length)
                query(c, `update issues set count = issues.count + t.n, last_seen = now(), level = t.level,
                        status = case when issues.status = 'resolved' then 'unresolved' else issues.status end
                    from unnest($1::bigint[], $2::int[], $3::text[]) as t(id, n, level) where issues.id = t.id`,
                        [arrayLiteral(ids), arrayLiteral(counts), arrayLiteral(levels)]);
        }
    }
    {
        string[] ps, fs, titles, culprits, levels, counts;
        foreach (k; sortedKeys(groups))
        {
            auto g = groups[k];
            if (g.issueId !is null)
                continue;
            ps ~= g.projectId.to!string;
            fs ~= g.fingerprint;
            titles ~= g.title;
            culprits ~= g.culprit;
            levels ~= g.level;
            counts ~= g.events.to!string;
        }
        if (ps.length)
            foreach (r; query(c, `insert into issues (project_id, fingerprint, title, culprit, level, count)
                    select t.p, t.f, t.title, t.culprit, t.level, t.n
                    from unnest($1::int[], $2::uuid[], $3::text[], $4::text[], $5::text[], $6::int[]) as t(p, f, title, culprit, level, n)
                    order by t.p, t.f
                    on conflict (project_id, fingerprint) do update
                        set count = issues.count + excluded.count, last_seen = now(), level = excluded.level,
                            status = case when issues.status = 'resolved' then 'unresolved' else issues.status end
                    returning project_id, replace(fingerprint::text, '-', ''), id`,
                    [arrayLiteral(ps), arrayLiteral(fs), arrayLiteral(titles), arrayLiteral(culprits), arrayLiteral(levels), arrayLiteral(counts)]))
                groups[r[0] ~ "|" ~ r[1]].issueId = r[2];
    }

    // ---- events: payloads are copied from the queue rows inside Postgres. The event id and the
    //      client IP are only patched into the jsonb when needed, because a patch rewrites the
    //      whole 30+ KB value
    {
        string[] eventIds, issueIds, queueIds, hexIds, envs, releases, tags;
        foreach (ref it; items)
        {
            if (it.skip)
                continue;
            it.issueId = groups[it.projectId.to!string ~ "|" ~ it.derived.fingerprint].issueId;
            eventIds ~= it.eventId;
            issueIds ~= it.issueId;
            queueIds ~= it.queueId;
            hexIds ~= it.eventId;
            envs ~= it.meta.environment;
            releases ~= it.meta.release;
            tags ~= it.meta.tagsJson;
        }
        auto inserted = query(c, `insert into events (event_id, issue_id, project_id, data, environment, release, tags)
            select t.ev, t.issue, q.project_id,
                   case when q.payload ->> 'event_id' = t.hex then b.base else jsonb_set(b.base, '{event_id}', to_jsonb(t.hex)) end,
                   t.env, t.rel, t.tags::jsonb
            from unnest($1::uuid[], $2::bigint[], $3::bigint[], $4::text[], $5::text[], $6::text[], $7::text[]) as t(ev, issue, qid, hex, env, rel, tags)
            join ingest_queue q on q.id = t.qid
            cross join lateral (select case when q.client_ip is not null and q.payload #>> '{user,ip_address}' = '{{auto}}'
                                            then jsonb_set(q.payload, '{user,ip_address}', to_jsonb(q.client_ip))
                                            else q.payload end as base) b
            on conflict do nothing
            returning replace(event_id::text, '-', '')`,
                [arrayLiteral(eventIds), arrayLiteral(issueIds), arrayLiteral(queueIds), arrayLiteral(hexIds),
                 arrayLiteral(envs), arrayLiteral(releases), arrayLiteral(tags)]);

        // The "already stored?" check above cannot see an identical event another worker is storing
        // right now. Such a duplicate is dropped by the unique index; take it back off the issue
        // count we already added (this transaction holds that issue's row lock).
        if (inserted.length != eventIds.length)
        {
            bool[string] ok;
            foreach (r; inserted)
                ok[r[0]] = true;
            long[string] lost;
            foreach (ref it; items)
                if (!it.skip && it.eventId !in ok)
                    lost[it.issueId]++;
            string[] ids, counts;
            foreach (id; lost.keys)
            {
                ids ~= id;
                counts ~= lost[id].to!string;
            }
            query(c, `update issues set count = greatest(issues.count - t.n, 0)
                from unnest($1::bigint[], $2::int[]) as t(id, n) where issues.id = t.id`,
                    [arrayLiteral(ids), arrayLiteral(counts)]);
        }
    }

    // ---- releases seen for the first time (sorted, so concurrent workers lock in the same order)
    bool[string] wanted;
    foreach (ref it; items)
        if (!it.skip && it.meta.release.length)
            wanted[it.projectId.to!string ~ "/" ~ it.meta.release] = true;
    auto releaseKeys = wanted.keys;
    releaseKeys.sort();
    foreach (k; releaseKeys)
    {
        auto slash = k.indexOf('/');
        trackRelease(c, k[0 .. slash].to!int, k[slash + 1 .. $]);
    }
}

/// Stores an envelope `user_report` item.
void storeUserReport(int projectId, JSONValue report)
{
    auto id = jstr(report, "event_id");
    auto comments = jstr(report, "comments").strip;
    if (!validEventId(id) || !comments.length)
        return;
    query(`insert into user_feedback (project_id, event_id, name, email, comments)
        values ($1::int, $2::uuid, $3, $4, $5)`,
            [projectId.to!string, id, truncate(jstr(report, "name"), 128), truncate(jstr(report, "email"), 254),
             truncate(comments, 8000)]);
}

/// Stores an envelope `attachment` item (silently drops oversized ones).
void storeAttachment(int projectId, string eventId, EnvelopeItem item)
{
    if (!validEventId(eventId) || item.payload.length == 0 || item.payload.length > maxAttachmentBytes)
        return;
    static immutable digits = "0123456789abcdef";
    auto hex = new char[2 + item.payload.length * 2];
    hex[0] = '\\';
    hex[1] = 'x';
    foreach (i, ch; cast(const(ubyte)[]) item.payload)
    {
        hex[2 + 2 * i] = digits[ch >> 4];
        hex[3 + 2 * i] = digits[ch & 15];
    }
    auto name = truncate(jstr(item.header, "filename", "attachment"), 200);
    query(`insert into event_attachments (project_id, event_id, name, content_type, size, data)
        values ($1::int, $2::uuid, $3, $4, $5::int, $6::bytea)`,
            [projectId.to!string, eventId, name, truncate(jstr(item.header, "content_type"), 100),
             item.payload.length.to!string, assumeUnique(hex)]);
}
