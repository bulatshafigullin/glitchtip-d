module intake;

import vibe.vibe;
import std.json : JSONValue, parseJSON;
import std.conv : to;
import std.string : split, toLower, indexOf, startsWith, endsWith, strip;
import std.utf : validate;
import std.datetime : Clock, UTC;
import db;
import ingest;
import worker : enqueueRaw;
import api : clientIp;

struct KeyInfo
{
    bool ok;
    int projectId; // the real project (the URL id may be an alias)
    string id;
    long limit, window;
    string[] origins;
}

private struct Bucket
{
    long start;
    long count;
}

// All ingest handlers run on the HTTP thread, so a plain thread-local map is
// enough. Limits are per process: they are not shared between server instances.
private Bucket[string] buckets;

/// Browser SDKs post cross-origin, so ingest responses (including errors) must carry CORS headers.
void cors(HTTPServerResponse res) @trusted
{
    res.headers["Access-Control-Allow-Origin"] = "*";
    res.headers["Access-Control-Expose-Headers"] = "X-Sentry-Error, X-Sentry-Rate-Limits, Retry-After";
}

void preflight(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    cors(res);
    res.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    res.headers["Access-Control-Allow-Headers"] =
        "X-Sentry-Auth, X-Requested-With, Origin, Accept, Content-Type, Authentication, Authorization, Content-Encoding, sentry-trace, baggage";
    res.headers["Access-Control-Max-Age"] = "3600";
    res.statusCode = 204;
    res.writeBody("");
}

private string hostOf(string origin)
{
    auto s = origin.toLower;
    auto i = s.indexOf("://");
    if (i >= 0)
        s = s[i + 3 .. $];
    auto slash = s.indexOf('/');
    if (slash >= 0)
        s = s[0 .. slash];
    return s;
}

/// Matches an Origin against allowed entries: `*`, `*.example.com`, a host (with or
/// without port), or a full origin. An empty list or a missing Origin allows everything.
bool originAllowed(string[] allowed, string origin)
{
    if (allowed.length == 0 || origin.length == 0)
        return true;
    auto host = hostOf(origin);
    auto hostNoPort = host.indexOf(':') >= 0 ? host[0 .. host.indexOf(':')] : host;
    foreach (a; allowed)
    {
        auto e = a.strip.toLower;
        if (e == "*")
            return true;
        if (e.startsWith("*."))
        {
            if (hostNoPort.endsWith(e[1 .. $]) || hostNoPort == e[2 .. $])
                return true;
        }
        else if (e == origin.toLower || e == host || e == hostNoPort || hostOf(e) == host)
            return true;
    }
    return false;
}

private void reject(HTTPServerResponse res, int status, string detail) @trusted
{
    res.statusCode = status;
    res.headers["X-Sentry-Error"] = detail;
    res.writeBody(`{"detail":` ~ serializeToJsonString(detail) ~ `}`, "application/json");
}

private struct CachedKey
{
    KeyInfo info;
    long expires;
}

/// DSN keys by "projectId/key", kept for `keyCacheSeconds` so the hot ingest path does not hit
/// the database on every request. Two generations give cheap approximate-LRU eviction without
/// per-entry bookkeeping: when the young map fills up it becomes the old one. Only valid keys
/// are cached. Changes made through this instance's API evict immediately; other instances see
/// them after at most the TTL. Thread-local, and all ingest handlers run on the HTTP thread.
__gshared long keyCacheSeconds = 30;
private CachedKey[string] keyCache, keyCacheOld;
private enum keyCacheCapacity = 5000;

/// Forgets every cached key (call after changing keys, rate limits, origins or deleting projects).
void invalidateKeyCache() @trusted
{
    keyCache = null;
    keyCacheOld = null;
}

private bool cachedKey(string ck, long now, ref KeyInfo k) @trusted
{
    if (auto e = ck in keyCache)
    {
        if (e.expires > now)
        {
            k = e.info;
            return true;
        }
    }
    else if (auto e = ck in keyCacheOld)
    {
        if (e.expires > now)
        {
            k = e.info;
            keyCache[ck] = *e; // promote: recently used
            return true;
        }
    }
    return false;
}

/// Validates the DSN key, project and allowed origin. Writes the error response on failure.
KeyInfo checkKey(HTTPServerRequest req, HTTPServerResponse res, int projectId) @trusted
{
    KeyInfo k;
    auto key = parseSentryKey(req.headers.get("X-Sentry-Auth", ""), req.query.get("sentry_key", ""));
    if (key.length == 0)
    {
        reject(res, 401, "Missing sentry_key");
        return k;
    }
    immutable now = Clock.currTime(UTC()).toUnixTime;
    immutable ck = projectId.to!string ~ "/" ~ key;
    if (keyCacheSeconds <= 0 || !cachedKey(ck, now, k))
    {
        string[][] rows;
        try
            rows = query(`select id::text, coalesce(rate_limit_count, 0)::text, coalesce(rate_limit_window, 0)::text,
                    array_to_string(allowed_origins, chr(10)), project_id::text
                from project_keys where public_key = $2::uuid and is_active
                  and project_id = coalesce((select project_id from project_aliases where alias_id = $1::int), $1::int)`,
                    [projectId.to!string, key]);
        catch (Exception) {} // malformed uuid
        if (!rows.length)
        {
            reject(res, 403, "Invalid sentry_key");
            return k;
        }
        k.id = rows[0][0];
        k.limit = rows[0][1].to!long;
        k.window = rows[0][2].to!long;
        k.origins = rows[0][3].length ? rows[0][3].split("\n") : null;
        k.projectId = rows[0][4].to!int;
        if (keyCacheSeconds > 0)
        {
            if (keyCache.length >= keyCacheCapacity)
            {
                keyCacheOld = keyCache;
                keyCache = null;
            }
            keyCache[ck] = CachedKey(k, now + keyCacheSeconds);
        }
    }
    if (!originAllowed(k.origins, req.headers.get("Origin", "")))
    {
        k = KeyInfo.init;
        reject(res, 403, "Origin not allowed");
        return k;
    }
    k.ok = true;
    return k;
}

/// Counts `n` events against the key's limit; answers 429 and returns false when exceeded.
bool underLimit(KeyInfo k, long n, HTTPServerResponse res) @trusted
{
    if (k.limit <= 0 || n == 0)
        return true;
    immutable now = Clock.currTime(UTC()).toUnixTime;
    auto b = buckets.get(k.id, Bucket(now, 0));
    if (now - b.start >= k.window)
        b = Bucket(now, 0);
    if (b.count + n > k.limit)
    {
        auto retry = k.window - (now - b.start);
        res.headers["Retry-After"] = retry.to!string;
        res.headers["X-Sentry-Rate-Limits"] = retry.to!string ~ ":error:key";
        reject(res, 429, "Rate limit exceeded");
        return false;
    }
    b.count += n;
    if (buckets.length > 10_000)
        buckets = null;
    buckets[k.id] = b;
    return true;
}

private ubyte[] readBody(HTTPServerRequest req) @trusted
{
    try
        return decodeBody(req.bodyReader.readAll(), req.headers.get("Content-Encoding", ""));
    catch (PayloadTooLargeException)
        throw new HTTPStatusException(413, "Payload too large.");
}

/// Parses a small JSON payload (user reports); rejects invalid UTF-8.
private JSONValue parseJson(const(char)[] text) @trusted
{
    try
    {
        validate(text);
        return parseJSON(text);
    }
    catch (Exception)
        throw new HTTPStatusException(400, "Invalid JSON payload.");
}

/// Queues an event without parsing it: the payload bytes go to Postgres as they are.
private string queueEvent(HTTPServerRequest req, int pid, const(char)[] payload, string fallbackId = null) @trusted
{
    // the body buffer is never modified after this point, so viewing it as a string is safe
    auto id = enqueueRaw(pid, cast(string) payload, clientIp(req), fallbackId);
    if (id is null)
        throw new HTTPStatusException(400, "Invalid event payload.");
    return id;
}

private void respondId(HTTPServerResponse res, string id) @trusted
{
    res.writeBody(id.length ? `{"id":"` ~ id ~ `"}` : `{}`, "application/json");
}

void handleStore(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    cors(res);
    int pid = req.params["project_id"].to!int;
    auto k = checkKey(req, res, pid);
    if (!k.ok || !underLimit(k, 1, res))
        return;
    respondId(res, queueEvent(req, k.projectId, cast(const(char)[]) readBody(req)));
}

/// Event-like item types that are accepted but not stored (yet).
private bool ignoredItem(string type)
{
    switch (type)
    {
    case "session", "sessions", "transaction", "client_report", "check_in", "profile", "replay_event",
         "replay_recording", "statsd", "metric_buckets", "span", "log", "feedback":
        return true;
    default:
        return false;
    }
}

void handleEnvelope(HTTPServerRequest req, HTTPServerResponse res) @trusted
{
    cors(res);
    int pid = req.params["project_id"].to!int;
    auto k = checkKey(req, res, pid);
    if (!k.ok)
        return;
    Envelope env;
    try
        env = parseEnvelope(cast(string) readBody(req));
    catch (Exception)
        throw new HTTPStatusException(400, "Invalid envelope.");

    long events;
    foreach (item; env.items)
        if (item.type == "event")
            events++;
    if (!underLimit(k, events, res))
        return;

    auto headerId = jstr(env.header, "event_id");
    string lastId;
    foreach (item; env.items)
    {
        if (item.type == "event")
            lastId = queueEvent(req, k.projectId, item.payload, headerId);
        else if (item.type == "user_report")
            storeUserReport(k.projectId, parseJson(item.payload));
        else if (item.type == "attachment")
            storeAttachment(k.projectId, headerId.length ? headerId : lastId, item);
        // other known types are acknowledged and dropped, unknown types too
    }
    respondId(res, lastId.length ? lastId : headerId);
}

void registerIntake(URLRouter router)
{
    foreach (path; ["/api/:project_id/store/", "/api/:project_id/envelope/"])
        router.match(HTTPMethod.OPTIONS, path, &preflight);
    router.post("/api/:project_id/store/", &handleStore);
    router.post("/api/:project_id/envelope/", &handleEnvelope);
}
