module app;

import vibe.vibe;
import std.json : parseJSON, JSONValue;
import std.process : environment;
import std.conv : to;
import std.string : startsWith;
import db;
import ingest : maxAttachmentBytes, maxBodyBytes;
import intake : keyCacheSeconds;
import api;
import intake;
import sentry_api;
import manage_api;
import worker;
import core.memory : GC;
import core.time : seconds;

void sendJson(HTTPServerResponse res, string json, int status = 200) @trusted
{
    res.statusCode = status;
    res.writeBody(json, "application/json");
}

/// Logs collector activity every `interval` seconds (GC_STATS_INTERVAL). Pauses stop
/// every thread, so a rising pause total is the number to watch.
void gcStatsLoop(int interval) nothrow
{
    for (;;)
    {
        try
        {
            sleep(interval.seconds);
            auto p = GC.profileStats();
            auto st = GC.stats();
            logInfo("gc: collections=%s pause_total=%sms pause_max=%sms collect_total=%sms heap_used=%sMB heap_free=%sMB",
                    p.numCollections, p.totalPauseTime.total!"msecs", p.maxPauseTime.total!"msecs",
                    p.totalCollectionTime.total!"msecs", st.usedSize >> 20, st.freeSize >> 20);
        }
        catch (Exception) {}
    }
}

enum indexHtml = import("index.html");

void main()
{
    auto port = environment.get("PORT", "8000").to!ushort;
    publicUrl = environment.get("PUBLIC_URL", "http://localhost:" ~ port.to!string);
    secureCookies = publicUrl.startsWith("https");
    trustProxy = environment.get("TRUST_PROXY", "false") == "true";
    immutable bindAddress = environment.get("BIND_ADDRESS", "0.0.0.0");
    registrationOpen = environment.get("ENABLE_REGISTRATION", "false") == "true";
    maxAttachmentBytes = environment.get("MAX_ATTACHMENT_BYTES", "1048576").to!long;
    keyCacheSeconds = environment.get("KEY_CACHE_SECONDS", "30").to!long;
    immutable gcStatsInterval = environment.get("GC_STATS_INTERVAL", "0").to!int;
    immutable workers = environment.get("WORKERS", "2").to!int;
    immutable retentionDays = environment.get("RETENTION_DAYS", "90").to!int;
    immutable cleanupMinutes = environment.get("CLEANUP_INTERVAL_MINUTES", "60").to!int;

    auto router = new URLRouter;
    router.get("/health", (HTTPServerRequest req, HTTPServerResponse res) @trusted { res.sendJson(`{"status":"ok"}`); });
    registerIntake(router);
    registerRoutes(router);
    registerSentryRoutes(router);
    registerManageRoutes(router);
    router.get("*", (HTTPServerRequest req, HTTPServerResponse res) @trusted {
        if (req.path.startsWith("/api/"))
            throw new HTTPStatusException(404, "Not found.");
        res.headers["X-Frame-Options"] = "DENY";
        res.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
        res.writeBody(indexHtml, "text/html; charset=utf-8");
    });

    auto settings = new HTTPServerSettings;
    settings.port = port;
    settings.bindAddresses = [bindAddress];
    settings.maxRequestSize = maxBodyBytes;
    settings.errorPageHandler = (HTTPServerRequest req, HTTPServerResponse res, HTTPServerErrorInfo err) @trusted {
        if (err.code >= 500 && err.exception)
            logError("%s %s: %s", req.method, req.requestURI, err.exception.toString());
        res.writeBody(`{"detail":` ~ serializeToJsonString(err.code >= 500 ? "Internal server error." : err.exception ? err.exception.msg : "Error")
                ~ `}`, "application/json");
    };
    // The Postgres driver is fiber based: all database access must happen inside the event loop.
    runTask({
        try
        {
            initDb();
            startBackground(workers, retentionDays, cleanupMinutes);
            if (trustProxy && bindAddress != "127.0.0.1" && bindAddress != "::1")
                logWarn("TRUST_PROXY is on but BIND_ADDRESS=%s: clients that reach the port directly can forge X-Real-IP and "
                        ~ "X-Forwarded-Proto. Bind to 127.0.0.1 or firewall the port.", bindAddress);
            if (gcStatsInterval > 0)
                runTask(&gcStatsLoop, gcStatsInterval);
            listenHTTP(settings, router);
            logInfo("glitchtip-d listening on :%s", port);
        }
        catch (Exception e)
        {
            logError("startup failed: %s", e.msg);
            exitEventLoop(true);
        }
    });
    runApplication();
}
