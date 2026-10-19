module bench;

// Allocation benchmark for the CPU-side event pipeline (no database needed).
//   dub build -c bench --compiler=ldc2 -b release && ./glitchtip-bench

import core.memory : GC;
import std.json;
import std.stdio;
import std.conv : to;
import std.format : format;
import std.datetime.stopwatch : StopWatch, AutoStart;
import ingest;

/// A realistic Python-SDK event: deep stack with locals and source context,
/// breadcrumbs, request data and the installed-module list.
string sampleEvent()
{
    JSONValue ev = parseJSON("{}");
    ev["event_id"] = "fc6d8c0c43fc4630ad850ee518f1b9d0";
    ev["level"] = "error";
    ev["platform"] = "python";
    ev["release"] = "1.4.2";
    ev["environment"] = "production";
    ev["server_name"] = "web-7";
    ev["transaction"] = "/api/orders";
    ev["tags"] = parseJSON(`{"browser":"Chrome 120","os":"Linux","runtime":"CPython 3.12"}`);
    ev["user"] = parseJSON(`{"id":"42","email":"ann@example.com","ip_address":"{{auto}}"}`);
    JSONValue[] frames;
    foreach (i; 0 .. 25)
    {
        JSONValue f = parseJSON("{}");
        f["filename"] = "app/services/module_%s.py".format(i);
        f["abs_path"] = "/srv/app/app/services/module_%s.py".format(i);
        f["module"] = "app.services.module_%s".format(i);
        f["function"] = "handle_%s".format(i);
        f["lineno"] = 100 + i;
        f["in_app"] = i > 5;
        f["pre_context"] = ["    x = compute()", "    y = other(x)", "    log.info('step')"];
        f["context_line"] = "    return process(x, y, request.session['user'])  # line %s".format(i);
        f["post_context"] = ["", "def next_function():"];
        JSONValue vars = parseJSON("{}");
        foreach (j; 0 .. 10)
            vars["variable_%s".format(j)] = "'some local value number %s in frame %s'".format(j, i);
        f["vars"] = vars;
        frames ~= f;
    }
    ev["exception"] = parseJSON(`{"values":[{"type":"ValueError","value":"invalid literal for int()","mechanism":{"type":"django","handled":false}}]}`);
    ev["exception"]["values"][0]["stacktrace"] = parseJSON(`{"frames":[]}`);
    ev["exception"]["values"][0]["stacktrace"]["frames"] = JSONValue(frames);
    JSONValue[] crumbs;
    foreach (i; 0 .. 50)
        crumbs ~= parseJSON(`{"timestamp":"2026-10-19T10:00:%02d.000Z","category":"query","level":"info","message":"SELECT * FROM table_%s WHERE id = %s","data":{"duration":1.5}}`.format(i % 60, i, i));
    ev["breadcrumbs"] = parseJSON(`{"values":[]}`);
    ev["breadcrumbs"]["values"] = JSONValue(crumbs);
    ev["request"] = parseJSON(`{"url":"https://example.com/api/orders","method":"POST","headers":{"User-Agent":"Mozilla/5.0","Accept":"*/*","Cookie":"[Filtered]"},"data":{"items":[1,2,3]}}`);
    string[] mods;
    foreach (i; 0 .. 200)
        mods ~= "package-%s==1.%s.0".format(i, i % 10);
    ev["modules"] = JSONValue(mods);
    return ev.toString;
}

struct Result
{
    string name;
    double bytes, usecs;
}

Result measure(string name, int iterations, scope void delegate() dg)
{
    dg(); // warm up (static init, regex)
    GC.collect();
    immutable before = GC.allocatedInCurrentThread();
    auto sw = StopWatch(AutoStart.yes);
    foreach (_; 0 .. iterations)
        dg();
    sw.stop();
    return Result(name, cast(double)(GC.allocatedInCurrentThread() - before) / iterations,
            sw.peek.total!"usecs" / cast(double) iterations);
}

void main()
{
    auto payload = sampleEvent();
    auto envelope = `{"event_id":"fc6d8c0c43fc4630ad850ee518f1b9d0"}` ~ "\n" ~ `{"type":"event","length":` ~ payload.length.to!string ~ "}\n" ~ payload ~ "\n";
    auto ev = parseJSON(payload);
    writefln("sample event: %s bytes", payload.length);

    enum n = 300;
    Result[] rs;
    auto raw = cast(ubyte[]) payload.dup;
    rs ~= measure("decodeBody (no compression)", n, { auto b = decodeBody(raw, ""); });
    rs ~= measure("parseEnvelope", n, { auto e = parseEnvelope(envelope); });
    rs ~= measure("parseJSON(event)            [was: intake + worker]", n, { auto e = parseJSON(payload); });
    rs ~= measure("ev.toString                 [was: intake + store]", n, { auto s = ev.toString; });
    rs ~= measure("normalizeFilename (hashed bundle)", n, { auto f = normalizeFilename("https://cdn.io/static/main.3f9a2b1c.js?v=3"); });
    rs ~= measure("normalizeFilename (plain path)", n, { auto f = normalizeFilename("app/services/module_1.py"); });
    rs ~= measure("derive (fingerprint/title)", n, { auto d = derive(ev); });
    rs ~= measure("extractMeta (tags)", n, { auto m = extractMeta(ev); });
    double total = 0;
    foreach (r; rs)
        writefln("%-46s %10.0f B/op %9.1f us/op", r.name, r.bytes, r.usecs);
}
