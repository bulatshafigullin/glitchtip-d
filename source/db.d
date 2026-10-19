module db;

import postgrex;
import core.time : seconds;
import std.process : environment;

// Pools belong to the thread (and event loop) that created them, so every
// thread gets its own, created on first use. Module variables are thread-local.
private PgPool threadPool;

private ConnectOptions options()
{
    auto url = environment.get("DATABASE_URL", "postgres://" ~ environment.get("USER", "postgres") ~ "@/glitchtip_d?host=/tmp");
    auto o = ConnectOptions.fromUrl(url);
    o.connectTimeout = 5.seconds;
    o.queryTimeout = 60.seconds;
    o.statementTimeout = 30.seconds;
    return o;
}

PgPool pool() @trusted
{
    if (threadPool is null)
        threadPool = new PgPool(options(), 8);
    return threadPool;
}

/// Applies the bundled schema. Must run inside the event loop.
void initDb() @trusted
{
    pool().simpleQuery(import("schema.sql"));
}

private const(Param)[] toParams(string[] args)
{
    auto ps = new Param[](args.length);
    foreach (i, a; args)
        ps[i] = a is null ? Param.null_ : Param.of(a); // a null string is SQL NULL
    return ps;
}

/// Runs a statement with text parameters ($1, $2, ...) and returns every cell as a
/// string (booleans as "t"/"f", NULL as null; cast timestamps etc. to text if you need
/// a specific format). Cells alias the result buffer, so reading them copies nothing.
string[][] query(PgConnection c, string sql, string[] args = null) @trusted
{
    auto res = c.queryParams(sql, toParams(args));
    immutable cols = res.columns.length;
    auto rows = new string[][](res.length);
    foreach (i; 0 .. res.length)
    {
        auto src = res[i];
        auto row = new string[](cols);
        foreach (j; 0 .. cols)
            row[j] = src.isNull(j) ? null : src.get!string(j);
        rows[i] = row;
    }
    return rows;
}

/// Same, on a connection checked out of this thread's pool.
string[][] query(string sql, string[] args = null) @trusted
{
    auto c = pool().lock();
    return query(c, sql, args);
}

/// Returns the single text value produced by a query that yields JSON.
string queryJson(string sql, string[] args = null) @trusted
{
    auto rows = query(sql, args);
    return rows.length ? rows[0][0] : "null";
}

/// Builds a Postgres text-array literal (`{"a","b",NULL}`) for `$n::type[]` parameters, so a
/// whole batch travels in one statement. Elements are quoted and escaped; null becomes NULL.
string arrayLiteral(const(string)[] items) @trusted
{
    import std.array : appender;
    auto sink = appender!string();
    sink.put('{');
    foreach (i, item; items)
    {
        if (i)
            sink.put(',');
        if (item is null)
        {
            sink.put("NULL");
            continue;
        }
        sink.put('"');
        foreach (ch; item)
        {
            if (ch == '"' || ch == '\\')
                sink.put('\\');
            sink.put(ch);
        }
        sink.put('"');
    }
    sink.put('}');
    return sink.data;
}
