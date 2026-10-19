module worker;

import vibe.core.core : sleep, runWorkerTask, setupWorkerThreads;
import vibe.core.log;
import core.time : msecs, seconds, minutes;
import std.json;
import std.conv : to;
import std.array : replace;
import std.string : startsWith;
import postgrex : PgConnection, PgServerException;
import db;
import ingest : storeEvents, QueuedEvent;

enum batchSize = 50;
enum maxAttempts = 5;

/// Queues a raw event payload without parsing it in D: Postgres validates the JSON,
/// keeps it as jsonb and picks the event id (the payload's own, else `fallbackId`, else
/// a fresh one). Returns the 32-hex event id, or null when the payload is not a JSON object.
string enqueueRaw(int projectId, string payload, string clientIp, string fallbackId) @trusted
{
    try
    {
        auto rows = query(`insert into ingest_queue (project_id, event_id, client_ip, payload)
            select $1::int, coalesce(gt_valid_event_id(j ->> 'event_id'), gt_valid_event_id($4), gen_random_uuid()), $3, j
            from (select $2::jsonb as j) s where jsonb_typeof(j) = 'object'
            returning replace(event_id::text, '-', '')`, [projectId.to!string, payload, clientIp, fallbackId]);
        return rows.length ? rows[0][0] : null;
    }
    catch (PgServerException e)
    {
        // class 22 = data exception (malformed JSON, bad \u escape, invalid UTF-8), 54 = limit exceeded
        if (e.code.startsWith("22") || e.code.startsWith("54"))
            return null;
        throw e;
    }
}

/// The few fields grouping needs, cut out of the stored jsonb inside Postgres. A 35 KB event
/// with locals, breadcrumbs and module lists shrinks to a couple of KB, so the worker's
/// JSON parse (the biggest allocator in the pipeline) stays small. Keep in sync with
/// `derive` and `extractMeta` in ingest.d.
private enum projectionSql = `jsonb_build_object(
    'level', q.payload -> 'level', 'message', q.payload -> 'message', 'logentry', q.payload -> 'logentry',
    'transaction', q.payload -> 'transaction', 'culprit', q.payload -> 'culprit', 'fingerprint', q.payload -> 'fingerprint',
    'environment', q.payload -> 'environment', 'release', q.payload -> 'release', 'server_name', q.payload -> 'server_name',
    'tags', q.payload -> 'tags',
    'user', jsonb_build_object('email', q.payload #> '{user,email}', 'username', q.payload #> '{user,username}', 'id', q.payload #> '{user,id}'),
    'exception', (select jsonb_agg(jsonb_build_object('type', v.val -> 'type', 'value', v.val -> 'value',
            'stacktrace', jsonb_build_object('frames', coalesce((
                select jsonb_agg(jsonb_build_object('module', f.val -> 'module', 'filename', f.val -> 'filename',
                        'function', f.val -> 'function', 'in_app', f.val -> 'in_app', 'context_line', f.val -> 'context_line') order by f.ord)
                from jsonb_array_elements(case when jsonb_typeof(v.val #> '{stacktrace,frames}') = 'array'
                                               then v.val #> '{stacktrace,frames}' else '[]'::jsonb end) with ordinality as f(val, ord)
                where jsonb_typeof(f.val) = 'object'), '[]'::jsonb))) order by v.ord)
        from jsonb_array_elements(case when jsonb_typeof(q.payload -> 'exception') = 'array' then q.payload -> 'exception'
                                       when jsonb_typeof(q.payload #> '{exception,values}') = 'array' then q.payload #> '{exception,values}'
                                       else '[]'::jsonb end) with ordinality as v(val, ord)
        where jsonb_typeof(v.val) = 'object'))`;

/// Deadlocks, serialization failures and lock timeouts are not the event's fault: retry the
/// batch later without counting an attempt against any event.
private bool isTransient(Exception e)
{
    auto pe = cast(PgServerException) e;
    return pe !is null && (pe.code == "40P01" || pe.code == "40001" || pe.code == "55P03");
}

/// After a batch fails for a non-transient reason, the next one runs row by row so the bad
/// event is found and the rest are stored.
private bool isolateNext;

private enum retryNow = batchSize; // processBatch result that makes the worker loop again without sleeping

/// Claims up to one batch and stores it in a single transaction. Returns the number of
/// queue rows handled (`retryNow` when it should simply be called again).
size_t processBatch() @trusted
{
    import std.random : uniform;
    size_t handled;
    immutable isolate = isolateNext;
    try
    {
        pool().transaction((PgConnection c) @trusted {
            auto rows = query(c, `select q.id, q.project_id, replace(coalesce(q.event_id, gen_random_uuid())::text, '-', ''),
                    q.attempts, ` ~ projectionSql ~ `::text
                from ingest_queue q order by q.id limit ` ~ batchSize.to!string ~ ` for update of q skip locked`);
            if (rows.length == 0)
                return;
            string[] ids;
            foreach (r; rows)
                ids ~= r[0];

            if (!isolate)
            {
                QueuedEvent[] batch;
                foreach (r; rows)
                    batch ~= QueuedEvent(r[0], r[1].to!int, r[2], r[4]);
                storeEvents(c, batch);
                query(c, "delete from ingest_queue where id = any($1::bigint[])", [arrayLiteral(ids)]);
            }
            else
                foreach (r; rows)
                {
                    try
                    {
                        // its own savepoint: a failing event rolls back alone
                        c.transaction((PgConnection c2) @trusted { storeEvents(c2, [QueuedEvent(r[0], r[1].to!int, r[2], r[4])]); });
                        query(c, "delete from ingest_queue where id = $1::bigint", [r[0]]);
                    }
                    catch (Exception e)
                    {
                        if (isTransient(e))
                            throw e;
                        if (r[3].to!int + 1 >= maxAttempts)
                        {
                            logError("dropping queued event %s after %s attempts: %s", r[0], maxAttempts, e.msg);
                            query(c, "delete from ingest_queue where id = $1::bigint", [r[0]]);
                        }
                        else
                            query(c, "update ingest_queue set attempts = attempts + 1 where id = $1::bigint", [r[0]]);
                    }
                }
            handled = rows.length;
        });
        isolateNext = false;
    }
    catch (Exception e)
    {
        if (isTransient(e))
        {
            logWarn("queue batch hit a lock conflict, retrying: %s", e.msg);
            sleep(uniform(20, 120).msecs); // jitter, so competing workers do not collide again
        }
        else
        {
            logError("queue batch failed, retrying row by row: %s", e.msg);
            isolateNext = true;
        }
        return retryNow;
    }
    return handled;
}

void queueWorker() nothrow
{
    for (;;)
    {
        try
        {
            if (processBatch() == batchSize)
                continue; // more work waiting
            sleep(300.msecs);
        }
        catch (Exception e)
        {
            try logError("queue worker: %s", e.msg); catch (Exception) {}
            try sleep(2.seconds); catch (Exception) {}
        }
    }
}

/// Deletes up to `limit` rows with the given statement; returns the count.
private long deleteBatch(string sql, string[] args) @trusted
{
    return query("with d as (" ~ sql ~ " returning 1) select count(*) from d", args)[0][0].to!long;
}

/// Removes events older than the retention window, issues left without events,
/// and expired sessions. Returns the number of events removed.
long runCleanup(int globalDays) @trusted
{
    enum chunk = "5000";
    enum cutoff = "now() - make_interval(days => coalesce(p.retention_days, $1::int))";
    long events, n;
    do
    {
        n = deleteBatch(`delete from events where id in (
            select e.id from events e join projects p on p.id = e.project_id
            where e.received_at < ` ~ cutoff ~ ` limit ` ~ chunk ~ `)`, [globalDays.to!string]);
        events += n;
    } while (n == to!long(chunk));

    deleteBatch(`delete from issues where id in (
        select i.id from issues i join projects p on p.id = i.project_id
        where i.last_seen < ` ~ cutoff ~ ` and not exists (select 1 from events e where e.issue_id = i.id)
          and not exists (select 1 from ingest_queue q where q.project_id = i.project_id) limit ` ~ chunk ~ `)`,
            [globalDays.to!string]);
    foreach (table; ["event_attachments", "user_feedback"])
        for (long m = to!long(chunk); m == to!long(chunk);)
            m = deleteBatch("delete from " ~ table ~ ` where id in (
                select a.id from ` ~ table ~ ` a join projects p on p.id = a.project_id
                where a.created_at < ` ~ cutoff.replace("e.received_at", "a.created_at") ~ ` limit ` ~ chunk ~ `)`, [globalDays.to!string]);
    deleteBatch("delete from sessions where expires_at < now()", null);
    return events;
}

void cleanupWorker(int globalDays, int intervalMinutes) nothrow
{
    for (;;)
    {
        try
        {
            auto n = runCleanup(globalDays);
            logInfo("retention cleanup removed %s events", n);
            sleep(intervalMinutes.minutes);
        }
        catch (Exception e)
        {
            try logError("cleanup: %s", e.msg); catch (Exception) {}
            try sleep(1.minutes); catch (Exception) {}
        }
    }
}

void startBackground(int workers, int retentionDays, int cleanupMinutes)
{
    setupWorkerThreads(workers + 1);
    foreach (_; 0 .. workers)
        runWorkerTask(&queueWorker);
    runWorkerTask(&cleanupWorker, retentionDays, cleanupMinutes);
}
