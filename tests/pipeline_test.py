"""Ingest pipeline checks: batching, dedupe, aliases, isolation, contention.

Needs a fresh database and a server started with ENABLE_REGISTRATION=true (use WORKERS=4 to stress it).
  python3 tests/pipeline_test.py
"""
import http.cookiejar, json, os, re, subprocess, threading, time, urllib.request as u, urllib.error, uuid
B = os.environ.get('BASE_URL', 'http://localhost:8765')
fails = []
def check(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else '  -> ' + str(extra)[:300]))
    if not cond: fails.append(name)
def sql(q): return subprocess.run(['psql', '-h', '/tmp', 'glitchtip_d', '-Atc', q], capture_output=True, text=True).stdout.strip()
X = {'X-Requested-With': 'x', 'Content-Type': 'application/json'}
op = u.build_opener(u.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(method, path, body=None):
    r = u.Request(B + '/api/0' + path, data=json.dumps(body).encode() if body is not None else None, headers=X, method=method)
    try: return json.loads(op.open(r).read() or b'null')
    except urllib.error.HTTPError as e: return {'_status': e.code}
try: api('POST', '/auth/register/', {'email': 'pipe@x.io', 'password': 'password1'})
except Exception: api('POST', '/auth/login/', {'email': 'pipe@x.io', 'password': 'password1'})
org = api('GET', '/auth/me/')['organizations'][0]['slug']
proj = api('POST', '/projects/', {'name': 'Pipe', 'organization': org})
pid, key = proj['id'], re.search(r'//([0-9a-f]+)@', proj['dsn']).group(1)
H = {'X-Sentry-Auth': 'Sentry sentry_key=' + key}
def send(ev, hdr=None):
    raw = ev if isinstance(ev, bytes) else json.dumps(ev).encode()
    return u.urlopen(u.Request(f'{B}/api/{pid}/store/', data=raw, headers={**H, **(hdr or {})})).status
def fan(events, threads=8):
    errs = []
    def run(chunk):
        for e in chunk:
            try: send(e)
            except Exception as ex: errs.append(ex)
    ts = [threading.Thread(target=run, args=(events[i::threads],)) for i in range(threads)]
    [t.start() for t in ts]; [t.join() for t in ts]
    return errs
def drain(limit=60):
    t0 = time.time()
    while int(sql('select count(*) from ingest_queue') or 1) > 0 and time.time() - t0 < limit: time.sleep(0.05)
    time.sleep(0.2)
def exc(t, fn, **kw):
    return {'event_id': uuid.uuid4().hex, 'exception': {'values': [{'type': t, 'value': 'v', 'stacktrace': {'frames': [{'function': fn, 'module': 'm', 'in_app': True}]}}]}, **kw}
def issues(): return {i['title']: i for i in api('GET', f'/projects/{org}/pipe/issues/?limit=100&query=')}
deadlocks_before = int(subprocess.run("grep -c 'deadlock detected' /opt/homebrew/var/log/postgresql@14.log", shell=True, capture_output=True, text=True).stdout or 0)

# 1. one hot fingerprint, many concurrent events -> a single issue with the exact count
check('storm: no HTTP errors', fan([exc('StormError', 'f') for _ in range(400)]) == [])
drain(); i = issues()
check('storm: one issue, count 400', i['StormError: v']['count'] == '400', i.get('StormError: v'))
check('storm: 400 events stored', sql("select count(*) from events e join issues i on i.id=e.issue_id where i.title='StormError: v'") == '400')

# 2. duplicates: same event id many times, concurrently (same batch) and again later (other batch)
dup = exc('DupError', 'd'); fan([dup] * 20); drain()
check('dup within batches: counted once', issues()['DupError: v']['count'] == '1', issues().get('DupError: v'))
fan([dup] * 5); drain()
check('dup across batches: still once', issues()['DupError: v']['count'] == '1' and sql("select count(*) from events where data->>'event_id'='%s'" % dup['event_id']) == '1')

# 3. many fingerprints interleaved
evs = [exc(f'Multi{n % 15}', 'g') for n in range(600)]
import random; random.shuffle(evs); fan(evs); drain(); i = issues()
check('15 interleaved issues, 40 each', all(i[f'Multi{n}: v']['count'] == '40' for n in range(15)), [i.get(f'Multi{n}: v', {}).get('count') for n in range(15)])

# 4. merged fingerprints: two sources merged into a target; a burst for all three lands on the survivor
for n in ('MergeA', 'MergeB', 'MergeC'): send(exc(n, 'm'))
drain(); i = issues(); ids = [i[f'Merge{c}: v']['id'] for c in 'ABC']
r = api('PUT', f'/organizations/{org}/issues/?' + '&'.join('id=' + x for x in ids), {'merge': True})
check('merge ok', 'merge' in r, r)
fan([exc(n, 'm') for n in ('MergeA', 'MergeB', 'MergeC') for _ in range(10)]); drain()
survivors = [v for k, v in issues().items() if k.startswith('Merge')]
check('merge: one survivor with 3 + 30 events (two aliases summed in one batch)', len(survivors) == 1 and survivors[0]['count'] == '33', [(s['title'], s['count']) for s in survivors])

# 5. a resolved issue reopens when a batch brings a new event
api('PUT', f'/organizations/{org}/issues/?id={issues()["StormError: v"]["id"]}', {'status': 'resolved'})
send(exc('StormError', 'f')); drain()
check('regression: resolved -> unresolved', issues()['StormError: v']['status'] == 'unresolved' and issues()['StormError: v']['count'] == '401')

# 6. event id and client IP patching only when needed
dashed = str(uuid.uuid4()); send({'event_id': dashed, 'message': 'dashed id', 'user': {'ip_address': '{{auto}}'}})
plain = uuid.uuid4().hex; send({'event_id': plain, 'message': 'plain id', 'user': {'ip_address': '9.9.9.9'}})
send({'message': 'no id'}); drain()
check('dashed id normalised in data', sql("select data->>'event_id' from events where data->>'message'='dashed id'") == dashed.replace('-', ''))
check('{{auto}} replaced by client ip', sql("select data->'user'->>'ip_address' from events where data->>'message'='dashed id'") == '127.0.0.1')
check('explicit ip untouched', sql("select data->'user'->>'ip_address' from events where data->>'message'='plain id'") == '9.9.9.9')
check('missing id generated', re.fullmatch('[0-9a-f]{32}', sql("select data->>'event_id' from events where data->>'message'='no id'") or '') is not None)

# 7. a poison queue row must not stall the others (it is dropped after 5 attempts)
sql("insert into ingest_queue (project_id, event_id, payload) values (999999, gen_random_uuid(), '{\"message\":\"poison\"}')")
good = [exc('AfterPoison', 'p') for _ in range(30)]; fan(good); drain(90)
check('poison: good events stored', issues()['AfterPoison: v']['count'] == '30', issues().get('AfterPoison: v'))
check('poison: queue empty', sql('select count(*) from ingest_queue') == '0')

# 8. totals add up; no deadlocks were logged
check('every unique event stored exactly once', sql("select count(*) from events") == sql("select count(distinct event_id) from events"))
check('issue counts match stored events', sql("select count(*) from issues i where i.count <> (select count(*) from events e where e.issue_id=i.id) and not exists (select 1 from issue_fingerprints f where f.issue_id=i.id and false)") == '0')
deadlocks = int(subprocess.run("grep -c 'deadlock detected' /opt/homebrew/var/log/postgresql@14.log", shell=True, capture_output=True, text=True).stdout or 0) - deadlocks_before
check('no deadlocks during the run', deadlocks == 0, deadlocks)
print('\nFAILED:', fails if fails else 'none')
