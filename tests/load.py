"""Load generator: posts realistic ~35 KB events and waits for the queue to drain.

  python3 tests/load.py [events] [threads]        (server on BASE_URL, default :8765)
Needs a fresh database with ENABLE_REGISTRATION=true (it registers load@x.io).
"""
import http.cookiejar, json, os, re, subprocess, sys, threading, time, urllib.request as u, uuid
B = os.environ.get('BASE_URL', 'http://localhost:8765')
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
T = int(sys.argv[2]) if len(sys.argv) > 2 else 8
X = {'X-Requested-With': 'x', 'Content-Type': 'application/json'}
op = u.build_opener(u.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(path, body):
    return json.loads(op.open(u.Request(B + path, data=json.dumps(body).encode(), headers=X)).read())
try: call('/api/0/auth/register/', {'email': 'load@x.io', 'password': 'password1'})
except Exception: call('/api/0/auth/login/', {'email': 'load@x.io', 'password': 'password1'})
org = json.loads(op.open(u.Request(B + '/api/0/auth/me/')).read())['organizations'][0]['slug']
p = call('/api/0/projects/', {'name': 'Load', 'platform': 'python', 'organization': org})
pid, key = p['id'], re.search(r'//([0-9a-f]+)@', p['dsn']).group(1)

def frames(kind):
    return [{'filename': f'app/services/module_{i}.py', 'abs_path': f'/srv/app/app/services/module_{i}.py', 'module': f'app.services.module_{i}',
             'function': f'handle_{kind}_{i}', 'lineno': 100 + i, 'in_app': i > 5, 'pre_context': ['    x = compute()', '    y = other(x)', "    log.info('step')"],
             'context_line': f'    return process(x, y, request.session["user"])  # line {i}', 'post_context': ['', 'def next_function():'],
             'vars': {f'variable_{j}': f"'some local value number {j} in frame {i}'" for j in range(10)}} for i in range(25)]
def event(n):
    kind = n % 20  # 20 distinct issues
    return json.dumps({'event_id': uuid.uuid4().hex, 'level': 'error', 'platform': 'python', 'release': '1.4.2', 'environment': 'production',
        'server_name': 'web-7', 'transaction': '/api/orders', 'tags': {'browser': 'Chrome 120', 'os': 'Linux'},
        'user': {'id': '42', 'email': 'ann@example.com', 'ip_address': '{{auto}}'},
        'exception': {'values': [{'type': 'ValueError', 'value': f'invalid literal {n}', 'stacktrace': {'frames': frames(kind)}}]},
        'breadcrumbs': {'values': [{'timestamp': '2026-10-19T10:00:00Z', 'category': 'query', 'message': f'SELECT * FROM t_{i} WHERE id = {i}'} for i in range(50)]},
        'request': {'url': 'https://example.com/api/orders', 'method': 'POST', 'headers': {'User-Agent': 'Mozilla/5.0'}},
        'modules': [f'package-{i}==1.{i % 10}.0' for i in range(200)]}).encode()

bodies = [event(n) for n in range(N)]
H = {'X-Sentry-Auth': 'Sentry sentry_key=' + key}
errors = []
def worker(chunk):
    for b in chunk:
        try: u.urlopen(u.Request(f'{B}/api/{pid}/store/', data=b, headers=H)).read()
        except Exception as e: errors.append(str(e))
size = len(bodies[0])
t0 = time.time()
ths = [threading.Thread(target=worker, args=(bodies[i::T],)) for i in range(T)]
[t.start() for t in ths]; [t.join() for t in ths]
t1 = time.time()
def sql(q): return subprocess.run(['psql', '-h', '/tmp', 'glitchtip_d', '-Atc', q], capture_output=True, text=True).stdout.strip()
while int(sql('select count(*) from ingest_queue') or 1) > 0 and time.time() - t1 < 300: time.sleep(0.1)
t2 = time.time()
stored = sql(f'select count(*) from events where project_id = {pid}'); issues = sql(f'select count(*) from issues where project_id = {pid}')
print(f'event size {size} B | ingest {N} events in {t1 - t0:.2f}s = {N / (t1 - t0):.0f}/s | queue drained {t2 - t1:.2f}s after | total {t2 - t0:.2f}s = {N / (t2 - t0):.0f}/s')
print(f'stored events={stored} issues={issues} http_errors={len(errors)} {errors[:2]}')
