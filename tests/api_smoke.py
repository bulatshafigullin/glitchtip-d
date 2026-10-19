import urllib.request as u, urllib.error, json, gzip, uuid, re, http.cookiejar, time, sys
import os
B=os.environ.get('BASE_URL','http://localhost:8765')  # needs a fresh database and ENABLE_REGISTRATION=true
fails=[]
def check(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ')+name+('' if cond else '  -> '+str(extra)[:300]))
    if not cond: fails.append(name)
class S:
    def __init__(s): s.cj=http.cookiejar.CookieJar(); s.o=u.build_opener(u.HTTPCookieProcessor(s.cj)); s.h={}
    def call(s, path, body=None, headers=None, method=None, raw=None):
        h={**s.h, **(headers or {})}
        data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if body is not None: h.setdefault('Content-Type','application/json')
        r=u.Request(B+path, data=data, headers=h, method=method)
        try: x=s.o.open(r); return x.status, x.read().decode('latin1'), dict(x.headers)
        except urllib.error.HTTPError as e: return e.code, e.read().decode('latin1'), dict(e.headers)
    def j(s,*a,**k):
        st,b,h=s.call(*a,**k)
        try: return st, json.loads(b) if b else None
        except Exception: return st, b
X={'X-Requested-With':'x'}
a=S(); b=S(); a.h=X; b.h=X
print(a.call('/api/0/auth/register/',{'email':'a@x.io','password':'password1'})[0], b.call('/api/0/auth/register/',{'email':'b@x.io','password':'password2'})[0])
org=a.j('/api/0/auth/me/')[1]['organizations'][0]['slug']
st,p=a.j('/api/0/projects/',{'name':'Web','platform':'javascript','organization':org}); check('create project',st==201 and p['dsn'],p)
pid=p['id']; slug=p['slug']; key=re.search(r'//([0-9a-f-]+)@',p['dsn']).group(1)
check('dsn has no dashes','-' not in key,key)
H={'X-Sentry-Auth':'Sentry sentry_key='+key}
def store(ev, hdr=None):
    return S().call(f'/api/{pid}/store/',raw=json.dumps(ev).encode(),headers={**H,**(hdr or {})})
# ---- CORS
st,_,h=S().call(f'/api/{pid}/envelope/',method='OPTIONS',headers={'Origin':'https://site.io','Access-Control-Request-Method':'POST'})
check('preflight 204 + ACAO', st==204 and h.get('Access-Control-Allow-Origin')=='*' and 'X-Sentry-Auth' in h.get('Access-Control-Allow-Headers',''), (st,h))
st,_,h=store({'message':'x'}); check('ingest has CORS header', h.get('Access-Control-Allow-Origin')=='*')
st,_,h=S().call(f'/api/{pid}/store/',raw=b'{}'); check('401 has CORS', st==401 and h.get('Access-Control-Allow-Origin')=='*',(st,h))
# ---- grouping
def exc(t,v,frames,**kw): return {'level':'error','exception':{'values':[{'type':t,'value':v,'stacktrace':{'frames':frames}}]},**kw}
fr=lambda fn,mod,line,app=True: {'function':fn,'module':mod,'lineno':line,'in_app':app}
store(exc('TypeError','a is undefined',[fr('main','app',1),fr('run','app',10)],release='1.0.0',environment='prod',tags={'browser':'chrome'}))
store(exc('TypeError','b is undefined',[fr('main','app',2),fr('run','app',99)],release='1.0.0',environment='prod',tags=[['browser','firefox']]))  # different lines/values -> same issue
store(exc('TypeError','a',[{'function':'x','filename':'https://cdn.io/static/main.3f9a2b1c.js','in_app':True}],release='1.0.1',environment='staging'))
store(exc('TypeError','a',[{'function':'x','filename':'https://other.io/static/main.99aabbcc.js?v=3','in_app':True}],release='1.0.1',environment='staging'))  # hash/host normalized -> same issue
store({'level':'warning','logentry':{'message':'user %s not found','params':['42']}})
store({'level':'warning','logentry':{'message':'user %s not found','params':['43']}})  # same template
store(exc('KeyError','k',[fr('f','m',1)],fingerprint=['{{ default }}','tenant-1']))
store(exc('KeyError','k',[fr('f','m',1)],fingerprint=['{{ default }}','tenant-2']))
store(exc('KeyError','k',[fr('f','m',1)]))
store({'message':'big','event_id':'z'*3,'level':'bogus'})
time.sleep(2)
st,issues=a.j(f'/api/0/organizations/{org}/issues/?limit=100')
titles=sorted((i['title'],i['count']) for i in issues); print(titles)
byt={i['title']:i for i in issues}
check('stack grouping ignores line/value', byt['TypeError: a is undefined']['count']=='2' and sum(int(i['count']) for i in issues if i['title'].startswith('TypeError'))==4 and len([i for i in issues if i['title'].startswith('TypeError')])==2, titles)
check('bundle hash/host normalized', any(i['title']=='TypeError: a' and i['count']=='2' for i in issues), titles)
check('message template grouping', any(i['title']=='user 42 not found' and i['count']=='2' for i in issues), titles)
check('fingerprint {{ default }} combos', len([i for i in issues if i['title']=='KeyError: k'])==3, titles)
check('bogus level normalized', any(i['title']=='big' and i['level']=='error' for i in issues), titles)
# ---- search
q=lambda s: sorted(i['title'] for i in a.j(f'/api/0/organizations/{org}/issues/?limit=100&query='+u.quote(s))[1])
check('search release', q('release:1.0.0')==['TypeError: a is undefined'], q('release:1.0.0'))
check('search environment+tag', q('environment:prod browser:firefox')==['TypeError: a is undefined'])
check('search negation', 'TypeError: a is undefined' not in q('!environment:prod') and 'TypeError: a' in q('!environment:prod'))
check('search wildcard release', q('release:1.0.*')==['TypeError: a','TypeError: a is undefined'], q('release:1.0.*'))
check('search level', q('level:warning')==['user 42 not found'])
check('search free text', q('not found')==['user 42 not found'])
check('search quoted', q('"user 42"')==['user 42 not found'])
check('search has:release', len(q('has:release'))==2)
check('default unresolved', len(a.j(f'/api/0/organizations/{org}/issues/')[1])>=8)
check('project issues endpoint', len(a.j(f'/api/0/projects/{org}/{slug}/issues/?query=level:warning')[1])==1)
check('sort freq', a.j(f'/api/0/organizations/{org}/issues/?sort=freq')[1][0]['count']!='0')
st,_,h=a.call(f'/api/0/organizations/{org}/issues/?limit=1'); check('X-Hits header', int(h.get('X-Hits','0'))>=8, h)
# ---- bulk / assign / merge / comments
ids=[i['id'] for i in issues if i['title'].startswith('KeyError')]
st,r=a.j(f'/api/0/organizations/{org}/issues/?'+'&'.join('id='+i for i in ids),{'merge':True},method='PUT')
check('merge', st==200 and r['merge']['parent'] and len(r['merge']['children'])==2, (st,r))
time.sleep(0.2)
store(exc('KeyError','k',[fr('f','m',1)],fingerprint=['{{ default }}','tenant-1'])); time.sleep(1.2)
kes=[i for i in a.j(f'/api/0/organizations/{org}/issues/?limit=100&query='+u.quote('KeyError'))[1]]
check('merge leaves 1 issue, alias routes new event', len(kes)==1 and kes[0]['count']=='4', [(i['id'],i['count']) for i in kes])
iid=kes[0]['id']
st,r=a.j(f'/api/0/issues/{iid}/',{'assignedTo':'me','status':'resolved'},method='PUT'); check('single issue assign+resolve', st==200 and r['assignedTo']=='a@x.io' and r['status']=='resolved',r)
check('search assigned:me', iid in [i['id'] for i in a.j(f'/api/0/organizations/{org}/issues/?query='+u.quote('is:resolved assigned:me'))[1]])
st,r=a.j(f'/api/0/organizations/{org}/issues/?id={iid}',{'assignedTo':None},method='PUT'); check('bulk unassign',st==200 and r['updated']==1,r)
st,r=a.j(f'/api/0/organizations/{org}/issues/?id={iid}',{'assignedTo':'nobody@x.io'},method='PUT'); check('assign non-member 404',st==404,r)
st,r=a.j(f'/api/0/organizations/{org}/issues/',{'status':'ignored'},method='PUT'); check('bulk without selection 400',st==400,r)
st,r=a.j(f'/api/0/issues/{iid}/comments/',{'text':'looking into it'}); check('add comment',st==201 and r['text']=='looking into it',r)
cid=r['id']; check('list comments', len(a.j(f'/api/0/issues/{iid}/comments/')[1])==1)
check('numComments', [i for i in a.j(f'/api/0/organizations/{org}/issues/?query=')[1] if i['id']==iid][0]['numComments']==1)
check('delete comment', a.call(f'/api/0/issues/{iid}/comments/{cid}/',method='DELETE')[0]==204)
st,r=a.j(f'/api/0/issues/{ids[0]}/tags/'); check('issue tags', st==200 and isinstance(r,list), r)
tid=[i['id'] for i in issues if i['title']=='TypeError: a is undefined'][0]
st,r=a.j(f'/api/0/issues/{tid}/tags/'); check('issue tags content', any(t['key']=='browser' and t['totalValues']==2 for t in r), r)
st,r=a.j(f'/api/0/issues/{tid}/events/latest/'); check('latest event', st==200 and r['eventID'], r)
# ---- events / tags / envs
st,r=a.j(f'/api/0/projects/{org}/{slug}/events/?environment=prod'); check('project events filter', st==200 and len(r)==2 and r[0]['title'], r)
eid=r[0]['eventID']; st,r=a.j(f'/api/0/projects/{org}/{slug}/events/{eid}/'); check('event detail', st==200 and r['data'] and r['attachments']==[], r)
check('environments', [e['name'] for e in a.j(f'/api/0/projects/{org}/{slug}/environments/')[1]]==['prod','staging'])
check('tag keys', 'browser' in [t['key'] for t in a.j(f'/api/0/projects/{org}/{slug}/tags/')[1]])
check('tag values', sorted(v['value'] for v in a.j(f'/api/0/projects/{org}/{slug}/tags/browser/values/')[1])==['chrome','firefox'])
st,r=a.j(f'/api/0/projects/{org}/{slug}/stats/'); check('project stats', st==200 and len(r)>=24 and sum(x[1] for x in r)>=10, r[-3:] if isinstance(r,list) else r)
st,r=a.j(f'/api/0/organizations/{org}/stats/?resolution=1d'); check('org stats 1d', st==200 and sum(x[1] for x in r)>=10)
check('stats bad resolution', a.j(f'/api/0/organizations/{org}/stats/?resolution=5m')[0]==400)
# ---- envelope: user_report, attachment, ignored items, gzip
eidv=uuid.uuid4().hex
att=b'\x00\x01binary\xff\xfe data'
env=(json.dumps({'event_id':eidv}).encode()+b'\n'
    +b'{"type":"event"}\n'+json.dumps({'message':'with attachment','level':'info'}).encode()+b'\n'
    +json.dumps({'type':'attachment','length':len(att),'filename':'log"x.bin','content_type':'text/html'}).encode()+b'\n'+att+b'\n'
    +b'@@UR@@'
    +b'{"type":"session"}\n{"status":"ok"}\n{"type":"transaction"}\n{"spans":[]}\n{"type":"client_report"}\n{"discarded_events":[]}\n{"type":"weird_new"}\n{}\n')
ur=json.dumps({'event_id':eidv,'name':'Ann','email':'ann@x.io','comments':'it broke'}).encode()
env=env.replace(b'@@UR@@', json.dumps({'type':'user_report','length':len(ur)}).encode()+b'\n'+ur+b'\n')
st,_,_=S().call(f'/api/{pid}/envelope/',raw=gzip.compress(env),headers={**H,'Content-Encoding':'gzip'}); check('envelope with all item types',st==200,st)
time.sleep(1.2)
st,r=a.j(f'/api/0/projects/{org}/{slug}/events/{eidv}/'); check('envelope event stored + attachment listed', st==200 and len(r['attachments'])==1 and r['attachments'][0]['size']==len(att), r)
aid=r['attachments'][0]['id']
st,body,h=a.call(f'/api/0/projects/{org}/{slug}/events/{eidv}/attachments/{aid}/')
check('attachment download safe', st==200 and body.encode('latin1',errors='ignore')!=b'' and h.get('X-Content-Type-Options')=='nosniff' and 'attachment' in h.get('Content-Disposition','') and '"x' not in h.get('Content-Disposition','').split('filename=')[1].strip('"'), h)
raw=u.urlopen(u.Request(B+f'/api/0/projects/{org}/{slug}/events/{eidv}/attachments/{aid}/',headers={'Cookie':'; '.join(c.name+'='+c.value for c in a.cj)})).read()
check('attachment bytes intact', raw==att, raw)
st,r=a.j(f'/api/0/projects/{org}/{slug}/user-feedback/'); check('user feedback listed with issue', st==200 and r[0]['comments']=='it broke' and r[0]['issueId'], r)
st,r=a.j(f'/api/0/projects/{org}/{slug}/user-feedback/',{'event_id':eidv,'name':'Bob','email':'b@x.io','comments':'via api'}); check('post feedback',st==201)
check('envelope 400 on bad length', S().call(f'/api/{pid}/envelope/',raw=b'{}\n{"type":"event","length":9999}\n{}',headers=H)[0]==400)
check('store 400 on bad json', store.__call__({}) [0]==200 and S().call(f'/api/{pid}/store/',raw=b'{nope',headers=H)[0]==400)
# ---- keys
st,ks=a.j(f'/api/0/projects/{org}/{slug}/keys/'); check('list keys', st==200 and len(ks)==1 and ks[0]['dsn']['public'].startswith('http'), ks)
st,k2=a.j(f'/api/0/projects/{org}/{slug}/keys/',{'label':'limited','rateLimit':{'count':2,'window':60},'allowedOrigins':['https://good.io','*.ok.com']})
check('create key with limits', st==201 and k2['rateLimit']=={'count':2,'window':60} and k2['allowedOrigins']==['https://good.io','*.ok.com'], k2)
H2={'X-Sentry-Auth':'Sentry sentry_key='+k2['public']}
send=lambda hdr=None: S().call(f'/api/{pid}/store/',raw=b'{"message":"rl"}',headers={**H2,**(hdr or {})})[0]
check('origin allowed exact', send({'Origin':'https://good.io'})==200)
check('origin wildcard', send({'Origin':'https://app.ok.com'})==200)
st,_,h=S().call(f'/api/{pid}/store/',raw=b'{"message":"rl"}',headers={**H2,'Origin':'https://evil.io'}); check('origin denied 403',st==403 and h.get('Access-Control-Allow-Origin')=='*',st)
st,_,h=S().call(f'/api/{pid}/store/',raw=b'{"message":"rl"}',headers=H2); check('rate limit 429 + Retry-After', st==429 and int(h.get('Retry-After','0'))>0 and 'X-Sentry-Rate-Limits' in h,(st,h))
check('other key unaffected', store({'message':'ok'})[0]==200)
st,r=a.j(f'/api/0/projects/{org}/{slug}/keys/{k2["id"]}/',{'rateLimit':None,'allowedOrigins':[],'isActive':False},method='PUT'); check('update key', st==200 and r['rateLimit'] is None and r['isActive']==False and r['allowedOrigins']==[],r)
check('inactive key 403', send()==403)
check('bad rate limit 400', a.j(f'/api/0/projects/{org}/{slug}/keys/{k2["id"]}/',{'rateLimit':{'count':0,'window':5}},method='PUT')[0]==400)
a.j(f'/api/0/projects/{org}/{slug}/keys/{k2["id"]}/',{'isActive':True},method='PUT')
st,r=a.j(f'/api/0/projects/{org}/{slug}/keys/{k2["id"]}/rotate/',{}); check('rotate key', st==200 and r['public']!=k2['public'],r)
check('old key rejected after rotate', send()==403)
check('new key works', S().call(f'/api/{pid}/store/',raw=b'{"message":"rot"}',headers={'X-Sentry-Auth':'Sentry sentry_key='+r['public']})[0]==200)
check('delete key', a.call(f'/api/0/projects/{org}/{slug}/keys/{r["id"]}/',method='DELETE')[0]==204 and a.j(f'/api/0/projects/{org}/{slug}/keys/{r["id"]}/')[0]==404)
check('key CRUD needs admin', b.j(f'/api/0/projects/{org}/{slug}/keys/',{})[0] in (403,404))
# ---- releases
time.sleep(0.5)
st,rels=a.j(f'/api/0/organizations/{org}/releases/'); check('auto-created releases', sorted(r['version'] for r in rels)==['1.0.0','1.0.1'], rels)
st,r=a.j(f'/api/0/organizations/{org}/releases/',{'version':'app@2.0.0','projects':[slug],'ref':'abc123','url':'https://git/commit/abc'}); check('create release', st==201 and r['version']=='app@2.0.0' and r['projects'][0]['slug']==slug and r['ref']=='abc123',r)
st,r=a.j(f'/api/0/organizations/{org}/releases/app@2.0.0/'); check('get release', st==200 and r['version']=='app@2.0.0',(st,r))
st,r=a.j(f'/api/0/organizations/{org}/releases/app@2.0.0/',{'dateReleased':'2026-10-01T12:00:00Z'},method='PUT'); check('finalize release', st==200 and r['dateReleased'],r)
check('bad date 400', a.j(f'/api/0/organizations/{org}/releases/app@2.0.0/',{'dateReleased':'not-a-date'},method='PUT')[0]==400)
st,r=a.j(f'/api/0/organizations/{org}/releases/app@2.0.0/deploys/',{'environment':'production','name':'deploy 1'}); check('create deploy', st==201 and r['environment']=='production',r)
check('list deploys', len(a.j(f'/api/0/organizations/{org}/releases/app@2.0.0/deploys/')[1])==1)
r=[x for x in a.j(f'/api/0/organizations/{org}/releases/?query=2.0')[1]]; check('release search + lastDeploy', len(r)==1 and r[0]['deployCount']==1 and r[0]['lastDeploy']['environment']=='production',r)
check('release 404', a.j(f'/api/0/organizations/{org}/releases/nope/')[0]==404)
# ---- teams & access
st,t=a.j(f'/api/0/organizations/{org}/teams/',{'name':'Backend'}); check('create team', st==201 and t['slug']=='backend' and t['memberCount']==0,t)
check('team needs admin', b.j(f'/api/0/organizations/{org}/teams/',{'name':'X'})[0] in (403,404))
a.j(f'/api/0/organizations/{org}/members/',{'email':'b@x.io','role':'member'})
bid=[m for m in a.j(f'/api/0/organizations/{org}/members/')[1] if m['email']=='b@x.io'][0]['id']
check('open membership: member sees project', len(b.j('/api/0/projects/')[1])==1 and b.j(f'/api/0/projects/{org}/{slug}/issues/')[0]==200)
st,r=a.j(f'/api/0/organizations/{org}/',{'openMembership':False},method='PUT'); check('close membership', st==200 and r['openMembership']==False,r)
check('closed: member sees nothing', b.j('/api/0/projects/')[1]==[] and b.j(f'/api/0/projects/{org}/{slug}/issues/')[0]==404 and b.j(f'/api/0/issues/{tid}/')[0]==404 and b.j(f'/api/0/organizations/{org}/issues/')[1]==[])
check('closed: admin/owner still sees', len(a.j('/api/0/projects/')[1])==1)
st,r=a.j(f'/api/0/projects/{org}/{slug}/teams/backend/',{}); check('assign team to project', st==201 and r['teams'][0]['slug']=='backend',r)
check('assigned but not in team: still hidden', b.j('/api/0/projects/')[1]==[])
check('member cannot join in closed org', b.j(f'/api/0/organizations/{org}/members/{bid}/teams/backend/',{})[0]==403)
st,r=a.j(f'/api/0/organizations/{org}/members/{bid}/teams/backend/',{}); check('admin adds member to team', st==201 and r['memberCount']==1 and r['projects']==[slug],r)
check('team member sees project', len(b.j('/api/0/projects/')[1])==1 and b.j(f'/api/0/projects/{org}/{slug}/issues/')[0]==200 and b.j(f'/api/0/issues/{tid}/')[0]==200 and len(b.j(f'/api/0/organizations/{org}/issues/')[1])>0)
check('team members list', [m['email'] for m in a.j(f'/api/0/teams/{org}/backend/members/')[1]]==['b@x.io'])
check('team projects list', [p['slug'] for p in a.j(f'/api/0/teams/{org}/backend/projects/')[1]]==[slug])
check('member cannot admin project', b.j(f'/api/0/projects/{org}/{slug}/',{'name':'hack'},method='PUT')[0]==403)
st,r=a.j(f'/api/0/teams/{org}/backend/projects/',{'name':'Backend API'}); check('create project under team', st==201 and r['teams'][0]['slug']=='backend',r)
check('stats scoped by access', b.j(f'/api/0/organizations/{org}/stats/')[0]==200)
st,r=a.j(f'/api/0/organizations/{org}/members/{bid}/teams/backend/',method='DELETE'); check('remove from team', st==200 and r['memberCount']==0)
check('removed: hidden again', b.j('/api/0/projects/')[1]==[])
a.j(f'/api/0/organizations/{org}/',{'openMembership':True},method='PUT')
st,r=b.j(f'/api/0/organizations/{org}/members/{bid}/teams/backend/',{}); check('open org: self-join allowed', st==201,r)
check('self-join other user denied', b.j(f'/api/0/organizations/{org}/members/999/teams/backend/',{})[0] in (403,404))
st,r=a.j(f'/api/0/teams/{org}/backend/',{'name':'Backend Team'},method='PUT'); check('rename team', st==200 and r['name']=='Backend Team')
check('delete team', a.call(f'/api/0/teams/{org}/backend/',method='DELETE')[0]==204 and a.j(f'/api/0/teams/{org}/backend/')[0]==404)
# ---- project detail / root / delete issues
st,r=a.j(f'/api/0/projects/{org}/{slug}/'); check('project detail', st==200 and r['slug']==slug)
st,r=a.j(f'/api/0/projects/{org}/{slug}/',{'retentionDays':30,'name':'Web App'},method='PUT'); check('update project', st==200 and r['retentionDays']==30 and r['name']=='Web App',r)
check('retention validation', a.j(f'/api/0/projects/{org}/{slug}/',{'retentionDays':0},method='PUT')[0]==400)
st,r=S().j('/api/0/'); check('root unauth', st==200 and r['auth'] is None)
st,r=a.j('/api/0/'); check('root auth', st==200 and r['user']['email']=='a@x.io')
check('org detail', a.j(f'/api/0/organizations/{org}/')[1]['slug']==org)
check('org projects', len(a.j(f'/api/0/organizations/{org}/projects/')[1])==2)
check('unauth org api 401', S().j(f'/api/0/organizations/{org}/issues/')[0]==401)
check('csrf on mutations', S().call(f'/api/0/organizations/{org}/teams/',{'name':'q'})[0] in (401,403))
n=len(a.j(f'/api/0/organizations/{org}/issues/?query=')[1])
check('bulk delete admin', a.call(f'/api/0/organizations/{org}/issues/?id={iid}',method='DELETE')[0]==204 and a.j(f'/api/0/issues/{iid}/')[0]==404)
check('member cannot bulk delete', b.call(f'/api/0/organizations/{org}/issues/?id={tid}',method='DELETE')[0] in (403,404))

# ---- project aliases (DSNs issued under another id scheme keep working)
import subprocess as _sp
def _psql(q): return _sp.run(['psql','-h','/tmp','glitchtip_d','-Atc',q],capture_output=True,text=True).stdout.strip()
_psql(f"insert into project_aliases (alias_id, project_id) values (987654321, {pid})")
A2={'X-Sentry-Auth':'Sentry sentry_key='+key}
st=S().call('/api/987654321/store/',raw=json.dumps({'message':'via alias id','level':'warning'}).encode(),headers=A2)[0]
check('alias id + project key accepted', st==200, st)
check('alias id + wrong key rejected', S().call('/api/987654321/store/',raw=b'{}',headers={'X-Sentry-Auth':'Sentry sentry_key=00000000000000000000000000000000'})[0]==403)
check('unknown id still rejected', S().call('/api/987654322/store/',raw=b'{}',headers=A2)[0]==403)
time.sleep(1.3)
check('alias event lands in the real project', any(i['title']=='via alias id' for i in a.j(f'/api/0/projects/{org}/{slug}/issues/?query=')[1]))
check('alias envelope works too', S().call('/api/987654321/envelope/',raw=b'{}\n{"type":"event"}\n{"message":"alias envelope"}\n',headers=A2)[0]==200)

# ---- change password
c=S(); c.h=X
c.call('/api/0/auth/login/',{'email':'a@x.io','password':'password1'})
check('second session works', c.j('/api/0/auth/me/')[0]==200)
check('wrong current password 403', a.j('/api/0/auth/password/',{'currentPassword':'nope','newPassword':'newpassword1'})[0]==403)
check('short new password 400', a.j('/api/0/auth/password/',{'currentPassword':'password1','newPassword':'short'})[0]==400)
check('change password ok', a.j('/api/0/auth/password/',{'currentPassword':'password1','newPassword':'newpassword1'})[0]==200)
check('current session survives', a.j('/api/0/auth/me/')[0]==200)
check('other sessions signed out', c.j('/api/0/auth/me/')[0]==401)
d=S(); d.h=X
check('old password rejected', d.call('/api/0/auth/login/',{'email':'a@x.io','password':'password1'})[0]==401)
check('new password accepted', d.call('/api/0/auth/login/',{'email':'a@x.io','password':'newpassword1'})[0]==200)
check('password change needs auth', S().call('/api/0/auth/password/',{'currentPassword':'x','newPassword':'yyyyyyyy'},X)[0]==401)

print('\nFAILED:' , fails if fails else 'none')
