"""U9 case contract and executable UI regression checks; no live upstream needed."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.requests import Request

os.environ.setdefault('SOC_DB', os.path.join(tempfile.mkdtemp(), 'soc.db'))
import app

ROOT = Path(__file__).resolve().parents[1]
CASE = dict(case_id='abc123', tenant='acme', title='Investigation', owner=None,
            assignees=[], status='new', notes=[dict(author='analyst', text='Investigate', ts='2026-09-29T00:00:00Z')],
            linked_findings=['finding-1'], linked_entities=[dict(type='ip', value='192.0.2.1')],
            created='2026-09-29T00:00:00Z', updated='2026-09-29T00:00:00Z', audit=[])


def request(query=''):
    return Request({'type': 'http', 'query_string': query.encode(), 'headers': []})


def test_list_contract_filters_paging_and_server_credentials(monkeypatch):
    seen = []
    payload = dict(cases=[CASE], limit=50, offset=0, next_offset=50)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return json.dumps(payload).encode()
    def urlopen(req, timeout):
        seen.append(req)
        assert timeout == 5
        return Response()
    monkeypatch.setattr(app, 'CASE_API_URL', 'http://case.test')
    monkeypatch.setattr(app, 'CASE_API_TOKEN', 'server-session')
    monkeypatch.setattr(app.urllib.request, 'urlopen', urlopen)
    assert app.case_list(request('owner=alice&status=new&limit=50&offset=0')) == payload
    assert parse_qs(urlsplit(seen[0].full_url).query) == dict(owner=['alice'], status=['new'], limit=['50'], offset=['0'])
    assert seen[0].headers['Authorization'] == 'Bearer server-session'
    assert urlsplit(seen[0].full_url).path == '/cases'
    for query in ('tenant=other', 'actor=admin', 'status=new&status=closed'):
        assert app.case_list(request(query)).status_code == 400
    assert len(seen) == 1


@pytest.mark.parametrize('action,body', [('assign', {'assignee': 'alice'}), ('owner', {'owner': None}),
    ('notes', {'text': 'check'}), ('status', {'status': 'investigating'}),
    ('findings', {'finding_id': 'f2'}), ('entities', {'entity': {'type': 'domain', 'value': 'example.test'}})])
def test_mutations_exact_paths_bodies_and_returned_state(monkeypatch, action, body):
    captured = []
    def send(path, method, data):
        captured.append((path, method, data))
        return copy.deepcopy(CASE)
    monkeypatch.setattr(app, '_case_request', send)
    assert app.case_action('abc123', action, request(), body) == CASE
    assert captured == [('/cases/abc123/' + action, 'POST', body)]
    assert app.case_action('abc123', action, request(), dict(body, tenant='other')).status_code == 400
    assert app.case_action('abc123', action, request('actor=admin'), body).status_code == 400
    assert len(captured) == 1


def test_detail_and_degraded_responses(monkeypatch):
    monkeypatch.setattr(app, '_case_request', lambda *a: CASE)
    assert app.case_detail('abc123', request()) == CASE  # status:new is not degraded
    for bad in (None, {}, {'quality': 'degraded'}, dict(CASE, notes=[None]), dict(CASE, quality='unavailable')):
        monkeypatch.setattr(app, '_case_request', lambda *a: bad)
        result = app.case_detail('abc123', request())
        assert result.status_code == 503 and json.loads(result.body)['quality'] == 'unavailable'
    def fail(*args): raise OSError('unreachable')
    monkeypatch.setattr(app, '_case_request', fail)
    assert app.case_list(request()).status_code == 503
    assert app.case_action('abc123', 'notes', request(), {'text': 'draft'}).status_code == 503


def test_upstream_errors_and_empty_page(monkeypatch):
    for code, expected in ((400, 400), (401, 503), (403, 403), (404, 404), (500, 503)):
        def fail(*args): raise urllib.error.HTTPError('url', code, 'error', {}, None)
        monkeypatch.setattr(app, '_case_request', fail)
        assert app.case_detail('abc123', request()).status_code == expected
    page = dict(cases=[], limit=50, offset=0, next_offset=None)
    monkeypatch.setattr(app, '_case_request', lambda *a: page)
    assert app.case_list(request()) == page
    for bad in ('..', '../cases', 'a/b', 'a?tenant=other'):
        assert app.case_detail(bad, request()).status_code == 400


def test_javascript_case_interactions_and_inert_rendering():
    # Minimal DOM seam executes the actual view, captures HTML and bound handlers.
    source = (ROOT / 'static/overview.js').read_text().split('// U9 cases:')[1]
    assert ' onclick=' not in source and 'javascript:' not in source
    script = r'''
const assert=require('assert');
global.window=global;
const nodes={};
function element(){return {innerHTML:'',textContent:'',value:'',disabled:false,children:{},
 querySelector(s){return this.children[s]||(this.children[s]=element());},
 querySelectorAll(s){return this.children[s]||[];}};}
global.$=id=>nodes[id]||(nodes[id]=element());
global.esc=v=>String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
global.show=()=>{};
let doc=CASE, calls=[], unavailable=false;
global.req=async (url,opts)=>{
 calls.push({url,opts});
 if(unavailable)return {ok:false,status:503};
 if(opts){let b=JSON.parse(opts.body); if(url.endsWith('/assign'))doc.assignees.push(b.assignee);
 if(url.endsWith('/notes'))doc.notes.push({author:'session-analyst',text:b.text,ts:'now'});
 if(url.endsWith('/status'))doc.status=b.status;}
 return {ok:true,data:url.includes('?')?{cases:[doc],limit:50,offset:0,next_offset:null}:doc};
};
let row=element();row.dataset={caseId:doc.case_id};$('case-list').children['[data-case-id]']=[row];
const actions=['assign','notes','status'].map(action=>{let b=element();b.dataset={action};return b;});
$('case-detail').children['[data-action]']=actions;
SOURCE
(async()=>{
 $('case-owner-filter').value='alice';$('case-status-filter').value='new';
 await loadCases();assert(calls[0].url.includes('owner=alice'));assert(calls[0].url.includes('status=new'));
 assert($('case-list').innerHTML.includes('&lt;img'));assert(!$('case-list').innerHTML.includes('<img'));
 row.onclick();await new Promise(setImmediate);
 let box=$('case-detail');assert(box.innerHTML.includes('finding-1'));assert(box.innerHTML.includes('192.0.2.1'));assert(box.innerHTML.includes('Investigate'));
 box.querySelector('[data-case="assignee"]').value='alice';actions[0].onclick();await new Promise(setImmediate);
 assert(box.innerHTML.includes('Assignees: alice'));
 box.querySelector('[data-case="text"]').value='<script>bad()</script>';actions[1].onclick();await new Promise(setImmediate);
 assert(box.innerHTML.includes('&lt;script&gt;'));assert(box.innerHTML.includes('session-analyst'));
 box.querySelector('[data-case="status"]').value='investigating';actions[2].onclick();await new Promise(setImmediate);
 assert(box.innerHTML.includes('<option selected>investigating</option>'));assert(doc.status==='investigating');
 const writes=calls.filter(c=>c.opts);assert.deepEqual(writes.map(c=>c.url.split('/').pop()),['assign','notes','status']);
 assert.deepEqual(JSON.parse(writes[0].opts.body),{assignee:'alice'});
 assert(!/<[^>]*\son\w+=/i.test(box.innerHTML));
 unavailable=true;box.querySelector('[data-case="text"]').value='draft';actions[1].onclick();await new Promise(setImmediate);
 assert(box.querySelector('[data-case="message"]').textContent.includes('unavailable'));
 assert(box.querySelector('[data-case="text"]').value==='draft');
 await loadCases();assert($('case-list').textContent.includes('unavailable'));
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
    hostile = dict(CASE, title='<img src=x onerror=bad()>', case_id="abc'\"><img src=x>")
    script = script.replace('CASE', json.dumps(hostile), 1).replace('SOURCE', '// U9 cases:' + source)
    subprocess.run(['node', '-e', script], check=True, capture_output=True, text=True)


def test_write_transport_uses_post_json_and_server_token(monkeypatch):
    seen = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return json.dumps(CASE).encode()
    def urlopen(req, timeout):
        seen.append(req)
        return Response()
    monkeypatch.setattr(app, 'CASE_API_URL', 'http://case.test')
    monkeypatch.setattr(app, 'CASE_API_TOKEN', 'server-session')
    monkeypatch.setattr(app.urllib.request, 'urlopen', urlopen)
    assert app.case_action('abc123', 'notes', request(), {'text': 'hello'}) == CASE
    sent = seen[0]
    assert sent.full_url == 'http://case.test/cases/abc123/notes'
    assert sent.get_method() == 'POST'
    assert sent.headers['Authorization'] == 'Bearer server-session'
    assert sent.headers['Content-type'] == 'application/json'
    assert json.loads(sent.data) == {'text': 'hello'}
    monkeypatch.setattr(app, 'CASE_API_TOKEN', '')
    assert app.case_detail('abc123', request()).status_code == 503
    assert len(seen) == 1
