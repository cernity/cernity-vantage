/* Cernity Vantage — Overview view module (plan 012 V1). Queue-centric graphite console.
   Depends on globals from index.html: req(), esc(), $(), show(), openFinding(), relatedEve().
   Investigation queue is the centerpiece; live signals collapse to a right rail; charts + pipeline
   are a supporting band. V1 wires the queue to recent retained findings (labeled recent, not ranked);
   revision-deduped classification analytics are V3. */
(function(){
  "use strict";
  var QFILTER = "priority";                 // priority | needs | all
  var OVRANGE = "1h";
  var _open = null;                          // expanded finding_id
  // U5 caps [from,to) to from+MAX_WINDOW (1 day) and its upper bound is EXCLUSIVE (normalized_time <
  // until). To keep the finding instant t INSIDE the window we ask for [t+LEAD−MAX_WINDOW, t+LEAD): a
  // full day back, ending just past t — the cap never bites (window == MAX_WINDOW) and t is included.
  var EV_MAX_WINDOW_MS = 864e5, EV_LEAD_MS = 1000;

  function qmeta(q){return {fresh:['q-fresh','measured'],stale:['q-stale','stale'],error:['q-error','unavailable'],
    unsupported:['q-unsupported','not deployed'],no_data:['q-no_data','no data']}[q]||['q-unsupported',String(q)];}
  function sdot(c){ // color a required check by measured STATE when fresh (V0 semantics), else quality
    if(c.quality==='fresh'){var m={ok:'s-ok',degraded:'s-degraded',down:'s-down',unknown:'s-unknown'}[c.state]||'s-unknown';
      return '<span class="ovdot '+m+'"></span>';}
    return '<span class="ovdot '+qmeta(c.quality)[0]+'"></span>';}
  function slabel(c){ if(c.quality==='fresh') return {ok:'ok',degraded:'degraded',down:'DOWN',unknown:'measured'}[c.state]||esc(c.state); return qmeta(c.quality)[1]; }
  function unwrap(r){ return (r && r.ok) ? r.data : null; }   // req() returns {ok,data,...}

  window.ovSetRange = function(r){ OVRANGE = r; document.querySelectorAll('#ov-range button').forEach(function(b){b.classList.toggle('on',b.dataset.r===r);}); loadOverview(); };
  window.ovSetFilter = function(f){ QFILTER = f; document.querySelectorAll('#ov-qfilters button').forEach(function(b){b.classList.toggle('on',b.dataset.f===f);}); loadQueue(); };
  window.ovToggleRow = function(fid){ _open = (_open===fid)?null:fid; renderQueue(window._ovFindings||[]); };

  // ---- data ----
  var RANGE_S={'15m':900,'1h':3600,'6h':21600,'24h':86400};
  async function loadOverview(){
    $('ov-updated').textContent='loading…';
    var ws=RANGE_S[OVRANGE]||3600, step=Math.max(15, Math.floor(ws/300));   // <=300 points/series
    var snap = unwrap(await req('/api/overview/snapshot?window_s='+ws+'&step_s='+step));   // one coordinated call
    if(!snap){ var st=$('ov-status'); st.className='ovstatus'; st.innerHTML='<span class="ovdot s-unknown"></span> overview unavailable'; $('ov-updated').textContent='error'; return; }
    renderStatusAndSignals(snap.health, snap.cernity);
    renderOps(snap.cernity, snap.traffic);
    await loadQueue();
    loadAnalytics();
    loadFleet();
    loadCoverage();
    loadQuality();
    $('ov-updated').textContent='updated '+new Date().toLocaleTimeString()+(snap.cached?' · cached '+snap.age_s+'s':'');
  }
  async function loadAnalytics(){
    var a=unwrap(await req('/api/overview/analytics')); var el=$('ov-analytics'); if(!el) return;
    if(!a){ el.innerHTML='<div class="ovcard"><div class="ov-q">analytics unavailable</div></div>'; return; }
    var c=a.classification||{}, e=a.evidence||{};
    var cats=(c.categories||[]); var maxc=Math.max.apply(null,cats.map(function(x){return x.revision_docs;}).concat([1]));
    var mix = (c.quality==='error') ? '<div class="ov-q">unavailable ('+esc(c.reason||'')+')</div>' :
      '<div class="ov-q" style="margin-bottom:8px"><b class="num" style="color:var(--ink)">'+esc(c.unique_findings)+'</b> unique findings · '
        +'<span class="num">'+esc(c.revision_docs)+'</span> revision docs · <span class="num">'+esc(c.needs_classification_unique)+'</span> need classification</div>'
      + cats.map(function(x){ return '<div style="display:grid;grid-template-columns:120px 1fr 48px;gap:8px;align-items:center;margin-bottom:6px;font-size:12px"><span>'+esc(x.category)+'</span><div style="height:12px;background:#0e1a2a;border-radius:4px;overflow:hidden"><div style="height:100%;width:'+Math.round(x.revision_docs/maxc*100)+'%;background:linear-gradient(90deg,var(--cyan),#2f9fb5)"></div></div><span class="num" style="text-align:right;color:var(--mut)">'+esc(x.revision_docs)+'</span></div>'; }).join('');
    var evd = (e.quality==='error') ? '<div class="ov-q">unavailable</div>' :
      '<div class="ov-q"><b class="num" style="color:var(--ink)">'+esc(e.with_evidence_refs)+'</b> / '+esc(e.total_docs)+' docs carry an evidence reference · '+esc(e.without_evidence_refs)+' without</div>';
    el.innerHTML='<div class="ovcard"><h2>Classification mix</h2><div class="sub">'+esc(c.note||'over revision documents; unique deduped by finding_id')+'</div>'+mix+'</div>'
      +'<div class="ovcard"><h2>Evidence coverage</h2><div class="sub">'+esc(e.note||'')+'</div>'+evd+'</div>';
  }
  // U10 (A): FLEET-HEALTH panel — sensors + clock-skew flags from the read-only fleet API proxy.
  // A degraded/unreachable upstream returns quality:'unavailable' -> a measured message, never a throw.
  async function loadFleet(){
    var el=$('ov-fleet'); if(!el) return;
    var f=unwrap(await req('/api/fleet/health'));
    if(!f || f.quality==='unavailable'){ el.innerHTML='<div class="ovcard"><h2>Fleet health</h2><div class="ov-q">unavailable'+((f&&f.reason)?' ('+esc(f.reason)+')':'')+' — fleet API not wired or unreachable</div></div>'; return; }
    var sensors=f.sensors||[];
    if(!sensors.length){ el.innerHTML='<div class="ovcard"><h2>Fleet health</h2><div class="ov-q">no sensors reported</div></div>'; return; }
    var rows=sensors.map(function(s){
      var hm={ok:'s-ok',healthy:'s-ok',degraded:'s-degraded',down:'s-down',stale:'s-degraded'}[s.health]||'s-unknown';
      var skew=(s.clock_skew_s!=null)?(esc(s.clock_skew_s)+'s'):'—';
      var skewChip=s.clock_skew_flag?'<span class="tag" style="border-color:var(--amber)">⚠ clock skew '+skew+'</span>':'<span class="tag">skew '+skew+'</span>';
      var staleChip=s.stale?'<span class="tag" style="border-color:var(--amber)">stale</span>':'';
      return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px"><span class="ovdot '+hm+'"></span><b style="min-width:150px">'+esc(s.sensor_id)+'</b><span class="ov-q" style="min-width:70px">'+esc(s.health)+'</span>'+staleChip+skewChip+'</div>';
    }).join('');
    el.innerHTML='<div class="ovcard"><h2>Fleet health</h2><div class="sub">sensors reporting to the read-only fleet API · skew flagged by the registry above '+esc(f.skew_warn_ms)+'ms</div>'+rows+'</div>';
  }
  // U6 (B): ATT&CK COVERAGE grid — one cell per technique, three honest states: gap (no detector),
  // detector-only (covered, not observed), observed (covered AND fired). Color marks STATE, never a
  // verdict; the title text carries the meaning. Pure render, no inline handlers, esc() on every value.
  // A degraded/unreachable upstream returns quality:'unavailable' -> a measured message, never a throw.
  async function loadCoverage(){
    var el=$('ov-coverage'); if(!el) return;
    var c=unwrap(await req('/api/coverage'));
    if(!c || c.quality==='unavailable'){ el.innerHTML='<div class="ovcard"><h2>ATT&CK coverage</h2><div class="ov-q">unavailable'+((c&&c.reason)?' ('+esc(c.reason)+')':'')+' — coverage API not wired or unreachable</div></div>'; return; }
    var techs=c.techniques||[];
    if(!techs.length){ el.innerHTML='<div class="ovcard"><h2>ATT&CK coverage</h2><div class="ov-q">no techniques in the coverage catalog</div></div>'; return; }
    var cells=techs.map(function(t){
      var cls=!t.covered?'cov-gap':(t.observed?'cov-observed':'cov-exists');
      var lbl=!t.covered?'gap — no detector':(t.observed?'observed firing (tenant)':'detector exists, not observed');
      var dets=Array.isArray(t.detectors)?t.detectors:[];
      // untrusted values (technique/name/detectors from config + findings) only ever land in an
      // esc()'d title attribute — never in an inline handler code string.
      var title=esc(t.technique)+(t.name?' '+esc(t.name):'')+' — '+lbl+(dets.length?' · '+esc(dets.join(', ')):'');
      return '<div class="covcell '+cls+'" title="'+title+'"><span class="covid">'+esc(t.technique)+'</span><span class="covn">'+esc(t.name||t.tactic||'')+'</span></div>';
    }).join('');
    var gaps=(c.gaps||[]).length, n=techs.length;
    var sub='exists = a detector maps to it · observed = it actually fired (tenant-scoped) · gap = no detector · '
      +'<b class="num" style="color:var(--red)">'+esc(gaps)+'</b> gap'+(gaps===1?'':'s')+' of <span class="num">'+esc(n)+'</span> techniques';
    el.innerHTML='<div class="ovcard"><h2>ATT&CK coverage</h2><div class="sub">'+sub+'</div><div class="covgrid">'+cells+'</div></div>';
  }
  // U6 (B): DETECTION QUALITY table — per-detector precision/FP (finding-joined) + the SEPARATE
  // advisory entity-allowlist rate (never folded into a detector's precision). Wilson interval +
  // low-confidence flag surfaced honestly; thin data reads low-confidence, not spuriously precise.
  function _qpct(r){
    if(!r || r.value==null) return '<span class="ov-q">n/a</span>';
    var lc=r.low_confidence?' <span class="tag" style="border-color:var(--amber);color:var(--amber)">low-confidence n='+esc(r.denominator)+'</span>':'';
    return '<b class="num">'+esc((r.value*100).toFixed(1))+'%</b> <span class="ov-q num">('+esc(r.numerator)+'/'+esc(r.denominator)+')</span>'+lc;
  }
  async function loadQuality(){
    var el=$('ov-quality'); if(!el) return;
    var q=unwrap(await req('/api/quality'));
    if(!q || q.quality==='unavailable'){ el.innerHTML='<div class="ovcard"><h2>Detection quality</h2><div class="ov-q">unavailable'+((q&&q.reason)?' ('+esc(q.reason)+')':'')+' — quality API not wired or unreachable</div></div>'; return; }
    var dets=q.detectors||[];
    var win=q.window?' · '+esc(String(q.window.from||'').slice(0,10))+'→'+esc(String(q.window.to||'').slice(0,10)):'';
    var alLine='<div class="ov-q" style="margin-bottom:9px">advisory allowlist-suggestion rate <span title="entity-scoped analyst suggestions — NOT detector precision">(entity-scoped, advisory)</span>: '+_qpct(q.entity_allowlist_suggestion_rate)+'</div>';
    var sub='per-detector precision/FP from confirmed vs benign/FP dispositions · advisory only'+win;
    if(!dets.length){ el.innerHTML='<div class="ovcard"><h2>Detection quality</h2><div class="sub">'+sub+'</div>'+alLine+'<div class="ov-q">no per-detector dispositions in this window</div></div>'; return; }
    var rows=dets.map(function(d){
      var counts=d.counts||{};
      return '<tr><td><b>'+esc(d.detector_id)+'</b></td><td>'+_qpct(d.precision)+'</td><td>'+_qpct(d.fp_rate)+'</td>'
        +'<td class="num">'+esc(counts.true_positive||0)+' / '+esc(counts.false_positive||0)+' / '+esc(counts.benign||0)+'</td></tr>';
    }).join('');
    el.innerHTML='<div class="ovcard"><h2>Detection quality</h2><div class="sub">'+sub+'</div>'+alLine
      +'<table class="covtable"><thead><tr><th>detector</th><th>precision</th><th>FP rate</th><th title="confirmed / false-positive / benign disposition counts">TP / FP / benign</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  }
  async function loadQueue(){
    // tiered queue: Priority=threat+lead, Low-signal, Needs-classification, Allowlisted, All.
    // Tier ranks by category-class × confidence × disposition (a lead aid, never a verdict).
    var r = unwrap(await req('/api/overview/queue?tier='+encodeURIComponent(QFILTER)+'&size=250'));
    var rows = (r && r.rows) || [];
    window._ovFindings = rows; window._ovCounts = (r && r.counts) || {}; window._ovScanned = (r && r.total_scanned) || 0;
    renderQueue(rows);
  }

  // ---- render ----
  function renderStatusAndSignals(h, cer){
    var st=$('ov-status');
    if(!h){ st.className='ovstatus'; st.innerHTML='<span class="ovdot s-unknown"></span> monitoring unavailable'; }
    else {
      st.className='ovstatus '+(h.verdict||'amber');
      var cov=h.coverage||{}; var iss=(h.checks||[]).filter(function(c){return c.state==='down'||c.state==='degraded';})
        .map(function(c){return c.metric_id+(c.reason?' ('+c.reason.split(',')[0]+')':'');});
      st.innerHTML='<span class="ovdot s-'+({green:'ok',amber:'degraded',red:'down'}[h.verdict]||'unknown')+'"></span>'
        +'<b>'+esc(({green:'Healthy',amber:'Attention',red:'Critical'}[h.verdict]||h.verdict||'—'))+'</b>'
        +'<span class="cov">· '+esc(cov.healthy!=null?cov.healthy:'?')+'/'+esc(cov.expected!=null?cov.expected:'?')+' required checks measured</span>'
        +(iss.length?'<span class="issue">⚠ '+esc(iss.slice(0,2).join(' · '))+'</span>':'');
    }
    // signal rail: pull compact live numbers from health checks + cernity metrics
    function firstVal(env){ return (env && env.value && env.value[0] && env.value[0].v!=null) ? env.value[0].v : null; }
    var cm=(cer&&cer.metrics)||{};
    function fmt(n,suf){ if(n==null) return '—'; return (typeof n==='number'? (n>=1e6?(n/1e6).toFixed(2)+'M':n>=1000?(n/1000).toFixed(1)+'k':(n%1?n.toFixed(2):n)) : n)+(suf?'<small> '+suf+'</small>':''); }
    var sig=[
      ['Candidate activity', firstVal(cm.detector_activity), '/s', 'ok'],
      ['Final-topic', firstVal(cm.final_topic_throughput), '/s', 'ok'],
      ['Enrichment pending', firstVal(cm.enrichment_pending), '', 'ok'],
      ['Consumer backlog', firstVal(cm.consumer_lag), 'records', firstVal(cm.consumer_lag)>100000?'warn':'ok'],
      ['Delivery obligations', firstVal(cm.dlq_unresolved), 'unresolved', 'ok']
    ];
    $('ov-signal').innerHTML = sig.map(function(s){ return '<div class="sig'+(s[3]==='warn'?' warn':'')+'"><div class="l"><span class="ovdot '+(s[3]==='warn'?'s-degraded':'s-ok')+'"></span>'+esc(s[0])+'</div><div class="v num">'+fmt(s[1],s[2])+'</div></div>'; }).join('');
  }

  function sevColor(sev){ sev=+sev||0; return sev>=8?'var(--red)':sev>=6?'var(--red)':sev>=4?'var(--amber)':'#3f6f8a'; }
  function findingHeadline(f){ return f.summary || f.assertion || f.title || ((f.category||'finding')+' — '+((f.entities&&f.entities[0]&&(f.entities[0].value||f.entities[0].id))||f.finding_id||'')); }

  function tierChip(t){var m={threat:['q-error','threat'],lead:['q-stale','lead'],low_signal:['q-unsupported','low-signal'],needs_classification:['q-stale','needs classification'],observation:['q-unsupported','observation'],benign:['q-fresh','allowlisted']}[t]||['q-unsupported',t||'?'];
    return '<span class="tag"><span class="ovdot '+m[0]+'" style="width:7px;height:7px;margin-right:4px"></span>'+esc(m[1])+'</span>';}
  function dstIp(f){var es=Array.isArray(f.entities)?f.entities:[];var e=es.filter(function(x){return x&&x.type==='ip'&&x.role==='dst';})[0];return e&&e.value;}
  function dstAsn(f){var g=f.geo||{};for(var ip in g){if(g[ip]&&g[ip].as_org)return g[ip].as_org;}return null;}
  function renderQueue(rows){
    var c=window._ovCounts||{};
    $('ov-qcount').innerHTML='<b>'+rows.length+'</b> shown · <span class="num">'+((c.threat||0)+(c.lead||0))+'</span> priority · '+(c.low_signal||0)+' low-signal · '+(c.benign||0)+' allowlisted <span style="color:var(--mut)">(of '+(window._ovScanned||0)+' recent)</span>';
    if(!rows.length){ $('ov-qlist').innerHTML='<div class="qempty">Nothing in this tier. Triage tier is a lead-ordering aid, not a verdict — use All or Allowlisted to see every finding.</div>'; return; }
    $('ov-qlist').innerHTML = rows.map(function(f){
      var fid=f.finding_id||f.id||''; var sev=f.severity!=null?f.severity:'?';
      var det=f.detector_id||f.detector||''; var cat=f.category||''; var conf=f.confidence;
      var open=(fid===_open);
      var meta=tierChip(f.tier)+'<span class="tag">'+esc(det||cat||'finding')+'</span>'
        +'<span class="tag">sev '+esc(sev)+(conf!=null?' · conf '+esc((+conf).toFixed(2)):'')+'</span>'
        +(f.allowlisted_by?'<span class="tag ok">allowlisted: '+esc(f.allowlisted_by)+'</span>':'');
      var when=f.last_seen||f.emitted_at||f.ts||f['@timestamp']||''; when=when?String(when).replace('T',' ').replace(/\..*/,'Z'):'';
      if(open){
        var dip=dstIp(f), das=dstAsn(f);
        // untrusted values (dip/das from monitored traffic, F08) go in data-* attrs — never built into
        // an onclick JS string, where HTML-entity decoding would let a crafted value break out (XSS).
        var alBtns=(dip?'<button class="ovbtn" data-al-field="dst_ip" data-al-value="'+esc(dip)+'">Allowlist dst '+esc(dip)+'</button>':'')
          +(das?'<button class="ovbtn" data-al-field="dst_asn" data-al-value="'+esc(das)+'">Allowlist ASN '+esc(das)+'</button>':'')
          +(cat?'<button class="ovbtn" data-al-field="category" data-al-value="'+esc(cat)+'">Allowlist category '+esc(cat)+'</button>':'');
        return '<div class="qrow open" data-fid="'+esc(fid)+'"><div class="sev" style="background:'+sevColor(sev)+'"></div><div>'
          +'<h3>'+esc(findingHeadline(f))+'</h3><div class="basis">basis: '+esc(cat||det||'—')+' · '+esc((f.entities&&f.entities[0]&&(f.entities[0].value||f.entities[0].id))||'')+'</div>'
          +'<div class="meta">'+meta+'</div>'
          +'<div class="qdetail"><div class="assert"><b>Triage:</b> '+esc(f.tier_reason||'—')+'</div>'
          +'<div class="lim">Severity is a basis signal, classification is a lead — not a verdict or a threat count.</div>'
          +'<div class="ev"><span class="chip">detector: '+esc(det||'—')+'</span><span class="chip">retained in SIEM</span></div>'
          +'<div class="act"><button class="ovbtn p" data-open="'+esc(fid)+'">Open finding</button>'
          +'<button class="ovbtn" data-related="'+esc(fid)+'">Find related EVE</button>'
          +'<button class="ovbtn" data-evidence="'+esc(fid)+'">Evidence</button></div>'
          +'<div class="evbox" data-evbox="1"></div>'   // U10 (B): evidence-pivot drawer (one open row at a time)
          +(alBtns?'<div class="act" style="margin-top:6px"><span class="ov-q" style="align-self:center;margin-right:4px">mark benign (retained, off Priority):</span>'+alBtns+'</div>':'')
          +'</div></div></div>';  // close .qdetail, content <div>, and .qrow.open (was missing → next rows nested in the open card)
      }
      return '<div class="qrow" data-fid="'+esc(fid)+'"><div class="sev" style="background:'+sevColor(sev)+'"></div>'
        +'<div><h3>'+esc(findingHeadline(f))+'</h3><div class="meta">'+meta+'</div></div>'
        +'<div class="when">'+esc(when)+'</div></div>';
    }).join('');
    bindQueue();
  }
  // bind handlers directly after each render — reads data-* (no inline onclick, no untrusted data in
  // code strings). .onclick (not addEventListener) so re-renders never stack duplicate handlers.
  function bindQueue(){ var list=$('ov-qlist'); if(!list) return;
    list.querySelectorAll('[data-fid]').forEach(function(el){ el.onclick=function(){ ovToggleRow(el.dataset.fid); }; });
    list.querySelectorAll('[data-open]').forEach(function(el){ el.onclick=function(e){ e.stopPropagation(); ovOpen(el.dataset.open); }; });
    list.querySelectorAll('[data-related]').forEach(function(el){ el.onclick=function(e){ e.stopPropagation(); ovRelated(el.dataset.related); }; });
    list.querySelectorAll('[data-al-field]').forEach(function(el){ el.onclick=function(e){ e.stopPropagation(); ovAllowlist(el.dataset.alField, el.dataset.alValue); }; });
    list.querySelectorAll('[data-evidence]').forEach(function(el){ el.onclick=function(e){ e.stopPropagation(); ovEvidence(el.dataset.evidence); }; });
  }
  // U10 (B): EVIDENCE-PIVOT — from the open finding, list normalized observations WITH their
  // capability flags (provenance, not a verdict). data-* + delegation, never untrusted data in a
  // code string. Unreachable upstream -> a measured 'unavailable' line, never a throw.
  // one entity value + a bounded window off the open finding — U5 is entity+window scoped, not keyed
  // by finding_id. The window is [t+LEAD−MAX_WINDOW, t+LEAD) so U5's 1-day cap never bites and the
  // finding instant t is INSIDE the half-open window (an earlier [t−24h,t+1s) was capped to [t−24h,t),
  // dropping the observation at exactly t).
  function evidenceQuery(fid){
    var f=(window._ovFindings||[]).filter(function(x){return (x.finding_id||x.id)===fid;})[0]||{};
    var ent=(Array.isArray(f.entities)?f.entities:[]).map(function(e){return e&&(e.value||e.id);}).filter(Boolean)[0];
    var when=f.ts||f['@timestamp']||f.last_seen||f.emitted_at;
    if(!ent||!when) return null;
    var t=new Date(when).getTime(); if(isNaN(t)) return null;
    var to=t+EV_LEAD_MS, frm=to-EV_MAX_WINDOW_MS;
    return 'entity='+encodeURIComponent(ent)+'&frm='+encodeURIComponent(new Date(frm).toISOString())
      +'&to='+encodeURIComponent(new Date(to).toISOString());
  }
  window.ovEvidence = async function(fid){
    // scope the drawer to the OPEN row only; there is one open at a time (.qrow.open).
    var box=document.querySelector('.qrow.open [data-evbox]'); if(box) box.innerHTML='<span class="ov-q">loading evidence…</span>';
    var qs=evidenceQuery(fid);
    if(!qs){ if(box) box.innerHTML='<span class="ov-q">no entity/timestamp on this finding to pivot on</span>'; return; }
    var e=unwrap(await req('/api/evidence/'+encodeURIComponent(fid)+'?'+qs));
    // defect: a late/stale response must fill ONLY the finding it was requested for. If the open row
    // changed (or closed) while this was in flight, drop it — never overwrite a different drawer.
    if(_open!==fid) return;
    box=document.querySelector('.qrow.open [data-evbox]'); if(!box) return;
    if(!e || e.quality==='unavailable'){ box.innerHTML='<span class="ov-q">evidence unavailable'+((e&&e.reason)?' ('+esc(e.reason)+')':'')+'</span>'; return; }
    var obs=e.observations||[];
    if(!obs.length){ box.innerHTML='<span class="ov-q">no observations in this window</span>'; return; }
    box.innerHTML=obs.map(function(o){
      // preserve normalized detail: type + time + capability flags (a list; provenance, not a
      // verdict) + a few observation fields. esc() on every untrusted value; no inline handlers.
      var caps=Array.isArray(o.capabilities)?o.capabilities:[];
      var chips=caps.map(function(k){return '<span class="tag">'+esc(k)+'</span>';}).join('');
      var flds=o.fields||{}; var detail=Object.keys(flds).slice(0,8).map(function(k){return esc(k)+'='+esc(flds[k]);}).join(' · ');
      var when=o.ts?String(o.ts).replace('T',' ').replace(/\..*/,'Z'):'';
      return '<div style="padding:3px 0;font-size:12px"><b>'+esc(o.type||o.kind||'obs')+'</b> <span class="ov-q">'+esc(when)+'</span> '+chips
        +(detail?'<div class="ov-q mono" style="margin-top:2px">'+detail+'</div>':'')+'</div>';
    }).join('')
      // U5 bounds the response (window/page cap): when it hands back a continuation, DISCLOSE that
      // this is a partial page rather than silently presenting it as the whole window.
      +(e.next?'<div class="ov-q" style="margin-top:4px">⋯ more observations exist beyond this page (U5 window/page cap) — showing the first '+obs.length+'.</div>':'');
  };
  window.ovAllowlist = async function(field, value){
    var reason = window.prompt('Allowlist '+field+' = '+value+' as benign?\nReason (kept for audit):', 'known-benign');
    if(reason===null) return;
    var r = await req('/api/allowlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({field:field,value:value,reason:reason})});
    if(r&&r.ok){ _open=null; loadQueue(); } else { alert('allowlist failed: '+((r&&r.error)||'error')); }
  };
  window.ovOpen = function(fid){ show('findings'); if(typeof openFinding==='function') openFinding(fid,'f-detail'); };
  window.ovRelated = function(fid){ var f=(window._ovFindings||[]).find(function(x){return (x.finding_id||x.id)===fid;}); if(f&&typeof relatedEve==='function') relatedEve(f); };

  var TRIO=[['records_processed','records','var(--cyan)'],['detector_activity','candidates','var(--violet)'],['final_topic_throughput','finals','var(--green)']];
  window._ovCer=null;
  function renderOps(cer, tr){
    window._ovCer=cer;
    var s=(tr&&tr.series)||{};
    var trioHTML=TRIO.map(function(t){return '<div><div class="ov-q" style="margin-bottom:3px">'+esc(t[1])+'</div><div id="chart-'+t[0]+'" style="height:118px"></div></div>';}).join('');
    $('ov-ops').innerHTML='<div class="ovcard"><h2>Telemetry activity</h2><div class="sub">processed · candidates · finals — shared cursor, separate scales, gaps preserved</div>'
      +'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">'+trioHTML+'</div>'
      +'<details style="margin-top:8px"><summary class="ov-q" style="cursor:pointer">data tables (keyboard-accessible values)</summary><div id="ov-tables" style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;overflow:auto"></div></details></div>'
      +'<div class="ovcard"><h2>Pipeline</h2><div class="sub">topology + state — click a node</div><div id="ov-pipe"></div><div id="ov-pipe-drawer" class="ov-q" style="margin-top:8px;min-height:18px"></div></div>';
    // ECharts trio + shared cursor + accessible tables
    var ids=[]; TRIO.forEach(function(t){ var env=s[t[0]]; if(env&&window.VantageCharts){ VantageCharts.render('chart-'+t[0], env, {color:t[2], area:t[0]==='records_processed'}); if(env.quality==='fresh'||env.quality==='stale') ids.push('chart-'+t[0]); } });
    if(window.VantageCharts) VantageCharts.connect(ids);
    if(window.VantageCharts) $('ov-tables').innerHTML=TRIO.map(function(t){var env=s[t[0]];return (env&&(env.quality==='fresh'||env.quality==='stale'))?VantageCharts.dataTableHTML(env):'';}).join('')||'<span class="ov-q">no series</span>';
    renderPipe(cer);
  }
  function renderPipe(cer){
    var stages=(cer&&cer.stages)||['sensor','fluent-bit','redpanda','detectors','finding-service','final-topic','forwarder','sinks'];
    var W=110, svg='<svg viewBox="0 0 '+(stages.length*W)+' 70" width="100%" height="70" style="overflow:visible">';
    stages.forEach(function(st,i){var x=i*W;
      if(i) svg+='<path d="M'+(x-14)+',35 L'+(x+2)+',35" stroke="#33506e" stroke-width="1.3" fill="none"/>';
      svg+='<g style="cursor:pointer" onclick="ovPipeNode(\''+esc(st)+'\')"><rect x="'+(x+4)+'" y="18" width="'+(W-22)+'" height="34" rx="7" fill="#0e1a2a" stroke="#1f5a4a"/><text x="'+(x+14)+'" y="38" fill="#E7F0FA" font-size="11" font-weight="600">'+esc(st)+'</text></g>';
    });
    svg+='</svg>';
    $('ov-pipe').innerHTML=svg;
    $('ov-pipe-drawer').textContent='raw-EVE→SIEM fork and ClickHouse persist branch are separate paths — click a node for its source, rate and backlog.';
  }
  window.ovPipeNode=function(stage){
    var cer=window._ovCer||{}; var m=cer.metrics||{};
    var map={detectors:'detector_activity','finding-service':'enrichment_pending','final-topic':'final_topic_throughput',forwarder:'dlq_unresolved',redpanda:'consumer_lag'};
    var mid=map[stage]; var env=mid&&m[mid];
    var v=(env&&env.value&&env.value[0]&&env.value[0].v); var q=env?env.quality:null;
    $('ov-pipe-drawer').innerHTML='<b style="color:var(--ink)">'+esc(stage)+'</b> — '+(env?('metric '+esc(mid)+': '+(v==null?'—':esc(v))+' ('+esc(qmeta(q)[1])+')'):'no scoped metric for this node (topology only)');
  };

  window.loadOverview = loadOverview;
  window._evidenceQuery = evidenceQuery;   // ponytail: test seam so the U5 window boundary is node-checkable
  // Overview is the default landing; activate it once the DOM + shared helpers are ready.
  if(typeof show==='function'){ show('overview'); }
})();

// U9 cases: server-side proxy, data attributes and bound handlers only.
(function(){
  'use strict';
  var offset=0, next=null, listGeneration=0, detailGeneration=0, selected=null;
  var statuses=['new','investigating','resolved','closed'];
  function caseError(r){return r&&r.status>=400&&r.status<500 ? (r.error||'Case request rejected') : 'Case API unavailable';}
  window.loadCases=async function(){
    var generation=++listGeneration;
    $('case-list').textContent='Loading cases…';
    $('case-prev').disabled=true; $('case-next').disabled=true;
    var query=new URLSearchParams({limit:50,offset:offset});
    var owner=$('case-owner-filter').value.trim(), status=$('case-status-filter').value;
    if(owner) query.set('owner',owner); if(status) query.set('status',status);
    var r=await req('/api/cases?'+query);
    if(generation!==listGeneration) return;
    if(!r.ok||!r.data||r.data.quality==='unavailable'){$('case-list').textContent=caseError(r);return;}
    var d=r.data; next=d.next_offset;
    $('case-list').innerHTML=d.cases.length?'<table class="dt"><thead><tr><th>Case</th><th>Status</th><th>Owner</th><th>Assignees</th></tr></thead><tbody>'+d.cases.map(function(c){
      return '<tr><td><button class="btn" data-case-id="'+esc(c.case_id)+'">'+esc(c.title)+'</button></td><td>'+esc(c.status)+'</td><td>'+esc(c.owner||'Unassigned')+'</td><td>'+esc(c.assignees.join(', '))+'</td></tr>';
    }).join('')+'</tbody></table>':'<div class="empty">No matching cases.</div>';
    $('case-list').querySelectorAll('[data-case-id]').forEach(function(el){el.onclick=function(){openCase(el.dataset.caseId);};});
    $('case-prev').disabled=offset===0; $('case-next').disabled=next===null;
  };
  async function openCase(id){
    selected=id; var generation=++detailGeneration;
    $('case-detail').textContent='Loading case…';
    var r=await req('/api/cases/'+encodeURIComponent(id));
    if(generation!==detailGeneration) return;
    if(!r.ok||!r.data||r.data.quality==='unavailable'){$('case-detail').textContent=caseError(r);return;}
    renderCase(r.data);
  }
  function renderCase(c){
    var box=$('case-detail');
    box.innerHTML='<h2>'+esc(c.title)+'</h2><p class="note">Case '+esc(c.case_id)+' · Tenant '+esc(c.tenant)+' · '+esc(c.status)+'</p>'
      +'<div class="actions"><label>Owner <input data-case="owner" maxlength="256" value="'+esc(c.owner||'')+'"></label><button class="btn" data-action="owner">Set owner</button>'
      +'<label>Assignee <input data-case="assignee" maxlength="256"></label><button class="btn" data-action="assign">Assign</button>'
      +'<label>Status <select data-case="status">'+statuses.map(function(s){return '<option'+(s===c.status?' selected':'')+'>'+s+'</option>';}).join('')+'</select></label><button class="btn" data-action="status">Change status</button></div>'
      +'<p>Assignees: '+esc(c.assignees.join(', ')||'None')+'</p>'
      +'<h3>Linked findings</h3><div>'+c.linked_findings.map(function(f){return '<button class="btn" data-case-finding="'+esc(f)+'">'+esc(f)+'</button>';}).join('')+'</div>'
      +'<div class="actions"><label>Finding ID <input data-case="finding_id" maxlength="256"></label><button class="btn" data-action="findings">Link finding</button></div>'
      +'<h3>Linked entities</h3><div>'+c.linked_entities.map(function(e){return '<div>'+esc(e.type)+': '+esc(e.value)+'</div>';}).join('')+'</div>'
      +'<div class="actions"><label>Entity type <select data-case="entity-type"><option>ip</option><option>hostname</option><option>domain</option><option>asset</option></select></label><label>Value <input data-case="entity-value" maxlength="512"></label><button class="btn" data-action="entities">Link entity</button></div>'
      +'<h3>Notes</h3>'+c.notes.map(function(n){return '<div class="noteitem"><div class="ts">'+esc(n.author)+' · '+esc(n.ts)+'</div>'+esc(n.text)+'</div>';}).join('')
      +'<label>New note <textarea data-case="text" maxlength="8192" rows="3"></textarea></label><button class="btn" data-action="notes">Add note</button><p data-case="message" role="status"></p>';
    box.querySelectorAll('[data-case-finding]').forEach(function(el){el.onclick=function(){show('findings');openFinding(el.dataset.caseFinding,'f-detail');};});
    box.querySelectorAll('[data-action]').forEach(function(el){el.onclick=function(){mutateCase(c.case_id,el.dataset.action,box);};});
  }
  async function mutateCase(id,action,box){
    var field={owner:'owner',assign:'assignee',status:'status',notes:'text',findings:'finding_id',entities:'entity'}[action];
    var value=action==='entities'?{type:box.querySelector('[data-case="entity-type"]').value,value:box.querySelector('[data-case="entity-value"]').value.trim()}:box.querySelector('[data-case="'+field+'"]').value.trim();
    if(action==='owner'&&!value) value=null;
    var body={}; body[field]=value;
    var generation=detailGeneration;
    box.querySelectorAll('[data-action]').forEach(function(b){b.disabled=true;});
    var r=await req('/api/cases/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(generation!==detailGeneration||selected!==id) return;
    if(!r.ok||!r.data||r.data.quality==='unavailable'){
      box.querySelector('[data-case="message"]').textContent=caseError(r);
      box.querySelectorAll('[data-action]').forEach(function(b){b.disabled=false;});return;
    }
    renderCase(r.data); // display authoritative returned state, including author and notes
    $('case-detail').querySelector('[data-case="message"]').textContent='Saved';
    await loadCases();
  }
  // Keep this module importable by the existing DOM-free evidence tests.
  if(typeof $!=='function'||!$('tab-cases')) return;
  $('tab-cases').onclick=function(){show('cases');};
  $('case-filter').onclick=function(){offset=0;loadCases();};
  $('case-prev').onclick=function(){offset=Math.max(0,offset-50);loadCases();};
  $('case-next').onclick=function(){if(next!==null){offset=next;loadCases();}};
})();
