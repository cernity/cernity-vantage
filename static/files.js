// U6 files: read-only file-observation / YARA-hit view over the evidence API (server-side proxy).
// Mirrors the U9 cases + evidence-pivot views: server-derived tenant, no token/URL in the browser,
// data-* attributes and bound handlers only (no inline onclick), every untrusted value through esc().
// KTD2 is enforced server-side — a metadata_only/hashes_only file arrives with NO verdict — and is
// surfaced here as "metadata only — not scanned", never an implied clean/dirty.
(function(){
  'use strict';
  var generation=0;
  var _files=[];   // last-rendered set, keyed by obs_id, so a row click can open its detail.

  // Scan completion is EXPLICIT (server sends scan=completed|pending|failed|unscanned|unknown). Only a
  // COMPLETED scan may show a no-hit result; every other state is honest about the absence of a verdict.
  var _SCAN_CHIP={completed:'scanned',pending:'scan pending',failed:'scan failed',
                  unscanned:'not scanned',unknown:'scan status unknown'};

  // bytes-available / scan badges. Color marks STATE; the text label carries the meaning so it reads
  // without relying on color.
  function stateBadges(f){
    var scan=f.scan||(f.scanned?'completed':(f.bytes_available?'unknown':'unscanned'));
    return (f.bytes_available?'<span class="chip intel">bytes available</span>'
                             :'<span class="chip st">bytes unavailable</span>')
      +'<span class="chip '+(scan==='completed'?'intel':'st')+'">'+esc(_SCAN_CHIP[scan]||scan)+'</span>';
  }

  // KTD2 + scan-completion honesty: a YARA verdict (or a "no hit" result) exists ONLY for a file whose
  // scan COMPLETED. A file with bytes but a pending/failed/unknown scan, or no bytes at all, gets an
  // explicit no-verdict line — never a fabricated clean/dirty result.
  function verdict(f){
    if(!f.bytes_available) return '<div class="note">metadata only — not scanned</div>';
    var scan=f.scan||(f.scanned?'completed':'unknown');
    if(scan==='pending') return '<div class="note">bytes available · scan pending — no verdict yet</div>';
    if(scan==='failed')  return '<div class="note">bytes available · scan failed — no verdict</div>';
    if(scan!=='completed') return '<div class="note">bytes available · scan status unknown — no verdict</div>';
    var hits=Array.isArray(f.yara)?f.yara:[];
    if(!hits.length) return '<div class="note">scanned · no YARA hit</div>';
    return hits.map(function(h){
      return '<span class="chip vd">YARA hit: '+esc(h.rule)+(h.version?' v'+esc(h.version):'')+'</span>';
    }).join('');
  }

  function intelChip(f){
    var i=f.intel_hash_hit; if(!i) return '';
    var fid=i.finding_id||i.finding||'';
    var label='intel hash hit'+(i.indicator?': '+esc(i.indicator):'');
    // pivot to the linked finding when the hit carries one; else a plain chip.
    return fid?'<button class="btn" data-finding="'+esc(fid)+'"><span class="chip intel">'+label+'</span></button>'
              :'<span class="chip intel">'+label+'</span>';
  }

  function pivots(f){
    // Reference-aware pivots: the transfer flow (conn_uid/community_id/flow_id) and its PCAP
    // (pcap_filename) resolve by an EXACT match on that field — carried through as data-*-field so the
    // Suricata tab queries the exact field, never a full-text search that would miss an alertless flow.
    return (f.transfer_ref?'<button class="btn" data-transfer="'+esc(f.transfer_ref)+'" data-transfer-field="'+esc(f.transfer_field||'conn_uid')+'">Transfer evidence ↗</button>':'')
      +(f.pcap_ref?'<button class="btn" data-pcap="'+esc(f.pcap_ref)+'" data-pcap-field="'+esc(f.pcap_field||'pcap_filename')+'">PCAP ↗</button>':'');
  }

  function fileId(f){ return f.sha256||f.md5||f.obs_id||'?'; }

  function metaLine(f){
    return [f.mime,(f.size!=null?f.size+' bytes':null),
            (f.bytes_scanned!=null?f.bytes_scanned+' scanned':null)].filter(Boolean).map(esc).join(' · ');
  }

  function renderFiles(files){
    _files=Array.isArray(files)?files:[];
    var box=$('files-list');
    if(!_files.length){ box.innerHTML='<div class="empty">No file observations in this window.</div>'; clearDetail(); return; }
    box.innerHTML=_files.map(function(f){
      var meta=metaLine(f);
      // Row is a keyboard-operable button that opens the file detail (data-obs).
      return '<div class="qrow" data-obs="'+esc(f.obs_id)+'" role="button" tabindex="0" aria-label="File '+esc(fileId(f))+'">'
        +'<div class="mono">'+esc(fileId(f))+'</div>'
        +'<div style="margin:3px 0">'+stateBadges(f)+'</div>'
        +(meta?'<div class="note">'+meta+'</div>':'')
        +'<div style="margin:4px 0">'+verdict(f)+'</div>'
        +'<div>'+intelChip(f)+'</div>'
        +'<div class="actions" style="margin-top:6px">'+pivots(f)+'</div>'
        +'</div>';
    }).join('');
    box.querySelectorAll('[data-obs]').forEach(function(el){
      el.onclick=function(){selectFile(el.dataset.obs);};
      el.onkeydown=function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();selectFile(el.dataset.obs);}};
    });
    // Pivot/finding buttons stop the click from also opening/re-opening the row detail.
    box.querySelectorAll('[data-finding]').forEach(function(el){el.onclick=function(e){if(e)e.stopPropagation();show('findings');if(typeof openFinding==='function')openFinding(el.dataset.finding,'f-detail');};});
    box.querySelectorAll('[data-transfer]').forEach(function(el){el.onclick=function(e){if(e)e.stopPropagation();pivotSuricata(el.dataset.transfer,el.dataset.transferField);};});
    box.querySelectorAll('[data-pcap]').forEach(function(el){el.onclick=function(e){if(e)e.stopPropagation();pivotSuricata(el.dataset.pcap,el.dataset.pcapField);};});
  }
  window._renderFiles=renderFiles;   // ponytail: test seam for the node DOM smoke check

  function byObs(obsId){ for(var i=0;i<_files.length;i++){ if(_files[i].obs_id===obsId) return _files[i]; } return null; }

  function clearDetail(){ var d=$('files-detail'); if(d) d.innerHTML='<div class="empty">Select a file observation for its context and linked evidence.</div>'; }

  function selectFile(obsId){
    var f=byObs(obsId); var d=$('files-detail'); if(!d) return;
    if(!f){ clearDetail(); return; }
    var q=$('files-list');
    if(q&&q.querySelectorAll){ q.querySelectorAll('[data-obs]').forEach(function(el){ if(el.classList) el.classList.toggle('sel',el.dataset.obs===obsId); }); }
    d.innerHTML=renderDetail(f);
    d.querySelectorAll('[data-finding]').forEach(function(el){el.onclick=function(){show('findings');if(typeof openFinding==='function')openFinding(el.dataset.finding,'f-detail');};});
    d.querySelectorAll('[data-transfer]').forEach(function(el){el.onclick=function(){pivotSuricata(el.dataset.transfer,el.dataset.transferField);};});
    d.querySelectorAll('[data-pcap]').forEach(function(el){el.onclick=function(){pivotSuricata(el.dataset.pcap,el.dataset.pcapField);};});
  }
  window._selectFile=selectFile;     // ponytail: test seam — open a file's detail directly

  // File detail: observation context (hashes, ts, entities, source, capabilities) + KTD2-safe verdict +
  // linked evidence (intel finding, transfer flow, PCAP). Everything untrusted goes through esc().
  function renderDetail(f){
    var meta=metaLine(f);
    var ents=(Array.isArray(f.entities)?f.entities:[]).map(function(e){return '<span class="chip">'+esc(e)+'</span>';}).join('')||'<span class="note">none</span>';
    var caps=(Array.isArray(f.capabilities)?f.capabilities:[]).map(function(c){return '<span class="chip">'+esc(c)+'</span>';}).join('')||'<span class="note">none</span>';
    var links=pivots(f)||'<span class="note">no transfer/PCAP reference on this observation</span>';
    return '<div class="mono" style="font-size:13px">'+esc(fileId(f))+'</div>'
      +'<div style="margin:6px 0">'+stateBadges(f)+'</div>'
      +'<div style="margin:6px 0">'+verdict(f)+'</div>'
      +(f.intel_hash_hit?'<div style="margin:6px 0">'+intelChip(f)+'</div>':'')
      +'<div class="note" style="margin-top:10px">observation</div>'
      +'<div class="note">obs_id: '+esc(f.obs_id||'?')+'</div>'
      +'<div class="note">observed: '+esc(f.ts||'—')+'</div>'
      +(meta?'<div class="note">'+meta+'</div>':'')
      +(f.sha256?'<div class="note mono">sha256: '+esc(f.sha256)+'</div>':'')
      +(f.md5?'<div class="note mono">md5: '+esc(f.md5)+'</div>':'')
      +'<div class="note">source: '+esc(f.source_ref||'—')+'</div>'
      +'<div class="note" style="margin-top:10px">entities</div><div>'+ents+'</div>'
      +'<div class="note" style="margin-top:10px">capabilities</div><div>'+caps+'</div>'
      +'<div class="note" style="margin-top:10px">linked evidence</div>'
      +'<div class="actions" style="margin-top:4px">'+links+'</div>';
  }

  function pivotSuricata(ref,field){
    // Open the raw-EVE tab with the reference VISIBLE and editable. A transfer flow / PCAP capture
    // carries NO alert, so clear the alert-only + narrowing filters (mode->all, severity/event_type/
    // window cleared) and set the allowlisted `field` so the server resolves an EXACT term match.
    show('suricata');
    setVal('s-mode','all'); setVal('s-sev',''); setVal('s-type','');
    setVal('s-since',''); setVal('s-from',''); setVal('s-to','');
    setVal('s-field',field||''); setVal('s-q',ref);
    if(typeof loadSuricata==='function') loadSuricata();
  }
  window._pivotSuricata=pivotSuricata;   // ponytail: test seam — verify the reference-aware pivot

  function setVal(id,v){ var el=$(id); if(el) el.value=v; }

  window.loadFiles=async function(){
    var g=++generation;
    var box=$('files-list'); box.innerHTML='<div class="empty">Loading…</div>'; clearDetail();
    var entity=$('files-entity').value.trim();
    var frm=toQ($('files-from').value,'files-tz'), to=toQ($('files-to').value,'files-tz');
    if(!entity||!frm||!to){ box.innerHTML='<div class="empty">Enter an entity and a from/to window.</div>'; return; }
    var q=new URLSearchParams({entity:entity,frm:frm,to:to});
    var r=await req('/api/files?'+q);
    if(g!==generation) return;
    if(!r.ok||!r.data||r.data.quality==='unavailable'){
      box.innerHTML='<div class="empty">file observations unavailable'+((r.data&&r.data.reason)?' ('+esc(r.data.reason)+')':'')+'</div>';
      return;
    }
    renderFiles(r.data.files||[]);
  };

  // Keep this module importable by the DOM-free tests.
  if(typeof $!=='function'||!$('files-refresh')) return;
  $('files-refresh').onclick=function(){loadFiles();};
})();
