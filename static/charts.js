/* Cernity Vantage — shared chart adapter (plan 012 V2). Apache ECharts (pinned, locally vendored;
   no CDN). Converts the R2 metric envelope to a line-chart option: preserves NULL GAPS (no
   interpolation/smoothing that hides spikes), renders zero as zero, never draws a negative spike
   from a counter reset (source PromQL applies rate() before agg), formats units, and exposes a
   keyboard-reachable data table (library ARIA alone is not sufficient access). */
(function(){
  "use strict";
  var GRID={left:44,right:12,top:16,bottom:22};
  var registry={};                              // dom-id -> chart instance (for dispose on re-nav)

  // Envelope -> ECharts option. PURE + browser-agnostic so it is unit-testable without echarts.
  function envelopeToOption(env, opts){
    opts=opts||{}; var color=opts.color||'#55D8ED', unit=(env&&env.unit)||'';
    var series=(env&&env.series)||[];
    var ecSeries=series.map(function(s,i){
      // gaps: a missing bucket stays a [ts, null] point so ECharts breaks the line (no fill-in).
      var data=(s.points||[]).map(function(p){ var v=p[1]; return [p[0]*1000, (v==null||!isFinite(v))?null:v]; });
      return {name:seriesName(s,i), type:'line', showSymbol:false, connectNulls:false,
              lineStyle:{width:1.5,color:color}, areaStyle:opts.area?{opacity:0.10,color:color}:null, data:data};
    });
    return {
      animation:false, color:[color,'#A99BFF','#6DDBAD'], grid:GRID,
      xAxis:{type:'time', axisLabel:{color:'#7d90a8',fontSize:10}, axisLine:{lineStyle:{color:'#22344c'}}, splitLine:{show:false}},
      yAxis:{type:'value', name:unit, nameTextStyle:{color:'#7d90a8',fontSize:10,align:'left'},
             axisLabel:{color:'#7d90a8',fontSize:10}, splitLine:{lineStyle:{color:'#16273e'}}, scale:true},
      tooltip:{trigger:'axis', backgroundColor:'#101c2e', borderColor:'#22344c',
               textStyle:{color:'#E7F0FA',fontSize:12},
               valueFormatter:function(v){ return v==null?'—':(v+(unit?' '+unit:'')); }},
      series:ecSeries
    };
  }
  function seriesName(s,i){ var l=s.labels||{}; return l.event_type||l.detector_id||l.instance||l.group_id||('series '+(i+1)); }

  // Accessible fallback: a data table with the actual sampled values (gaps shown as —).
  function dataTableHTML(env){
    var series=(env&&env.series)||[]; if(!series.length) return '<div class="ov-q">no data</div>';
    var rows=series[0].points||[]; var unit=(env&&env.unit)||'';
    var head='<tr><th>time (UTC)</th>'+series.map(function(s,i){return '<th>'+esc(seriesName(s,i))+(unit?' ('+esc(unit)+')':'')+'</th>';}).join('')+'</tr>';
    var body=rows.map(function(_,ri){
      var t=new Date(rows[ri][0]*1000).toISOString().replace('T',' ').replace(/\..*/,'');
      return '<tr><td>'+esc(t)+'</td>'+series.map(function(s){var v=(s.points[ri]||[])[1];return '<td class="num">'+(v==null?'—':esc(v))+'</td>';}).join('')+'</tr>';
    }).join('');
    return '<table class="chart-table"><caption class="ov-q">data table — '+esc((env&&env.metric_id)||'')+'</caption>'+head+body+'</table>';
  }

  // Render (or update) a chart into a container id. Reuses the instance to avoid leaks on re-nav.
  function render(domId, env, opts){
    if(typeof window==='undefined'||!window.echarts) return;
    var el=document.getElementById(domId); if(!el) return;
    var q=env&&env.quality;
    if(q!=='fresh'&&q!=='stale'){ if(registry[domId]){registry[domId].dispose();delete registry[domId];}
      el.innerHTML='<div class="ov-q" style="padding:16px 0;color:var(--mut)">'+esc(qlabel(q))+'</div>'; return; }
    var inst=registry[domId]; if(!inst){ inst=window.echarts.init(el,null,{renderer:'svg'}); registry[domId]=inst; }
    inst.setOption(envelopeToOption(env,opts), true);
  }
  function disposeAll(){ Object.keys(registry).forEach(function(k){registry[k].dispose();delete registry[k];}); }
  function connect(ids){ if(window.echarts) window.echarts.connect(ids.map(function(i){return registry[i];}).filter(Boolean)); }
  function qlabel(q){ return {no_data:'no data',error:'unavailable',unsupported:'not deployed',stale:'stale'}[q]||String(q||'no data'); }

  if(typeof window!=='undefined'){ window.VantageCharts={ envelopeToOption:envelopeToOption, dataTableHTML:dataTableHTML, render:render, disposeAll:disposeAll, connect:connect }; }
  if(typeof module!=='undefined'&&module.exports){ module.exports={envelopeToOption:envelopeToOption}; }  // node test
})();
