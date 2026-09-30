// V2 proof-first: charts.js envelopeToOption preserves gaps, renders zero, carries units,
// drops nonfinite — the exact traps the review calls out. Run: node tests/test_charts_adapter.js
const {envelopeToOption} = require('../static/charts.js');
let ok=0, fail=0;
function eq(a,b,m){ if(JSON.stringify(a)===JSON.stringify(b)){ok++;console.log('ok  '+m);} else {fail++;console.log('FAIL '+m+' got '+JSON.stringify(a)+' want '+JSON.stringify(b));} }

const env={metric_id:'records_processed', unit:'records/s', quality:'fresh', series:[
  {labels:{event_type:'flow'}, points:[[1000,7.9],[1060,null],[1120,0],[1180,NaN],[1240,4.2]]}
]};
const opt=envelopeToOption(env,{color:'#55D8ED'});
const data=opt.series[0].data;
eq(data[0],[1000000,7.9],'value scaled to ms');
eq(data[1],[1060000,null],'missing bucket stays a NULL gap (not 0)');
eq(data[2],[1120000,0],'zero renders as zero (distinct from gap)');
eq(data[3],[1180000,null],'NaN coerced to null gap, never plotted');
eq(opt.series[0].connectNulls,false,'connectNulls false — gaps break the line');
eq(opt.yAxis.name,'records/s','unit carried to y-axis');
eq(opt.animation,false,'animation off (reduced-motion friendly)');
eq(opt.series[0].name,'flow','series name from labels');

console.log(fail? ('\n'+fail+' FAILED') : '\nall charts adapter tests passed');
process.exit(fail?1:0);
