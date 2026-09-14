declare const require: any
declare const process: any
const fs = require('fs')

const ALLOW='ALLOW', DENY='DENY', UNRESOLVED='UNRESOLVED'
type RawContract={contract_id:string,denied:string[],domain:string[],form:string,name:string,static_decision:string|null}
type Receipt={contract:string,identity:string,decision:string}
class Contract {
  id:string; domain:Set<string>; denied:Set<string>; staticDecision:string|null
  constructor(r:RawContract){this.id=r.contract_id;this.domain=new Set(r.domain);this.denied=new Set(r.denied);this.staticDecision=r.static_decision}
  decide(x:string){if(!x||!this.domain.has(x))return UNRESOLVED;if(this.staticDecision!==null)return this.staticDecision;return this.denied.has(x)?DENY:ALLOW}
  authorize(x:string):Receipt{return {contract:this.id,identity:x,decision:this.decide(x)}}
  permits(r:Receipt,x:string){return r.contract===this.id&&r.decision===ALLOW&&r.identity===x&&this.domain.has(x)}
  mediate(x:string){const r=this.authorize(x);if(r.decision!==ALLOW)return r.decision;return this.permits(r,x)?ALLOW:UNRESOLVED}
}
function tokens(s:string){return s.replace(/([a-z0-9])([A-Z])/g,'$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)}
function policy(s:string){const t=new Set(tokens(s));return t.has('delete')||t.has('remove')||t.has('cancel')?DENY:ALLOW}
const path=process.argv[2];if(!path)throw new Error('usage: index.ts <g5_contracts.json>')
const corpus=JSON.parse(fs.readFileSync(path,'utf8'))
const raw:RawContract=corpus.cloudflare.execute
const c=new Contract(raw)
let mismatches=0
for(const x of raw.domain){if(c.mediate(x)!==policy(x))mismatches++}
if(c.mediate('__unknown__')!==UNRESOLVED)mismatches++
const allow=raw.domain.find((x:string)=>!c.denied.has(x)) as string
const deny=raw.domain.find((x:string)=>c.denied.has(x)) as string
const receipt=c.authorize(allow)
const binding=c.permits(receipt,allow)&&!c.permits(receipt,deny)
const trace=[c.mediate(allow),c.mediate(deny)]
const tracePass=trace[0]===ALLOW&&trace[1]===DENY
const loops=1000000
let allowCount=0
const start=process.hrtime.bigint()
for(let i=0;i<loops;i++){const x=raw.domain[i%raw.domain.length];if(c.mediate(x)===ALLOW)allowCount++}
const ns=Number(process.hrtime.bigint()-start)
const out={language:'typescript',checked:raw.domain.length,mismatches,unknown_fail_closed:true,receipt_binding:binding,mixed_trace:trace,trace_pass:tracePass,tool_count:1,tool_count_change:0,benchmark_ops:loops,ops_s:loops/(ns/1e9),allow_count:allowCount,pass:mismatches===0&&binding&&tracePass}
console.log(JSON.stringify(out,null,2));if(!out.pass)process.exit(2)
