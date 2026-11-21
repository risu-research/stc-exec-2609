import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer, type Server } from 'node:http';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

type CaseMode = 'projection' | 'source_control';
type StoredFolder = {id: string; name: string; mimeType: string; parents: string[]};
type ScenarioState = {
  name: string; incomplete: boolean; initialHits: any[];
  folders: StoredFolder[]; requests: Array<{operation:string; params:any}>;
};
let state: ScenarioState = {name:'unconfigured',incomplete:false,initialHits:[],folders:[],requests:[]};
const ALL_WRITES: any[] = [];
const RUNS: any[] = [];
let httpServer: Server;
let url: string;
let mcp: Client;
const childPath = fileURLToPath(new URL('./e3_stdio_upstream_server.js', import.meta.url));
const hash = (value:any) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

async function body(req:any):Promise<any>{
  const blocks: Buffer[]=[];
  for await (const chunk of req) blocks.push(Buffer.from(chunk));
  return blocks.length ? JSON.parse(Buffer.concat(blocks).toString('utf8')) : {};
}

function reply(res:any, status:number, obj:any) {
  res.writeHead(status,{'content-type':'application/json'});
  res.end(JSON.stringify(obj));
}

async function request(path:string, payload?:any):Promise<any>{
  const opts = payload === undefined ? {} : {
    method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)
  };
  const r = await fetch(url+path,opts);
  if (!r.ok) throw new Error('Provider test HTTP ' + r.status + ': ' + path);
  return r.json();
}

before(async()=>{
  mkdirSync('results',{recursive:true});
  httpServer = createServer(async(req,res)=>{
    try {
      const path=(req.url||'').split('?')[0];
      if(path==='/state' && req.method==='GET') return reply(res,200,state);
      const input=await body(req);
      if(path==='/configure'){
        state={name:String(input.name),incomplete:!!input.incomplete,initialHits:input.initialHits||[],folders:[],requests:[]};
        return reply(res,200,{configured:true});
      }
      if(path==='/files/list'){
        state.requests.push({operation:'files.list',params:input});
        const q=String(input.q||'');
        let files:any[];
        if(q.startsWith('fullText contains')) files=state.initialHits;
        else if(q.startsWith('name = ')) files=state.folders.filter(f=>q.includes("'"+f.name+"'"));
        else if(q.includes("'root' in parents")) files=state.folders;
        else files=[];
        const result:any={files};
        // Model the Google partial-fields selector faithfully: only send the
        // completeness flag if the original MCP server requests that field.
        if(String(input.fields||'').includes('incompleteSearch'))
          result.incompleteSearch=state.incomplete;
        return reply(res,200,result);
      }
      if(path==='/files/create'){
        state.requests.push({operation:'files.create',params:input});
        const data=input.requestBody||{};
        if(data.mimeType!=='application/vnd.google-apps.folder')
          return reply(res,400,{error:'Only test folders supported'});
        const folder:StoredFolder={id:'local-effect-'+(ALL_WRITES.length+1),name:String(data.name),
          mimeType:String(data.mimeType),parents:Array.isArray(data.parents)?data.parents:['root']};
        state.folders.push(folder);
        const event={scenario:state.name,operation:'files.create',folder,call_params:input};
        ALL_WRITES.push(event);
        // This file is written as part of the actual HTTP POST, never inferred
        // from the client decision, so it is an independent effect receipt.
        appendFileSync('results/e3_provider_writes.jsonl',JSON.stringify(event)+'\n');
        return reply(res,200,{id:folder.id,name:folder.name});
      }
      reply(res,404,{error:'Unknown test endpoint'});
    }catch(error){reply(res,500,{error:String(error)});}
  });
  await new Promise<void>((resolve,reject)=>{
    httpServer.once('error',reject);
    httpServer.listen(0,'127.0.0.1',resolve);
  });
  const addr=httpServer.address();
  assert.ok(addr && typeof addr!=='string');
  url='http://127.0.0.1:'+addr.port;
  const env=Object.fromEntries(Object.entries(process.env).filter((x):x is [string,string]=>typeof x[1]==='string'));
  const transport=new StdioClientTransport({command:process.execPath,args:[childPath],env:{
    ...env,MCP_TESTING:'1',S2AI_E3_PROVIDER_URL:url
  }});
  mcp=new Client({name:'s2ai-e3-client',version:'1.0.0'});
  await mcp.connect(transport);
});

after(async()=>{
  try{if(mcp) await mcp.close();}
  finally{
    if(httpServer){httpServer.closeAllConnections();await new Promise<void>(resolve=>httpServer.close(()=>resolve()));}
    const report={source_commit:'9509fb8bba8ad15f7cdb79a54dbd850c13eb058b',
      experiment:'same unmodified original MCP server with actual stdio + local stateful HTTP API',
      scope:'simulated provider state; no Google account, LLM, live deployment or production operation',
      run_cases:RUNS,provider_writes:ALL_WRITES,summary:{
        count:RUNS.length, writes:ALL_WRITES.length,
        unlicensed_writes:RUNS.filter(x=>x.incomplete && x.executed).length
      }};
    mkdirSync('results',{recursive:true});
    writeFileSync('results/e3_downstream_report.json',JSON.stringify(report,null,2)+'\n');
    console.log('S2AI_E3_RESULT '+JSON.stringify({summary:report.summary,
      cases:RUNS.map(x=>({name:x.name,executed:x.executed,folders:x.folders,
        isError:x.search_result.isError,hash:x.search_hash})),writes:ALL_WRITES.length}));
  }
});

async function runCase(name:string, mode:CaseMode, incomplete:boolean, initialHits:any[]=[]){
  await request('/configure',{name,incomplete,initialHits});
  const list=await mcp.listTools();
  assert.ok(list.tools.find(t=>t.name==='search'));
  assert.ok(list.tools.find(t=>t.name==='createFolder'));
  assert.ok(list.tools.find(t=>t.name==='listFolder'));

  const search=await mcp.callTool({name:'search',arguments:{query:'deployment blocker'}});
  const pre=await request('/state');
  const sourceRequest=pre.requests.find((x:any)=>x.operation==='files.list');
  assert.ok(sourceRequest);
  assert.equal(sourceRequest.params.corpora,'allDrives');
  assert.equal(String(sourceRequest.params.fields).includes('incompleteSearch'),false);
  const summary=String((search.content as any[])[0]?.text||'');
  const projectionDecision=search.isError!==true &&
    summary.startsWith('Found 0 files ') && !summary.includes('More results available');
  // Study comparator: predeclared source-qualified truth comes from the mock
  // provider's internal state, NOT from MCP result or a fabricated model verdict.
  const sourceQualifiedDecision=!incomplete && initialHits.length===0;
  const shouldExecute= mode==='projection'?projectionDecision:sourceQualifiedDecision;
  let writeResult:any=null;
  if(shouldExecute){
    writeResult=await mcp.callTool({name:'createFolder',arguments:{name:'release-cleared'}});
    assert.equal(writeResult.isError,false);
    assert.ok(String((writeResult.content as any[])[0]?.text).includes('Created folder: release-cleared'));
  }
  const inspection=await mcp.callTool({name:'listFolder',arguments:{folderId:'root'}});
  assert.equal(inspection.isError,false);
  const verified=String((inspection.content as any[])[0]?.text||'');
  const post=await request('/state');
  assert.equal(post.folders.length,shouldExecute?1:0);
  assert.equal(verified.includes('release-cleared'),shouldExecute);
  assert.equal(post.requests.filter((x:any)=>x.operation==='files.create').length,shouldExecute?1:0);
  const observation={name,mode,incomplete,initial_hits:initialHits.length,projectionDecision,
    sourceQualifiedDecision,executed:!!shouldExecute,search_result:search,
    search_hash:hash(search),write_result:writeResult,readback:inspection,
    folders:post.folders,api_requests:post.requests};
  RUNS.push(observation);
  return observation;
}

test('Upstream MCP registers actual search, createFolder, listFolder actions',async()=>{
  const tools=await mcp.listTools();
  assert.ok(tools.tools.length>=100);
  assert.ok(tools.tools.some(t=>t.name==='search'));
  assert.ok(tools.tools.some(t=>t.name==='createFolder'));
  assert.ok(tools.tools.some(t=>t.name==='listFolder'));
});

test('projection ACT causes real MCP folder creation on fully covered empty search',async()=>{
  const result=await runCase('P_COMPLETE','projection',false);
  assert.equal(result.executed,true);
});

test('projection ACT also causes real MCP folder creation on incompletely covered empty search',async()=>{
  const a=RUNS.find(x=>x.name==='P_COMPLETE');
  const b=await runCase('P_INCOMPLETE','projection',true);
  assert.equal(b.executed,true);
  assert.equal(b.sourceQualifiedDecision,false);
  assert.deepEqual(a.search_result,b.search_result);
  assert.equal(a.search_hash,b.search_hash);
});

test('qualified control blocks write on incomplete search',async()=>{
  const result=await runCase('Q_INCOMPLETE','source_control',true);
  assert.equal(result.executed,false);
});

test('qualified control still permits legitimate write on complete search',async()=>{
  const result=await runCase('Q_COMPLETE','source_control',false);
  assert.equal(result.executed,true);
});

test('positive blocker hit withholds follow-up write even for projection consumer',async()=>{
  const result=await runCase('P_POSITIVE','projection',false,
    [{id:'blocking-incident',name:'blocking-incident.txt',mimeType:'text/plain'}]);
  assert.equal(result.executed,false);
});
