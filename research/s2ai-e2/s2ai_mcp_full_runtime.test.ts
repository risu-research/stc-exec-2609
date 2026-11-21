import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { setupTestServer, callTool, type TestContext } from '../helpers/setup-server.js';

const hash = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
let ctx: TestContext;
const evidence: any = {
  scope: 'Unmodified full upstream MCP server through official SDK InMemoryTransport',
  source_commit: '9509fb8bba8ad15f7cdb79a54dbd850c13eb058b',
  google_api: 'upstream test mock', transport: 'InMemoryTransport',
  checks: {}, observations: [],
};

before(async () => { ctx = await setupTestServer(); evidence.node = process.version; });
after(async () => {
  try { await ctx?.cleanup(); } finally {
    mkdirSync('results', {recursive:true});
    writeFileSync('results/s2ai_full_runtime.json',JSON.stringify(evidence,null,2)+'\n');
    console.log('S2AI_RESULT_JSON '+JSON.stringify(evidence));
  }
});

test('MCP initialize and tools/list discover upstream search tool',async () => {
  const list = await ctx.client.listTools();
  const search = list.tools.find(x=>x.name==='search');
  assert.ok(search);
  evidence.checks.tools_list_search = true;
  evidence.observations.push({id:'TOOLS_LIST',total_tools:list.tools.length,search_tool_name:search.name});
});

test('opposing coverage evidence collapses at actual tools/call boundary',async () => {
  const calls: any[] = []; let flag = false;
  ctx.mocks.drive.service.files.list._setImpl(async (params:any) => {
    calls.push({...params});
    return { data: {files: [], incompleteSearch:flag} };
  });
  const args={query:'deployment blocker'};
  flag=false; const a=await callTool(ctx.client,'search',args);
  flag=true; const b=await callTool(ctx.client,'search',args);
  assert.equal(a.isError,false);assert.equal(b.isError,false);
  assert.deepEqual(a,b);
  assert.equal(hash(a),hash(b));
  assert.deepEqual(calls[0],calls[1]);
  assert.equal(calls[0].corpora,'allDrives');
  assert.ok(calls[0].fields.includes('nextPageToken'));
  assert.ok(!calls[0].fields.includes('incompleteSearch'));
  evidence.checks.tools_call_equal=true;
  evidence.checks.same_google_request=true;
  evidence.checks.omits_coverage_field=true;
  evidence.observations.push({id:'EMPTY_COVERAGE_COLLISION',
    provider_cases:[{files:[],incompleteSearch:false},{files:[],incompleteSearch:true}],
    args,google_params:calls[0],result_a:a,result_b:b,hash_a:hash(a),hash_b:hash(b)});
  ctx.mocks.drive.service.files.list._resetImpl();
});

test('pagination control is distinct',async () => {
  ctx.mocks.drive.service.files.list._setImpl(async () => ({data:{files:[],nextPageToken:'next-page-012',incompleteSearch:false}}));
  const r=await callTool(ctx.client,'search',{query:'deployment blocker'});
  assert.equal(r.isError,false);
  assert.ok(r.content[0].text?.includes('next-page-012'));
  evidence.checks.pagination_visible=true;
  evidence.observations.push({id:'PAGE_CONTROL',result:r});
  ctx.mocks.drive.service.files.list._resetImpl();
});

test('positive-hit control is distinct',async () => {
  ctx.mocks.drive.service.files.list._setImpl(async () => ({data:{files:[{id:'f123',name:'incident.txt',mimeType:'text/plain'}],incompleteSearch:false}}));
  const r=await callTool(ctx.client,'search',{query:'deployment blocker'});
  assert.equal(r.isError,false);
  assert.ok(r.content[0].text?.includes('incident.txt'));
  evidence.checks.hit_visible=true;
  evidence.observations.push({id:'HIT_CONTROL',result:r});
  ctx.mocks.drive.service.files.list._resetImpl();
});

test('upstream error is not silently converted into zero',async () => {
  ctx.mocks.drive.service.files.list._setImpl(async () => {throw new Error('mock transport error');});
  const r=await callTool(ctx.client,'search',{query:'deployment blocker'});
  assert.equal(r.isError,true);
  evidence.checks.error_distinct=true;
  evidence.observations.push({id:'ERROR_CONTROL',result:r});
  ctx.mocks.drive.service.files.list._resetImpl();
});
