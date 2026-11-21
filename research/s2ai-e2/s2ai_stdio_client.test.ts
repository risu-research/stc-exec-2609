import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
const child = fileURLToPath(new URL('./s2ai_stdio_server.js',import.meta.url));
const hash = (o:unknown) => createHash('sha256').update(JSON.stringify(o)).digest('hex');
async function run(flag: boolean) {
  const env = Object.fromEntries(Object.entries(process.env).filter((e): e is [string,string] => typeof e[1] === 'string'));
  const transport = new StdioClientTransport({command: process.execPath,args:[child],env:{...env,MCP_TESTING:'1',S2AI_PROVIDER_FLAG:String(flag)}});
  const client = new Client({name:'s2ai-stdio-client',version:'1.0.0'});
  try {
    await client.connect(transport);
    const tools = await client.listTools();
    const result = await client.callTool({name:'search',arguments:{query:'deployment blocker'}});
    return {result, toolCount:tools.tools.length, searchListed:tools.tools.some(t=>t.name==='search')};
  } finally { await client.close(); }
}
test('Unmodified MCP server via child-process stdio hides incompleteSearch', async () => {
  const a=await run(false);
  const b=await run(true);
  assert.ok(a.searchListed && b.searchListed);
  assert.equal(a.toolCount,b.toolCount);
  assert.deepEqual(a.result,b.result);
  assert.equal(hash(a.result),hash(b.result));
  assert.equal(a.result.isError,false);
  const e={source_commit:'9509fb8bba8ad15f7cdb79a54dbd850c13eb058b',transport:'stdio',google_api:'test mock',distinct_source_values:[false,true],tools:a.toolCount,checks:{tools_list:true,tools_call_result_equal:true},results:{complete:a.result,incomplete:b.result},sha256:hash(a.result)};
  mkdirSync('results',{recursive:true});
  writeFileSync('results/s2ai_stdio_runtime.json',JSON.stringify(e,null,2)+'\n');
  console.log('S2AI_STDIO_RESULT_JSON '+JSON.stringify(e));
});
