import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { google } from 'googleapis';
import { createAllMocks } from '../helpers/mock-google-apis.js';

// This file runs unmodified original MCP server modules. All Google service
// methods are substituted with a loopback HTTP test provider, not Google.
async function main() {
  const url = process.env.S2AI_E3_PROVIDER_URL;
  if (!url || !url.startsWith('http://127.0.0.1:')) throw new Error('Missing local mock provider URL');
  const mocks = createAllMocks();
  (google as any).drive = mocks.google.drive;
  (google as any).docs = mocks.google.docs;
  (google as any).sheets = mocks.google.sheets;
  (google as any).slides = mocks.google.slides;
  (google as any).calendar = mocks.google.calendar;

  async function send(path: string, params: any): Promise<any> {
    const response = await fetch(url + path, {
      method: 'POST',
      headers: {'content-type':'application/json'},
      body: JSON.stringify(params),
    });
    if (!response.ok) throw new Error('Mock provider response ' + response.status);
    return {data: await response.json()};
  }
  mocks.drive.service.files.list._setImpl(async (params:any) => send('/files/list',params));
  mocks.drive.service.files.create._setImpl(async (params:any) => send('/files/create',params));

  const {server, _setAuthClientForTesting} = await import('../../src/index.js');
  _setAuthClientForTesting({request:async () => ({data:'mock-auth-request-response'})});
  await server.connect(new StdioServerTransport());
}
main().catch(error => {console.error(error); process.exitCode=1;});
