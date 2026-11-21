import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { google } from 'googleapis';
import { createAllMocks } from '../helpers/mock-google-apis.js';
const mocks = createAllMocks();
(google as any).drive = mocks.google.drive;
(google as any).docs = mocks.google.docs;
(google as any).sheets = mocks.google.sheets;
(google as any).slides = mocks.google.slides;
(google as any).calendar = mocks.google.calendar;
const {server, _setAuthClientForTesting} = await import('../../src/index.js');
_setAuthClientForTesting({request: async () => ({data:'mock-auth-request-response'})});
const incompleteSearch = process.env.S2AI_PROVIDER_FLAG === 'true';
mocks.drive.service.files.list._setImpl(async (params: any) => {
  process.stderr.write('S2AI_GOOGLE_REQUEST ' + JSON.stringify(params) + '\n');
  return {data:{files:[],incompleteSearch}};
});
await server.connect(new StdioServerTransport());
