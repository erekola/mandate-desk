import fs from 'node:fs';
import path from 'node:path';
import {ROOT,boundedPath} from '../src/store.mjs';
const directory=boundedPath(path.join(ROOT,'.local-demo'));fs.mkdirSync(directory,{recursive:true});
const file=boundedPath(path.join(directory,'mcp-config.json'));
const mcpServers=Object.fromEntries([['mandate-desk','mcp.mjs',[]],['mandate-desk-sepolia-preview','mcp-integration.mjs',[]],['mandate-desk-sepolia-live','mcp-integration.mjs',['--live']]].map(([name,entry,flags])=>[name,{command:process.execPath,args:[path.join(ROOT,'src',entry),...flags,'--data',directory]}]));
fs.writeFileSync(file,JSON.stringify({mcpServers},null,2));console.log('MCP configuration: '+file);
