import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Readable} from 'node:stream';
import {ROOT} from '../src/store.mjs';
import {saveDemoRecording} from '../src/demo-recording.mjs';
function directory(){const parent=path.join(ROOT,'test-output');fs.mkdirSync(parent,{recursive:true});return fs.mkdtempSync(path.join(parent,'recording-'))}
test('recording writes unique bounded bytes and matching metadata',async()=>{
 const dir=directory(),bytes=Buffer.concat([Buffer.from('1a45dfa3','hex'),Buffer.alloc(20)]);
 const result=await saveDemoRecording(Readable.from([bytes]),dir);
 assert.equal(result.bytes,bytes.length);assert.equal(result.mode,'simulation');
 assert.deepEqual(fs.readFileSync(path.join(dir,'recordings',result.name)),bytes);
 const again=await saveDemoRecording(Readable.from([bytes]),dir);assert.notEqual(again.name,result.name);
});
test('invalid and oversized recording bodies create no files',async()=>{
 const dir=directory();await assert.rejects(saveDemoRecording(Readable.from([Buffer.from('invalid')]),dir),/RECORDING_FORMAT/);
 await assert.rejects(saveDemoRecording(Readable.from([Buffer.alloc(32*1024*1024+1)]),dir),/RECORDING_SIZE/);
 assert.deepEqual(fs.readdirSync(dir),[]);
});
