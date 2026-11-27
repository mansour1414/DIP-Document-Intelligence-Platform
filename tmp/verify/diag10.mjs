// Does the shipped flatten path succeed on a NORMAL pdf-lib form (the common case)?
import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { spawn } from 'node:child_process';
import { PDFDocument } from 'pdf-lib';
const u32 = n => { const b=Buffer.alloc(4); b.writeUInt32BE(n,0); return b; };
const doc = await PDFDocument.create();
const page = doc.addPage([300,300]);
doc.getForm().createTextField('applicant.name').addToPage(page, {x:20,y:20,width:120,height:20});
const input = Buffer.from(await doc.save());
function run(flatten) {
  return new Promise(res => {
    const c = spawn(process.execPath,['--import','tsx','src/lib/pdf/form-worker-child.ts'],{shell:false,env:{PATH:process.env.PATH,NODE_ENV:'production'},stdio:['pipe','pipe','pipe','pipe']});
    const out=[]; c.stdio[3].on('data',d=>out.push(d));
    c.on('close',()=>{const b=Buffer.concat(out);const ml=b.readUInt32BE(0);res(JSON.parse(b.subarray(4,4+ml).toString()));});
    const cb=Buffer.from(JSON.stringify({v:1,op:'fill',flatten,fields:{'applicant.name':'X'},maxInputBytes:64*1024*1024}));
    c.stdin.on('error',()=>{}); c.stdin.end(Buffer.concat([u32(cb.length),cb,input]));
  });
}
console.log('pdf-lib form, flatten=false ->', JSON.stringify(await run(false)));
console.log('pdf-lib form, flatten=true  ->', JSON.stringify(await run(true)));
