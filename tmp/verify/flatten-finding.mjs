// Re-confirm the B31-08 finding end-to-end against the real child.
import { buildPdf, buildFormPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { spawn } from 'node:child_process';
const u32 = n => { const b=Buffer.alloc(4); b.writeUInt32BE(n,0); return b; };
function run(control, pdf) {
  return new Promise(res => {
    const c = spawn(process.execPath, ['--import','tsx','src/lib/pdf/form-worker-child.ts'],
      { shell:false, cwd:process.cwd(), env:{PATH:process.env.PATH,NODE_ENV:'production'}, stdio:['pipe','pipe','pipe','pipe'] });
    const out=[]; c.stdio[3].on('data',d=>out.push(d));
    c.on('close',()=>{const b=Buffer.concat(out);const ml=b.readUInt32BE(0);res(JSON.parse(b.subarray(4,4+ml).toString()));});
    const cb=Buffer.from(JSON.stringify(control));
    c.stdin.on('error',()=>{}); c.stdin.end(Buffer.concat([u32(cb.length),cb,pdf]));
  });
}
const hand = buildPdf({ withField: true });
console.log('hand-written  inspect            ->', JSON.stringify(await run({v:1,op:'inspect',maxInputBytes:64*1024*1024}, hand)));
console.log('hand-written  fill flatten=false ->', JSON.stringify((await run({v:1,op:'fill',flatten:false,fields:{'applicant.name':'X'},maxInputBytes:64*1024*1024}, hand)).code ?? 'ok'));
console.log('hand-written  fill flatten=true  ->', JSON.stringify((await run({v:1,op:'fill',flatten:true,fields:{'applicant.name':'X'},maxInputBytes:64*1024*1024}, hand)).code ?? 'ok'));
