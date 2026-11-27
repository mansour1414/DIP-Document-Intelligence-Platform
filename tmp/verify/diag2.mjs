import { buildPdf, rawPageCount } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { spawn } from 'node:child_process';
const u32 = n => { const b=Buffer.alloc(4); b.writeUInt32BE(n,0); return b; };
const input = buildPdf({ withField: true });
function run(control, pdf) {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['--import','tsx','src/lib/pdf/form-worker-child.ts'],
      { shell:false, env:{PATH:process.env.PATH,NODE_ENV:'production'}, stdio:['pipe','pipe','pipe','pipe'] });
    const out=[]; const err=[];
    c.stdio[3].on('data', d=>out.push(d));
    c.stderr.on('data', d=>err.push(d));
    c.on('close', ()=>{ const b=Buffer.concat(out);
      const ml=b.readUInt32BE(0); const meta=JSON.parse(b.subarray(4,4+ml).toString());
      let output;
      if (b.length > 4+ml) { const ol=b.readUInt32BE(4+ml); output=b.subarray(4+ml+4, 4+ml+4+ol); }
      res({meta, output, stderr: Buffer.concat(err).toString().slice(-300)});
    });
    const cb = Buffer.from(JSON.stringify(control));
    c.stdin.on('error',()=>{});
    c.stdin.end(Buffer.concat([u32(cb.length), cb, pdf]));
  });
}
const r = await run({v:1, op:'fill', flatten:true, fields:{'applicant.name':'Smoke Test'}, maxInputBytes:64*1024*1024}, input);
console.log('meta:', JSON.stringify(r.meta));
if (r.output) { console.log('output rawPageCount =', rawPageCount(r.output)); console.log(r.output.toString('latin1').slice(0, 1200)); }
else console.log('no output; stderr:', r.stderr);
