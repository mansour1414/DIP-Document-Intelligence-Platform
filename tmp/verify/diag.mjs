import { buildPdf, rawPageCount } from '../../scripts/smoke-pdf-worker-artifact.mjs';
const input = buildPdf({ withField: true });
console.log('input rawPageCount =', rawPageCount(input));
console.log(input.toString('latin1'));
