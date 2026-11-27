import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument } from 'pdf-lib';
const input = buildPdf({ withField: true });
const r = await PDFDocument.load(input);
try { r.getForm().flatten({ updateFieldAppearances: false }); const out = await r.save(); const c = await PDFDocument.load(out); console.log('flatten OK pages:', c.getPageCount()); }
catch (e) { console.log('flatten THREW:', e.message); }
