import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument, PDFArray } from 'pdf-lib';
// Faithful replica of the child's path: set text, save, reopen, flatten, prune.
let doc = await PDFDocument.load(buildPdf({ withField: true }));
const form = doc.getForm();
form.getTextField('applicant.name').setText('Smoke Test');
const firstPass = await doc.save({ useObjectStreams: true, updateFieldAppearances: false });
doc = await PDFDocument.load(firstPass);
const widgets = new Set();
for (const f of doc.getForm().getFields()) for (const w of f.acroField.getWidgets()) widgets.add(w.dict);
const refs = new Set();
for (const [ref,obj] of doc.context.enumerateIndirectObjects()) if (widgets.has(obj)) refs.add(ref.toString());
console.log('refs:', [...refs]);
for (const pg of doc.getPages()) { const a = pg.node.Annots?.(); const r2 = a instanceof PDFArray ? a : doc.context.lookup(a); console.log('before flatten annots size=', r2?.size?.()); }
try { doc.getForm().flatten({ updateFieldAppearances: false }); console.log('flatten did NOT throw'); }
catch (e) { console.log('flatten threw:', e.message); }
for (const pg of doc.getPages()) { const a = pg.node.Annots?.(); const r2 = a instanceof PDFArray ? a : doc.context.lookup(a); console.log('after flatten annots raw=', !!a, 'size=', r2?.size?.()); }
