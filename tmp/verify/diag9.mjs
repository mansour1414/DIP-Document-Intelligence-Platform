import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument, PDFArray, PDFName } from 'pdf-lib';
let doc = await PDFDocument.load(buildPdf({ withField: true }));
const form = doc.getForm();
const field = form.getTextField('applicant.name');
field.setText('Smoke Test');
field.defaultUpdateAppearances(await doc.embedFont('Helvetica'));
const firstPass = await doc.save({ useObjectStreams: true, updateFieldAppearances: false });
// mirror child: verifyFilledForm reopens; then flatten block reopens again
doc = await PDFDocument.load(firstPass);
const widgets = new Set();
for (const f of doc.getForm().getFields()) for (const w of f.acroField.getWidgets()) widgets.add(w.dict);
for (const pg of doc.getPages()) { const a = pg.node.Annots?.(); const r = a instanceof PDFArray ? a : doc.context.lookup(a); console.log('before: size=', r?.size?.()); }
try { doc.getForm().flatten({ updateFieldAppearances: false }); console.log('flatten ok'); } catch(e){ console.log('flatten threw:', e.message); }
for (const pg of doc.getPages()) { const a = pg.node.Annots?.(); const r = a instanceof PDFArray ? a : doc.context.lookup(a); console.log('after: raw=', !!a, 'size=', r?.size?.()); }
