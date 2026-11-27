import { PDFDocument, PDFArray } from 'pdf-lib';
const doc = await PDFDocument.create();
const page = doc.addPage([300,300]);
doc.getForm().createTextField('applicant.name').addToPage(page, {x:20,y:20,width:120,height:20});
let cur = await PDFDocument.load(Buffer.from(await doc.save()));
const f = cur.getForm().getTextField('applicant.name');
f.setText('X'); f.defaultUpdateAppearances(await cur.embedFont('Helvetica'));
const firstPass = await cur.save({ useObjectStreams: true, updateFieldAppearances: false });
cur = await PDFDocument.load(firstPass);
const widgets = new Set();
for (const x of cur.getForm().getFields()) for (const w of x.acroField.getWidgets()) widgets.add(w.dict);
for (const pg of cur.getPages()) { const a = pg.node.Annots?.(); const r = a instanceof PDFArray ? a : cur.context.lookup(a); console.log('before size=', r?.size?.()); }
try { cur.getForm().flatten({ updateFieldAppearances: false }); console.log('flatten ok'); } catch(e){ console.log('threw:', e.message); }
for (const pg of cur.getPages()) { const a = pg.node.Annots?.(); const r = a instanceof PDFArray ? a : cur.context.lookup(a); console.log('after raw=', !!a, 'size=', r?.size?.()); }
