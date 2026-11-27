import { PDFDocument, PDFArray } from 'pdf-lib';
const doc = await PDFDocument.create();
const page = doc.addPage([300,300]);
doc.getForm().createTextField('applicant.name').addToPage(page, {x:20,y:20,width:120,height:20});
const input = Buffer.from(await doc.save());
const r = await PDFDocument.load(input);
const form = r.getForm();
const widgets = new Set();
for (const f of form.getFields()) for (const w of f.acroField.getWidgets()) widgets.add(w.dict);
const refs = new Set();
for (const [ref,obj] of r.context.enumerateIndirectObjects()) if (widgets.has(obj)) refs.add(ref.toString());
console.log('pdf-lib form: refs:', [...refs]);
form.flatten({ updateFieldAppearances: false });
for (const pg of r.getPages()) {
  const raw = pg.node.Annots?.();
  const res = raw instanceof PDFArray ? raw : r.context.lookup(raw);
  console.log('  after flatten: raw=', !!raw, 'size=', res?.size?.());
}
