import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument, PDFArray, PDFRef, PDFName } from 'pdf-lib';
const input = buildPdf({ withField: true });
const doc = await PDFDocument.load(input);
const form = doc.getForm();
const field = form.getFields()[0];
const widgets = field.acroField.getWidgets();
console.log('widget count:', widgets.length);
for (const w of widgets) console.log('  widget.dict:', w.dict, 'isPDFObject?', typeof w.dict);
const refs = new Set();
for (const [ref, obj] of doc.context.enumerateIndirectObjects()) {
  if (widgets.some(w => w.dict === obj)) refs.add(ref.toString());
}
console.log('widget refs:', [...refs]);
for (const page of doc.getPages()) {
  const raw = page.node.Annots?.();
  console.log('raw Annots:', raw, 'instanceof PDFArray:', raw instanceof PDFArray);
  const resolved = raw instanceof PDFArray ? raw : doc.context.lookup(raw);
  console.log('resolved instanceof PDFArray:', resolved instanceof PDFArray, 'size:', resolved?.size?.());
  if (resolved instanceof PDFArray) for (let i=0;i<resolved.size();i++){const e=resolved.get(i); console.log('  entry', i, e?.toString?.(), 'isRef', e instanceof PDFRef);}
}
