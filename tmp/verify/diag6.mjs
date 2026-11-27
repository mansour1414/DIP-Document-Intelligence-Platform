import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument, PDFArray } from 'pdf-lib';
const input = buildPdf({ withField: true });
const r = await PDFDocument.load(input);
const form = r.getForm();
const widgets = new Set();
for (const f of form.getFields()) for (const w of f.acroField.getWidgets()) widgets.add(w.dict);
const refs = new Set();
for (const [ref,obj] of r.context.enumerateIndirectObjects()) if (widgets.has(obj)) refs.add(ref.toString());
console.log('hand-written: refs:', [...refs]);
form.flatten({ updateFieldAppearances: false });
for (const pg of r.getPages()) {
  const raw = pg.node.Annots?.();
  const res = raw instanceof PDFArray ? raw : r.context.lookup(raw);
  console.log('  after flatten: raw=', !!raw, 'size=', res?.size?.());
}
