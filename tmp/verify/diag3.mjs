import { buildPdf } from '../../scripts/smoke-pdf-worker-artifact.mjs';
import { PDFDocument } from 'pdf-lib';
const input = buildPdf({ withField: true });
const doc = await PDFDocument.load(input);
console.log('loaded pages:', doc.getPageCount());
const form = doc.getForm();
console.log('fields:', form.getFields().map(f => f.getName()));
form.getTextField('applicant.name').setText('Smoke Test');
const first = await doc.save({ useObjectStreams: true, updateFieldAppearances: false });
const reopened = await PDFDocument.load(first);
console.log('reopened pages:', reopened.getPageCount());
const widgets = [...reopened.getForm().getFields()];
console.log('widgets:', widgets.length);
// pruneAnnotations equivalent: remove each widget from its page
const pages = reopened.getPages();
let removed = 0;
for (const field of widgets) {
  for (const widget of field.acroField.getWidgets()) {
    for (const page of pages) {
      const annots = page.node.Annots();
      if (!annots) continue;
      const idx = annots.asArray().findIndex(a => a === widget.dict || (a && a.toString && false));
    }
  }
}
const flattened = await reopened.save({ useObjectStreams: true, updateFieldAppearances: false });
const check = await PDFDocument.load(flattened);
console.log('flattened pages:', check.getPageCount(), 'fields:', check.getForm().getFields().length);
