/**
 * FF-07 — appearance fidelity, behaviourally.
 *
 * Each case builds a real PDF, fills it through the public entry point, and reads
 * the result back with pdf-lib. Nothing here asserts on source text, so a test can
 * only pass if the *document* has the property.
 *
 * The review's four complaints drive the cases:
 *   1. a value silently truncated inside its widget;
 *   2. legibility floors stated but not enforced;
 *   3. rotation, border/background and option semantics ignored;
 *   4. interactive and flattened output disagreeing on what is visible.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { fillFormPdf } from "../src/lib/pdf/form-fill";
import { renderWidgetAppearance } from "../src/lib/pdf/form-appearance";

async function textForm(width = 200, height = 20, rotation?: 90 | 180 | 270) {
  const doc = await PDFDocument.create();
  const page = doc.addPage([400, 400]);
  if (rotation) page.setRotation({ type: "degrees", angle: rotation } as never);
  doc.getForm().createTextField("name").addToPage(page, { x: 40, y: 300, width, height });
  return new Uint8Array(await doc.save({ updateFieldAppearances: false }));
}

test("rotation is preserved for every quarter turn and the value still arrives", async () => {
  for (const rotation of [undefined, 90, 180, 270] as const) {
    const bytes = await textForm(200, 20, rotation);
    const output = await fillFormPdf(bytes, { name: "Layla" }, { flatten: false });
    const result = await PDFDocument.load(output.bytes);
    assert.equal(result.getForm().getTextField("name").getText(), "Layla");
    assert.equal(result.getPage(0).getRotation().angle, rotation ?? 0, `rotation ${rotation} must survive the fill`);
  }
});

test("an option that is not offered is rejected, and an offered one is selected", async () => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([400, 400]);
  const dropdown = doc.getForm().createDropdown("country");
  dropdown.addOptions(["SA", "AE", "EG"]);
  dropdown.addToPage(page, { x: 40, y: 300, width: 160, height: 20 });
  const bytes = new Uint8Array(await doc.save({ updateFieldAppearances: false }));

  const filled = await fillFormPdf(bytes, { country: "SA" }, { flatten: false });
  assert.deepEqual((await PDFDocument.load(filled.bytes)).getForm().getDropdown("country").getSelected(), ["SA"]);

  await assert.rejects(() => fillFormPdf(bytes, { country: "ZZ" }, { flatten: false }), (error: unknown) => {
    assert.equal((error as { code?: string }).code, "FORM_VALUE_INVALID");
    return true;
  });
});

test("interactive and flattened output agree that the value was applied", async () => {
  const bytes = await textForm();
  const interactive = await fillFormPdf(bytes, { name: "Layla" }, { flatten: false });
  const flattened = await fillFormPdf(bytes, { name: "Layla" }, { flatten: true });

  const interactiveReport = interactive.report.filled.map((item) => item.name);
  const flattenedReport = flattened.report.filled.map((item) => item.name);
  assert.deepEqual(interactiveReport, ["name"]);
  assert.deepEqual(flattenedReport, ["name"], "flattening must not silently skip a field");

  // Flattened output has no interactive fields left; interactive output still does.
  assert.equal((await PDFDocument.load(flattened.bytes)).getForm().getFields().length, 0);
  assert.equal((await PDFDocument.load(interactive.bytes)).getForm().getFields().length, 1);
});

test("a Latin value that cannot fit is rejected, never clipped", async () => {
  // The round-2 defect: Latin values that WinAnsi can encode took pdf-lib's
  // `defaultUpdateAppearances`, which draws one line and clips the rest with no fit
  // check. Only non-WinAnsi (Arabic) values were measured. A long Latin value in a
  // narrow widget was therefore accepted and silently truncated on screen.
  const narrow = await textForm(90, 24);
  await assert.rejects(
    () => fillFormPdf(narrow, { name: "The quick brown fox jumps over the lazy dog ".repeat(6) }, { flatten: false }),
    (error: unknown) => {
      assert.equal((error as { code?: string }).code, "FORM_VALUE_INVALID");
      const issues = (error as { details?: { issues?: Array<{ issue: string }> } }).details?.issues ?? [];
      assert.equal(issues[0]?.issue, "VALUE_OVERFLOWS_WIDGET", "the rejection must name the geometry problem");
      return true;
    },
  );
});

test("a Latin value that fits stays vector text and is still measured", async () => {
  const bytes = await textForm(200, 20);
  const result = await fillFormPdf(bytes, { name: "Layla" }, { flatten: false });
  // Vector, not raster: the legibility gate must not force Latin through canvas.
  assert.deepEqual(result.report.rasterAppearances, [], "a fitting Latin value must stay selectable text");
  assert.equal((await PDFDocument.load(result.bytes)).getForm().getTextField("name").getText(), "Layla");
});

test("a value that cannot fit is rejected, never clipped", async () => {
  const narrow = await textForm(90, 24);
  await assert.rejects(
    () => fillFormPdf(narrow, { name: "x".repeat(300) }, { flatten: false }),
    (error: unknown) => {
      assert.equal((error as { code?: string }).code, "FORM_VALUE_INVALID");
      return true;
    },
  );
});

test("Arabic text renders through the Arabic face without throwing", () => {
  const arabic = renderWidgetAppearance({ text: "محمد الأحمد", width: 200, height: 24, multiline: false });
  assert.ok(arabic.byteLength > 0);
  // Mixed direction in one value must not throw either.
  const mixed = renderWidgetAppearance({ text: "Mohammed محمد 1414", width: 240, height: 24, multiline: false });
  assert.ok(mixed.byteLength > 0);
});

test("legibility floors are enforced in points, not device pixels", () => {
  // 18x7 pt is below the 8 pt + padding floor.
  assert.throws(() => renderWidgetAppearance({ text: "a", width: 18, height: 7, multiline: false }), (error: unknown) => {
    assert.equal((error as { reason?: string }).reason, "WIDGET_TOO_SMALL");
    return true;
  });
  // A value that only fits at an illegible size must be rejected rather than drawn
  // microscopically. 12 pt of text height cannot hold two lines at >= 8 pt.
  assert.throws(() => renderWidgetAppearance({ text: "x".repeat(400), width: 120, height: 40, multiline: true }), (error: unknown) => {
    assert.ok(["VALUE_OVERFLOWS_WIDGET", "VALUE_NEEDS_MORE_LINES"].includes((error as { reason?: string }).reason ?? ""));
    return true;
  });
});

test("whitespace and blank-line-only values do not produce an unreadable widget", () => {
  // A blank line is a legitimate value (a cleared field), and must render rather
  // than throw: refusing it would make clearing a field impossible.
  for (const text of ["", " ", "\n", "  \n  "]) {
    assert.doesNotThrow(() => renderWidgetAppearance({ text, width: 200, height: 24, multiline: false }), JSON.stringify(text));
  }
});
