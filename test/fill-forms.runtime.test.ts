/**
 * Stage 2 `fill-forms` — engine acceptance tests (DIP-CR-006 targeted set).
 *
 * These execute the real engine (`fillFormPdf`) against real `pdf-lib`
 * documents built in-process, then **reopen the produced bytes** and verify
 * them independently of the helper the engine uses internally. No fixture PDFs
 * are checked in: the repository has no `test/fixtures/processing/` corpus, so
 * each document is generated deterministically here (see
 * `docs/stage2-fill-forms.md` → Evidence).
 *
 * Corpus covered:
 *   - bilingual Latin + Arabic values, including an RTL value next to English,
 *   - every supported field kind in one document,
 *   - untouched-field preservation,
 *   - flatten,
 *   - structural rejection: encrypted, signed, XFA, duplicated names, off-form
 *     field names, wrong value types, unsupported scripts, malformed payloads.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { PDFArray, PDFDocument, PDFName, PDFNumber, PDFString, StandardFonts } from "pdf-lib";
import {
  FormFillError,
  assertFillableDocument,
  readFormInventory,
  validateFillValues,
  verifyFilledForm,
} from "../src/lib/pdf/form-schema";
import { assertFieldsPayloadSize, parseFieldsPayload } from "../src/lib/pdf/form-validation";
import { FORM_ENGINE, FORM_ENGINE_VERSION, fillFormPdf, inspectFormPdf } from "../src/lib/pdf/form-fill";

// ------------------------------------------------------------------- fixtures

/**
 * One-page bilingual application form covering every supported field kind plus
 * a pre-filled field that must survive untouched.
 */
async function applicationForm() {
  const document = await PDFDocument.create();
  const page = document.addPage([595, 842]);
  const font = await document.embedFont(StandardFonts.Helvetica);
  page.drawText("Application Form (bilingual fixture)", { x: 60, y: 790, size: 16, font });
  const form = document.getForm();

  const name = form.createTextField("applicant.name.en");
  name.addToPage(page, { x: 60, y: 720, width: 300, height: 22 });
  const nameAr = form.createTextField("applicant.name.ar");
  nameAr.addToPage(page, { x: 60, y: 690, width: 300, height: 22 });
  const notes = form.createTextField("applicant.notes");
  notes.enableMultiline();
  notes.addToPage(page, { x: 60, y: 580, width: 420, height: 90 });
  const limited = form.createTextField("applicant.iqama");
  limited.setMaxLength(10);
  limited.addToPage(page, { x: 60, y: 545, width: 160, height: 22 });
  const consent = form.createCheckBox("consent");
  consent.addToPage(page, { x: 60, y: 510, width: 16, height: 16 });
  const city = form.createDropdown("city");
  city.addOptions(["Riyadh", "Dammam", "جدة"]);
  city.addToPage(page, { x: 60, y: 475, width: 200, height: 22 });
  const tags = form.createOptionList("tags");
  tags.addOptions(["alpha", "beta", "gamma"]);
  tags.addToPage(page, { x: 60, y: 390, width: 200, height: 70 });
  const shift = form.createRadioGroup("shift");
  shift.addOptionToPage("day", page, { x: 300, y: 475, width: 16, height: 16 });
  shift.addOptionToPage("night", page, { x: 340, y: 475, width: 16, height: 16 });
  const prefilled = form.createTextField("reference");
  prefilled.setText("DIP-2026-0042");
  prefilled.addToPage(page, { x: 60, y: 355, width: 220, height: 22 });
  const readOnly = form.createTextField("declaration");
  readOnly.setText("Accepted on submission");
  readOnly.enableReadOnly();
  readOnly.addToPage(page, { x: 60, y: 320, width: 300, height: 22 });
  return new Uint8Array(await document.save());
}

const bilingualValues = {
  "applicant.name.en": "Noura Al-Harbi",
  "applicant.name.ar": "نورة الحربي",
  "applicant.notes": "سطر أول\nسطر ثانٍ — then an English line",
  "applicant.iqama": "2412345678",
  consent: true,
  city: "جدة",
  tags: ["alpha", "gamma"] as string[],
  shift: "night",
};

/**
 * Build a small but structurally valid PDF from raw objects.
 *
 * Needed because `pdf-lib` cannot *write* `/XFA` (it deletes the key on load and
 * logs a warning), so the only way to reproduce a hybrid AcroForm+XFA document
 * faithfully — with a correct xref table, and therefore genuinely parseable — is
 * to assemble one. `offsets` are computed here, so the result is not a corrupted
 * fixture that would "reject" for the wrong reason.
 */
function minimalPdf(objects: string[]) {
  const header = "%PDF-1.7\n%\u00e2\u00e3\u00cf\u00d3\n";
  let body = header;
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(body.length);
    body += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) body += `${String(offset).padStart(10, "0")} 00000 n \n`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new Uint8Array(new TextEncoder().encode(body));
}

/** A one-page AcroForm PDF; `extra` is spliced into the AcroForm dictionary. */
function hybridForm(extra: string) {
  return minimalPdf([
    "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /Helvetica 6 0 R >> >> /Annots [7 0 R] >>",
    "<< >>",
    `<< /Fields [7 0 R] ${extra}/DA (/Helv 0 Tf 0 g) >>`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Type /Annot /Subtype /Widget /FT /Tx /T (legacy.field) /Rect [40 700 240 720] /P 3 0 R /DA (/Helv 12 Tf 0 g) >>",
  ]);
}

/** Re-read the output with pdf-lib, independently of the engine's own verifier. */
async function readBack(bytes: Uint8Array) {
  const document = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const form = document.getForm();
  return {
    document,
    form,
    value: (name: string): unknown => {
      const field = form.getFieldMaybe(name);
      if (!field) return Symbol.for("missing");
      const type = field.constructor.name;
      const raw = field as unknown as Record<string, () => unknown>;
      if (type === "PDFTextField") return raw.getText();
      if (type === "PDFCheckBox") return raw.isChecked();
      if (type === "PDFRadioGroup") return raw.getSelected();
      if (type === "PDFDropdown") { const selected = raw.getSelected() as string[]; return selected[0]; }
      if (type === "PDFOptionList") return raw.getSelected();
      return undefined;
    },
    needAppearances: () => String((document.getForm() as unknown as { acroForm: { dict: { lookup: (key: PDFName) => unknown } } }).acroForm.dict.lookup(PDFName.of("NeedAppearances")) ?? "") === "true",
    hasNormalAppearance: (name: string) => {
      const field = form.getFieldMaybe(name);
      if (!field) return false;
      return field.acroField.getWidgets().every((widget) => Boolean(widget.AP()?.lookup(PDFName.of("N"))));
    },
  };
}

const rejectionOf = (code: string) => (error: unknown) => {
  assert.ok(error instanceof FormFillError, `expected FormFillError, got ${String(error)}`);
  assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.message}`);
  return true;
};

// -------------------------------------------------------------- happy paths

test("S2 fill-forms: bilingual Latin + Arabic values are written and verified after reopening", async () => {
  const source = await applicationForm();
  const result = await fillFormPdf(source, { ...bilingualValues });
  assert.equal(result.mimeType, "application/pdf");
  assert.equal(result.name, "filled-form.pdf");
  assert.equal(result.report.engine, FORM_ENGINE);
  assert.equal(result.report.engineVersion, FORM_ENGINE_VERSION);
  assert.equal(result.report.pages, 1);
  assert.equal(result.report.flatten, false);

  const output = await readBack(result.bytes);
  assert.equal(output.value("applicant.name.en"), "Noura Al-Harbi");
  assert.equal(output.value("applicant.name.ar"), "نورة الحربي");
  assert.equal(output.value("applicant.notes"), "سطر أول\nسطر ثانٍ — then an English line");
  assert.equal(output.value("consent"), true);
  assert.equal(output.value("city"), "جدة");
  assert.deepEqual(output.value("tags"), ["alpha", "gamma"]);
  assert.equal(output.value("shift"), "night");
  // Every touched widget still carries a concrete appearance.
  for (const name of Object.keys(bilingualValues)) assert.ok(output.hasNormalAppearance(name), `${name} lost its appearance`);
  assert.equal(output.needAppearances(), false, "a stale /NeedAppearances flag would let a reader discard the verified appearances");
});

test("S2 fill-forms: Arabic-only values are painted through the approved raster path and recorded as such", async () => {
  const source = await applicationForm();
  const result = await fillFormPdf(source, { "applicant.notes": "ملاحظات بالعربية فقط", "applicant.name.en": "Latin only" });
  assert.deepEqual([...result.report.rasterAppearances], ["applicant.notes"]);
  const output = await readBack(result.bytes);
  assert.equal(output.value("applicant.notes"), "ملاحظات بالعربية فقط");
  assert.ok(output.hasNormalAppearance("applicant.notes"));
  // The Latin value stays vector/selectable text: only the Arabic widget is raster.
  assert.ok(!result.report.rasterAppearances.includes("applicant.name.en"));
});

test("S2 fill-forms: fields not named in the request keep their exact previous values", async () => {
  const source = await applicationForm();
  const before = await inspectFormPdf(source);
  const snapshot = new Map(before.fields.map((field) => [field.name, field.value]));
  assert.equal(snapshot.get("reference"), "DIP-2026-0042");

  const result = await fillFormPdf(source, { "applicant.name.en": "Changed only", shift: "day" });
  assert.equal(result.report.untouched, before.fields.length - 2);

  const output = await readBack(result.bytes);
  assert.equal(output.value("reference"), "DIP-2026-0042", "a pre-filled field was silently cleared");
  assert.equal(output.value("city"), undefined, "an untouched dropdown changed");
  assert.deepEqual(output.value("tags"), [], "an untouched option list changed");
  assert.equal(output.value("applicant.iqama"), undefined);
  // And the engine's own independent verifier agrees on the same snapshot.
  await verifyFilledForm(result.bytes, new Map([["applicant.name.en", "Changed only"], ["shift", "day"]]), { untouched: snapshot });
});

test("S2 fill-forms: read-only fields are refused instead of silently ignored", async () => {
  const source = await applicationForm();
  await assert.rejects(
    () => fillFormPdf(source, { declaration: "tampered" }),
    (error: unknown) => error instanceof FormFillError && error.code === "FORM_VALUE_INVALID" && /read-only/u.test(error.message),
  );
});

test("S2 fill-forms: flatten removes the widgets while keeping the page count", async () => {
  const source = await applicationForm();
  const result = await fillFormPdf(source, { "applicant.name.en": "Flattened", consent: true }, { flatten: true });
  assert.equal(result.report.flatten, true);
  const output = await readBack(result.bytes);
  assert.equal(output.document.getPageCount(), 1);
  assert.equal(output.form.getFields().length, 0, "flatten must not leave interactive widgets behind");
});

test("S2 fill-forms: filling the same input twice produces the same bytes and report", async () => {
  const source = await applicationForm();
  const fields = { "applicant.name.en": "Deterministic", consent: true };
  const first = await fillFormPdf(source, fields);
  const second = await fillFormPdf(source, fields);
  assert.equal(first.bytes.byteLength, second.bytes.byteLength);
  assert.deepEqual(first.report, second.report);
  assert.deepEqual([...first.bytes], [...second.bytes], "identical input must produce identical output, not merely equal behaviour");
  assert.equal((await readBack(first.bytes)).value("applicant.name.en"), "Deterministic");
});

// ---------------------------------------------------------------- rejections

test("S2 fill-forms: XFA documents are rejected as unsupported rather than half-filled", async () => {
  const bytes = hybridForm("/XFA <xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'/> ");
  // Documenting the trap: pdf-lib *removes* /XFA on load and only logs a
  // warning, so a reload-based check would see a clean AcroForm. The engine
  // must therefore reject from the original bytes — which is what it does.
  const reloaded = await PDFDocument.load(bytes);
  assert.equal(reloaded.getForm().hasXFA(), false, "pdf-lib silently drops /XFA on load");
  await assert.rejects(() => inspectFormPdf(bytes), rejectionOf("FORM_UNSUPPORTED"));
  await assert.rejects(() => fillFormPdf(bytes, { "legacy.field": "x" }), rejectionOf("FORM_UNSUPPORTED"));
});

/**
 * Build a compacted form (`/ObjStm`), optionally carrying one restriction.
 *
 * The default `save()` calls `getForm()` internally and deletes `/XFA` before
 * writing, so `updateFieldAppearances: false` is required for the fixture to
 * keep the entry it claims to have.
 */
async function compressedForm(kind: "clean" | "xfa" | "signature-field" | "sigflags" | "certified") {
  const document = await PDFDocument.create();
  const page = document.addPage([595, 842]);
  const form = document.getForm();
  form.createTextField("compact.field").addToPage(page, { x: 60, y: 720, width: 220, height: 22 });
  if (kind === "xfa") form.acroForm.dict.set(PDFName.of("XFA"), PDFString.of("<xdp:xdp/>"));
  if (kind === "sigflags") form.acroForm.dict.set(PDFName.of("SigFlags"), PDFNumber.of(3));
  if (kind === "signature-field") {
    const field = document.context.register(document.context.obj({ Type: "Annot", Subtype: "Widget", FT: "Sig", T: "signature.1", Rect: [40, 640, 200, 660] }));
    const fields = form.acroForm.dict.lookup(PDFName.of("Fields"));
    if (fields instanceof PDFArray) fields.push(field);
  }
  if (kind === "certified") document.catalog.set(PDFName.of("Perms"), document.context.obj({ DocMDP: document.context.obj({ Type: "Sig" }) }));
  return new Uint8Array(await document.save({ useObjectStreams: true, updateFieldAppearances: false }));
}

/** True when the marker is visible to a raw-byte scan of a compacted file. */
const markerVisible = (bytes: Uint8Array) => /\/XFA\b|\/FT\s*\/Sig\b|\/SigFlags\b|\/DocMDP\b/u.test(new TextDecoder("latin1").decode(bytes));

test("S2 fill-forms: restrictions inside compressed object streams are detected structurally, not by raw bytes", async () => {
  const cases: Array<["xfa" | "signature-field" | "sigflags" | "certified", string]> = [
    ["xfa", "FORM_UNSUPPORTED"],
    ["signature-field", "FORM_RESTRICTED"],
    ["sigflags", "FORM_RESTRICTED"],
    ["certified", "FORM_RESTRICTED"],
  ];
  for (const [kind, code] of cases) {
    const bytes = await compressedForm(kind);
    // The point of the fixture: a byte scan cannot see these at all.
    assert.equal(markerVisible(bytes), false, `${kind} was not actually compacted away; the test would prove nothing`);
    await assert.rejects(() => inspectFormPdf(bytes), rejectionOf(code), kind);
    await assert.rejects(() => fillFormPdf(bytes, { "compact.field": "x" }), rejectionOf(code), kind);
  }
  // Control: the same compacted layout without a restriction still fills.
  const clean = await compressedForm("clean");
  assert.equal(markerVisible(clean), false);
  const result = await fillFormPdf(clean, { "compact.field": "Compressed and filled" });
  assert.equal(result.report.filled.length, 1);
  assert.equal((await readBack(result.bytes)).value("compact.field"), "Compressed and filled");
});

test("S2 fill-forms: duplicated fully-qualified field names are rejected as ambiguous", async () => {
  const document = await PDFDocument.create();
  const page = document.addPage();
  const form = document.getForm();
  form.createTextField("dup").addToPage(page, { x: 40, y: 700, width: 200, height: 20 });
  const twin = form.createTextField("dup-twin");
  twin.addToPage(page, { x: 40, y: 660, width: 200, height: 20 });
  // pdf-lib refuses to create a duplicate through its API, so the second field
  // is renamed in the AcroForm dictionary — exactly the shape a hostile or
  // legacy generator produces.
  twin.acroField.dict.set(PDFName.of("T"), PDFString.of("dup"));
  const bytes = new Uint8Array(await document.save());
  const inventory = await inspectFormPdf(bytes);
  assert.deepEqual(inventory.duplicates, ["dup"]);
  await assert.rejects(() => fillFormPdf(bytes, { dup: "x" }), rejectionOf("FORM_UNSUPPORTED"));
});

test("S2 fill-forms: documents without a supported AcroForm are rejected, not treated as empty", async () => {
  const plain = await PDFDocument.create();
  plain.addPage();
  const plainBytes = new Uint8Array(await plain.save());
  await assert.rejects(() => fillFormPdf(plainBytes, { a: "x" }), rejectionOf("FORM_NOT_FOUND"));
  await assert.rejects(() => inspectFormPdf(new Uint8Array([0x25, 0x50, 0x44, 0x46])), rejectionOf("FORM_UNSUPPORTED"));
});

test("S2 fill-forms: values that do not match the field contract are rejected with actionable messages", async () => {
  const source = await applicationForm();
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{ "not.a.field": "x" }, /does not exist/u],
    [{ "applicant.name.en": 42 }, /expects a string/u],
    [{ consent: "yes" }, /expects a boolean/u],
    [{ city: "Dubai" }, /does not offer/u],
    [{ tags: ["alpha", "delta"] }, /does not offer/u],
    [{ tags: ["alpha", "alpha"] }, /duplicate selections/u],
    [{ "applicant.iqama": "1234567890123" }, /exceeds its 10 character limit/u],
    [{ "applicant.name.en": "line\nbreak" }, /single-line/u],
    [{ "applicant.name.en": "bell\u0007" }, /control character/u],
    [{ shift: "" }, /does not offer/u],
  ];
  for (const [values, pattern] of cases) {
    await assert.rejects(() => fillFormPdf(source, values as Record<string, string | boolean | string[]>), (error: unknown) => {
      assert.ok(error instanceof FormFillError && error.code === "FORM_VALUE_INVALID", `${JSON.stringify(values)} was not rejected as a value error`);
      assert.match(error.message, pattern);
      return true;
    });
  }
});

test("S2 fill-forms: scripts the approved fonts cannot render are refused instead of painted as tofu", async () => {
  const source = await applicationForm();
  for (const value of ["日本語のテキスト", "Кириллица", "हिन्दी"]) {
    await assert.rejects(
      () => fillFormPdf(source, { "applicant.notes": value }),
      (error: unknown) => error instanceof FormFillError && error.code === "FORM_UNSUPPORTED" && /cannot render/u.test(error.message),
      value,
    );
  }
});

test("S2 fill-forms: the transport payload is bounded and prototype-safe before any PDF is opened", () => {
  assert.throws(() => parseFieldsPayload(null), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload([]), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({}), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload(JSON.parse('{"__proto__":"x"}')), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({ a: 1 }), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({ "": "x" }), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({ ["a".repeat(201)]: "x" }), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({ a: "x".repeat(4_001) }), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => parseFieldsPayload({ a: Array.from({ length: 201 }, (_, index) => `o${index}`) }), rejectionOf("FORM_VALUE_INVALID"));
  assert.throws(() => assertFieldsPayloadSize("x".repeat(64 * 1024 + 1)), rejectionOf("FORM_VALUE_INVALID"));
  const parsed = parseFieldsPayload({ text: "ok", check: true, list: ["a", "b"] });
  assert.deepEqual(parsed, { text: "ok", check: true, list: ["a", "b"] });
});

test("S2 fill-forms: verification fails closed — a tampered output is never accepted", async () => {
  const source = await applicationForm();
  const result = await fillFormPdf(source, { "applicant.name.en": "Verified" });
  // Ask the verifier for a value that was never written: it must throw, which is
  // what guarantees the pipeline cannot store an output it did not check.
  await assert.rejects(() => verifyFilledForm(result.bytes, new Map([["applicant.name.en", "something else"]]), {}), rejectionOf("FORM_OUTPUT_UNVERIFIED"));
  // A field that vanished from the output is also a verification failure.
  await assert.rejects(() => verifyFilledForm(result.bytes, new Map(), { untouched: new Map([["ghost", null]]) }), rejectionOf("FORM_OUTPUT_UNVERIFIED"));
});

test("S2 fill-forms: inventory + assert helpers classify documents without writing to them", async () => {
  const source = await applicationForm();
  const document = await PDFDocument.load(source);
  const inventory = readFormInventory(document);
  assert.equal(inventory.pages, 1);
  assert.equal(inventory.hasXfa, false);
  assert.deepEqual(inventory.duplicates, []);
  assert.deepEqual(inventory.fields.map((field) => field.kind).sort(), ["checkbox", "dropdown", "optionlist", "radio", "text", "text", "text", "text", "text", "text"]);
  assert.equal(inventory.fields.length, 10);
  // Re-reading the same document must be stable (nothing was consumed).
  assert.deepEqual(readFormInventory(document), inventory);
  assert.doesNotThrow(() => assertFillableDocument(inventory, { encrypted: false, signed: false }));
  assert.throws(() => assertFillableDocument(inventory, { encrypted: false, signed: true }), rejectionOf("FORM_RESTRICTED"));
  assert.throws(() => assertFillableDocument(inventory, { encrypted: true, signed: false }), rejectionOf("FORM_RESTRICTED"));
  assert.throws(() => validateFillValues(inventory, {}), rejectionOf("FORM_VALUE_INVALID"));
  const validated = validateFillValues(inventory, { "applicant.name.en": "Validated", consent: false });
  assert.deepEqual([...validated.entries()], [["applicant.name.en", "Validated"], ["consent", false]]);
});

test("S2 fill-forms: verification and fill failures never echo the submitted value into a persisted message", async () => {
  const source = await applicationForm();
  const secret = "CONFIDENTIAL-IDENTIFIER-918273";
  const filled = await fillFormPdf(source, { "applicant.name.en": secret });
  // A verification failure is stored as the job's error message, so it must
  // describe the mismatch without reproducing either value.
  const error = await verifyFilledForm(filled.bytes, new Map([["applicant.name.en", "different"]])).then(() => undefined, (thrown: unknown) => thrown);
  assert.ok(error instanceof FormFillError);
  assert.equal(error.code, "FORM_OUTPUT_UNVERIFIED");
  assert.doesNotMatch(error.message, /CONFIDENTIAL-IDENTIFIER-918273/u);
  assert.doesNotMatch(error.message, /different/u);
  assert.match(error.message, /string\(\d+ chars\)/u);
  // Untouched-field drift is described the same way.
  const drift = await verifyFilledForm(filled.bytes, new Map(), { untouched: new Map([["reference", "WRONG-VALUE"]]) }).then(() => undefined, (thrown: unknown) => thrown);
  assert.ok(drift instanceof FormFillError);
  assert.doesNotMatch(drift.message, /WRONG-VALUE/u);
});

test("S2 fill-forms: values are never written to logs, metrics or audit metadata", async () => {
  const source = await applicationForm();
  const secret = "APPLICANT-SECRET-553311";
  // Capture everything the engine and pipeline modules log while a real fill runs.
  const captured: string[] = [];
  const original = { info: console.info, warn: console.warn, error: console.error, log: console.log };
  const capture = (...args: unknown[]) => { captured.push(args.map((value) => typeof value === "string" ? value : JSON.stringify(value)).join(" ")); };
  console.info = capture; console.warn = capture; console.error = capture; console.log = capture;
  try {
    await fillFormPdf(source, { "applicant.name.en": secret, "applicant.notes": "ملاحظة سرية" });
  } finally {
    console.info = original.info; console.warn = original.warn; console.error = original.error; console.log = original.log;
  }
  for (const line of captured) {
    assert.doesNotMatch(line, /APPLICANT-SECRET-553311/u, "a field value reached a log line");
    assert.doesNotMatch(line, /ملاحظة سرية/u, "an Arabic field value reached a log line");
  }
});
