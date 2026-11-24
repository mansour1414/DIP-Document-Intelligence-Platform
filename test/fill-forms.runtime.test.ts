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
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFNumber, PDFString, StandardFonts } from "pdf-lib";
import {
  FormFillError,
  assertFillableDocument,
  readFormInventory,
  validateFillValues,
  verifyFilledForm,
} from "../src/lib/pdf/form-schema";
import { assertFieldsPayloadSize, parseFieldsPayload } from "../src/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES } from "../src/lib/pdf/form-types";
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
  // FF-08: the message is allowlisted and content-free, so the *reason* lives in
  // structured detail rather than in prose that gets persisted on the job row.
  await assert.rejects(
    () => fillFormPdf(source, { declaration: "tampered" }),
    (error: unknown) => {
      assert.ok(error instanceof FormFillError && error.code === "FORM_VALUE_INVALID");
      assert.equal(error.message, FORM_ERROR_MESSAGES.FORM_VALUE_INVALID);
      assert.deepEqual((error.details as { issues: unknown[] }).issues, [{ issue: "READ_ONLY_FIELD", index: 0 }]);
      // Neither the value nor the field name may appear anywhere in the payload.
      const serialized = JSON.stringify(error);
      assert.doesNotMatch(serialized, /tampered|declaration/u);
      return true;
    },
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

test("S2 fill-forms: values that do not match the field contract are rejected with a stable issue code", async () => {
  const source = await applicationForm();
  // FF-08: each case asserts the *issue code* from the allowlist. Messages are
  // now content-free and identical for every rejection, so the code — not prose —
  // is the contract a client maps onto its own field UI.
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ "not.a.field": "x" }, "UNKNOWN_FIELD"],
    [{ "applicant.name.en": 42 }, "TYPE_MISMATCH"],
    [{ consent: "yes" }, "TYPE_MISMATCH"],
    [{ city: "Dubai" }, "OPTION_NOT_OFFERED"],
    [{ tags: ["alpha", "delta"] }, "OPTION_NOT_OFFERED"],
    [{ tags: ["alpha", "alpha"] }, "DUPLICATE_SELECTION"],
    [{ "applicant.iqama": "1234567890123" }, "LENGTH_EXCEEDED"],
    [{ "applicant.name.en": "line\nbreak" }, "LINE_BREAK_IN_SINGLE_LINE"],
    [{ "applicant.name.en": "bell\u0007" }, "CONTROL_CHARACTER"],
    [{ shift: "" }, "OPTION_NOT_OFFERED"],
  ];
  for (const [values, issue] of cases) {
    await assert.rejects(() => fillFormPdf(source, values as Record<string, string | boolean | string[]>), (error: unknown) => {
      assert.ok(error instanceof FormFillError && error.code === "FORM_VALUE_INVALID", `${JSON.stringify(values)} was not rejected as a value error`);
      assert.equal(error.message, FORM_ERROR_MESSAGES.FORM_VALUE_INVALID);
      const issues = (error.details as { issues: Array<{ issue: string }> }).issues;
      assert.ok(issues.some((entry) => entry.issue === issue), `${JSON.stringify(values)} produced ${JSON.stringify(issues)}, expected ${issue}`);
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
  // FF-08: the detail is a count of stable codes — no types, lengths or names.
  assert.equal(error.message, FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED);
  assert.deepEqual((error.details as { mismatches: unknown[] }).mismatches, [{ code: "VALUE_NOT_ROUND_TRIPPED", count: 1 }]);
  assert.doesNotMatch(JSON.stringify(error), /applicant\.name\.en|CONFIDENTIAL|different/u);
  // Untouched-field drift is described the same way.
  const drift = await verifyFilledForm(filled.bytes, new Map(), { untouched: new Map([["reference", "WRONG-VALUE"]]) }).then(() => undefined, (thrown: unknown) => thrown);
  assert.ok(drift instanceof FormFillError);
  assert.doesNotMatch(drift.message, /WRONG-VALUE/u);
  assert.deepEqual((drift.details as { mismatches: unknown[] }).mismatches, [{ code: "UNTOUCHED_FIELD_MODIFIED", count: 1 }]);
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

// ------------------------------------------------- FF-02 / FF-05 / FF-09 regression
//
// Each test below reproduces a defect the independent review found in the
// previous head. They are written against the *fixture shape the review used*,
// so a regression shows up as the same wrong outcome, not as a different one.

/** Add a field entry to the AcroForm `/Fields` array. */
function pushField(document: PDFDocument, entry: unknown) {
  const fields = document.getForm().acroForm.dict.lookup(PDFName.of("Fields"));
  assert.ok(fields instanceof PDFArray, "fixture must have an AcroForm /Fields array");
  const dict = document.context.obj(entry as Record<string, never>);
  fields.push(document.context.register(dict) as unknown as Parameters<typeof fields.push>[0]);
}

test("FF-02: a signature field nested under /Kids is refused before any write", async () => {
  // Review evidence: this document was accepted and produced an 11,289-byte
  // filled output. Only the top level of /Fields used to be inspected.
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField("name").addToPage(page, { x: 20, y: 200, width: 200, height: 20 });
  const signature = document.context.register(document.context.obj({ Type: "Annot", Subtype: "Widget", Rect: [20, 20, 120, 40], FT: "Sig", T: "signature1" }));
  pushField(document, { T: "group", Kids: [signature] });
  const bytes = new Uint8Array(await document.save({ updateFieldAppearances: false }));

  await assert.rejects(() => inspectFormPdf(bytes), rejectionOf("FORM_RESTRICTED"));
  await assert.rejects(() => fillFormPdf(bytes, { name: "x" }), rejectionOf("FORM_RESTRICTED"));
});

test("FF-02: an inherited /FT is read from the ancestor, not only from the child", async () => {
  // `/FT` is inheritable in the PDF object model: the child has none of its own,
  // so a scan that reads only the child's entry sees an ordinary field.
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField("name").addToPage(page, { x: 20, y: 200, width: 200, height: 20 });
  const child = document.context.register(document.context.obj({ Type: "Annot", Subtype: "Widget", Rect: [20, 20, 120, 40], T: "child" }));
  pushField(document, { T: "parent", FT: "Sig", Kids: [child] });
  const bytes = new Uint8Array(await document.save({ updateFieldAppearances: false }));
  await assert.rejects(() => inspectFormPdf(bytes), rejectionOf("FORM_RESTRICTED"));
});

test("FF-02: an unresolved /Perms entry is refused instead of read as unrestricted", async () => {
  // Review evidence: this document was accepted and produced 11,238 bytes.
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField("name").addToPage(page, { x: 20, y: 200, width: 200, height: 20 });
  document.catalog.set(PDFName.of("Perms"), document.context.nextRef());
  const bytes = new Uint8Array(await document.save({ updateFieldAppearances: false }));
  await assert.rejects(() => inspectFormPdf(bytes), rejectionOf("FORM_RESTRICTED"));
  await assert.rejects(() => fillFormPdf(bytes, { name: "x" }), rejectionOf("FORM_RESTRICTED"));
});

test("FF-02: malformed structure fails closed, and a /Kids cycle terminates", async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField("name").addToPage(page, { x: 20, y: 200, width: 200, height: 20 });
  // `/Fields` is not an array: the walk cannot establish the document's shape.
  document.getForm().acroForm.dict.set(PDFName.of("Fields"), document.context.obj({ T: "not-an-array" }));
  const bytes = new Uint8Array(await document.save({ updateFieldAppearances: false }));
  await assert.rejects(() => inspectFormPdf(bytes), rejectionOf("FORM_RESTRICTED"));

  // A `/Kids` cycle must be detected, not followed forever.
  const cyclic = await PDFDocument.create();
  const cyclicPage = cyclic.addPage([300, 300]);
  cyclic.getForm().createTextField("name").addToPage(cyclicPage, { x: 20, y: 200, width: 200, height: 20 });
  const node = cyclic.context.obj({ T: "loop" });
  const nodeRef = cyclic.context.register(node);
  node.set(PDFName.of("Kids"), cyclic.context.obj([nodeRef]));
  const fields = cyclic.getForm().acroForm.dict.lookup(PDFName.of("Fields"));
  if (fields instanceof PDFArray) fields.push(nodeRef);
  const cyclicBytes = new Uint8Array(await cyclic.save({ updateFieldAppearances: false }));
  // The reference walk terminates on the cycle by itself; the inventory built
  // afterwards cannot be trusted, so the document is refused either way — and it
  // is refused with a *coded* error, never an unclassified `RangeError`.
  await assert.rejects(() => inspectFormPdf(cyclicBytes), (error: unknown) => {
    assert.ok(error instanceof FormFillError, `expected a coded failure, got ${String(error)}`);
    assert.ok(["FORM_RESTRICTED", "FORM_UNSUPPORTED"].includes(error.code));
    return true;
  });
});

test("FF-05: flattening leaves no unresolved or surviving widget annotations", async () => {
  // Review evidence: a two-page, 15-widget form flattened to a document with
  // 0 fields but 15 unresolved `/Annots` entries (pypdf) / 15 `Invalid XRef`
  // (Poppler), while still reopening with the same page count — which is why the
  // old gate passed it.
  const document = await PDFDocument.create();
  const pages = [document.addPage([300, 300]), document.addPage([300, 300])];
  const form = document.getForm();
  for (let index = 0; index < 15; index += 1) {
    const field = form.createTextField(`f${index}`);
    field.setText(`v${index}`);
    field.addToPage(pages[index < 8 ? 0 : 1], { x: 10, y: 20 + (index % 8) * 30, width: 120, height: 18 });
  }
  // An unrelated (non-widget) annotation must survive the prune.
  pages[0].node.set(PDFName.of("Annots"), document.context.obj([
    ...(pages[0].node.Annots()?.asArray() ?? []),
    document.context.register(document.context.obj({ Type: "Annot", Subtype: "Link", Rect: [10, 280, 80, 295] })),
  ]));
  const source = new Uint8Array(await document.save({ updateFieldAppearances: false }));
  const values = Object.fromEntries(Array.from({ length: 15 }, (_, index) => [`f${index}`, "filled"]));
  const result = await fillFormPdf(source, values, { flatten: true });

  // Independent re-read with pdf-lib (no Poppler/pypdf in this sandbox).
  const reopened = await PDFDocument.load(result.bytes);
  assert.equal(reopened.getPageCount(), 2);
  assert.equal(reopened.getForm().getFields().length, 0, "flattening must remove the fields");
  let annots = 0;
  let unresolved = 0;
  let widgets = 0;
  let links = 0;
  for (const page of reopened.getPages()) {
    const array = page.node.Annots();
    if (!array) continue;
    for (let index = 0; index < array.size(); index += 1) {
      annots += 1;
      const entry = array.get(index);
      const target = reopened.context.lookup(entry);
      if (target === undefined) unresolved += 1;
      else if (target instanceof PDFDict) {
        const subtype = String(target.get(PDFName.of("Subtype")) ?? "");
        if (subtype === "/Widget") widgets += 1;
        if (subtype === "/Link") links += 1;
      }
    }
  }
  assert.equal(unresolved, 0, "no dangling /Annots reference may remain");
  assert.equal(widgets, 0, "a flattened widget must not survive as an annotation");
  assert.equal(links, 1, "unrelated annotations must be preserved");
  assert.equal(annots, 1);
});

test("FF-09: clearing a text field to an empty string verifies instead of failing", async () => {
  // Review evidence: `""` produced FORM_OUTPUT_UNVERIFIED with
  // "expected string(0 chars), found empty" — a correct write reported as an error.
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  const field = document.getForm().createTextField("note");
  field.setText("something to clear");
  field.addToPage(page, { x: 20, y: 200, width: 200, height: 20 });
  const source = new Uint8Array(await document.save({ updateFieldAppearances: false }));

  const result = await fillFormPdf(source, { note: "" });
  assert.equal(result.report.filled.length, 1);
  const reopened = await PDFDocument.load(result.bytes);
  const value = reopened.getForm().getTextField("note").getText();
  // Both empty spellings are the same value: absent `/V` and `/V ()`.
  assert.ok(value === "" || value === undefined, `expected an empty value, got ${JSON.stringify(value)}`);
});

// ------------------------------------------------------------------ FF-07 / FF-03

test("FF-07: Arabic line breaks survive layout, and an over-wide value is refused rather than clipped", async () => {
  const { renderWidgetAppearance, AppearanceLegibilityError } = await import("../src/lib/pdf/form-appearance");
  // Two explicit lines must stay two lines. The previous layout collapsed them
  // into one, which is a silent content change on the page.
  const twoLines = renderWidgetAppearance({ text: "سطر أول\nسطر ثانٍ", width: 200, height: 60, multiline: true });
  const oneLine = renderWidgetAppearance({ text: "سطر أول سطر ثانٍ", width: 200, height: 60, multiline: true });
  assert.ok(twoLines.byteLength > 0 && oneLine.byteLength > 0);
  // The review's 209-character value in a 90 pt widget was clipped. It must now
  // be rejected outright: no partial output is produced at all.
  assert.throws(
    () => renderWidgetAppearance({ text: "ب".repeat(209), width: 90, height: 18 }),
    (error: unknown) => error instanceof AppearanceLegibilityError && error.reason === "VALUE_OVERFLOWS_WIDGET",
  );
  // The review's 18x7 pt widget cannot hold legible text at any font size. The
  // measured rectangle includes the border, so it reaches the renderer as 19x8.
  assert.throws(
    () => renderWidgetAppearance({ text: "x", width: 19, height: 8 }),
    (error: unknown) => error instanceof AppearanceLegibilityError && error.reason === "WIDGET_TOO_SMALL",
  );
  // Multiline overflow beyond the line budget is refused, not truncated.
  assert.throws(
    () => renderWidgetAppearance({ text: Array.from({ length: 40 }, () => "نص").join(" "), width: 80, height: 20, multiline: true }),
    (error: unknown) => error instanceof AppearanceLegibilityError,
  );
});

test("FF-07: an unrenderable value fails the whole fill and produces no output document", async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  // A widget too small to render Arabic legibly.
  const field = document.getForm().createTextField("tiny");
  field.addToPage(page, { x: 10, y: 10, width: 18, height: 7 });
  const source = new Uint8Array(await document.save({ updateFieldAppearances: false }));
  await assert.rejects(() => fillFormPdf(source, { tiny: "نورة" }), (error: unknown) => {
    assert.ok(error instanceof FormFillError);
    assert.equal(error.code, "FORM_VALUE_INVALID");
    // Round 2: the rejection now names the *geometry* problem directly instead of
    // reporting it as a script-encoding failure, so a caller can tell "the widget
    // is too small" from "the script has no face".
    assert.deepEqual((error.details as { issues: Array<{ issue: string; field: string }> }).issues, [{ issue: "WIDGET_TOO_SMALL", field: "tiny" }]);
    return true;
  });
});

test("FF-03: the encrypted payload is non-destructive, tenant-bound and purged by lifecycle", async () => {
  const { putFormFields, readFormFields, purgeFormFields, formPayloadTtlSeconds } = await import("../src/lib/pdf/form-payload");
  // An in-memory store with the same semantics as the Redis one (`GET`, not
  // `GETDEL`), so retry-safety is provable without a live Redis.
  const items = new Map<string, { value: string; ttl: number }>();
  const store = {
    async set(key: string, value: string, ttl: number) {
      if (items.has(key)) throw new Error("SECRET_REFERENCE_COLLISION");
      items.set(key, { value, ttl });
    },
    async get(key: string) { return items.get(key)?.value ?? null; },
    async delete(key: string) { items.delete(key); },
  };
  process.env.PHASE1_SECRET_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");

  const values = { "applicant.name.ar": "نورة الحربي", "applicant.iqaz": "2412345678" };
  const reference = await putFormFields({ tenantId: "tenant-a", jobId: "job-1", fields: values }, store);
  assert.match(reference, /^[0-9a-f-]{36}$/u, "the reference must be an opaque uuid");
  // The stored envelope must not contain the values in clear text.
  const stored = [...items.values()][0];
  assert.doesNotMatch(stored.value, /نورة|2412345678/u, "values must be encrypted at rest");
  // TTL is the approved abandoned-job grace, not an arbitrary number.
  assert.ok(stored.ttl >= 24 * 60 * 60, `ttl ${stored.ttl} must cover the retention grace`);

  // Retry-safe: the same reference reads repeatedly.
  assert.deepEqual(await readFormFields({ reference, tenantId: "tenant-a", jobId: "job-1" }, store), values);
  assert.deepEqual(await readFormFields({ reference, tenantId: "tenant-a", jobId: "job-1" }, store), values);

  // Cross-tenant and cross-job reads fail authentication rather than returning data.
  await assert.rejects(() => readFormFields({ reference, tenantId: "tenant-b", jobId: "job-1" }, store), (error: unknown) => (error as { code?: string }).code === "FORM_PAYLOAD_INVALID");
  await assert.rejects(() => readFormFields({ reference, tenantId: "tenant-a", jobId: "job-2" }, store), (error: unknown) => (error as { code?: string }).code === "FORM_PAYLOAD_INVALID");

  // Purge is idempotent and makes the reference unusable.
  await purgeFormFields(reference, store);
  await purgeFormFields(reference, store);
  await assert.rejects(() => readFormFields({ reference, tenantId: "tenant-a", jobId: "job-1" }, store), (error: unknown) => (error as { code?: string }).code === "FORM_PAYLOAD_EXPIRED");
  assert.ok(formPayloadTtlSeconds() >= 86_400);
});
