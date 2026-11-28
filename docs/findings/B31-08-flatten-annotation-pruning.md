# Flatten compatibility finding (B31-08 candidate)

Status: **unresolved**. Recorded rather than fixed; no flattening redesign was undertaken.

## What was observed

Calling the bounded child's `fill` operation with `flatten: true` on a **hand-written**
AcroForm PDF — one where the widget is declared as a page annotation
(`/Annots[5 0 R]` → `/Type/Annot /Subtype/Widget /FT/Tx ...`) with **no `/AP` appearance
stream** — produces:

```
{"ok":false,"op":"fill","code":"FORM_OUTPUT_UNVERIFIED"}
```

The parent sanitises `details` (by design), so the wire reply does not name the guard.
Instrumenting `src/lib/pdf/form-fill.ts` located it:

```
[D] pre-prune
[D] removed= 0 of 1        <-- this tripwire
```

which is the guard at `form-fill.ts`:

```ts
const pruned = pruneAnnotations(reopened, widgets);
if (pruned.removed !== widgets.size) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", ..., { flatten: "ANNOTATION_COUNT_MISMATCH" });
```

## Why `removed` is 0

`pdf-lib`'s `flatten()` has two different behaviours depending on the input:

| input | `flatten()` | `/Annots` after flatten | `pruneAnnotations` removes |
|---|---|---|---|
| pdf-lib-generated form | succeeds | still holds the widget ref (size 1) | 1 → guard passes |
| hand-written form, no `/AP` | succeeds | already emptied (size 0) | 0 → guard fails |

So the guard's premise — "flattening leaves the widget references behind, so we must
remove exactly as many as there were widgets" — holds for the documents the test suite
and the product generate, and **not** for hand-written forms where pdf-lib cleans up
itself. The check is a tripwire on `pdf-lib`'s internal behaviour, so its correctness
depends on that behaviour.

## What was verified

- pdf-lib-generated forms, `flatten: true` → `{"ok":true,...,"report":{...,"flatten":true}}`
- pdf-lib-generated forms, `flatten: false` → `{"ok":true,...}`
- The failing fixture is otherwise a **valid** PDF: it inspects cleanly
  (`{"ok":true,"op":"inspect","pages":1,...}`), and `fill` with `flatten: false`
  succeeds on the same bytes.
- A truly malformed widget (no `/AP`, and pdf-lib cannot locate a normal appearance)
  makes `flatten()` *throw*, which `form-fill.ts` maps to
  `FORM_UNSUPPORTED {flatten:"FAILED"}` — a different, clearer failure than the one
  above.

## Why it is not treated as a confirmed product defect

Whether a hand-written form without `/AP` is a **supported input** is not established by
the codebase: there is no documented contract for it, and the existing test corpus only
covers pdf-lib-generated forms. Declaring it a defect would assert a contract that does
not exist; declaring it invalid would be equally unfounded.

The `removed !== widgets.size` comparison remains a real fragility regardless: it can
only pass when `pdf-lib` leaves references behind, which is an implementation detail of
a dependency rather than a property the product guarantees.

## Reproduction

The fixture builder is `buildPdf({ withField: true })` in
`scripts/smoke-pdf-worker-artifact.mjs` (kept deliberately, now that the fill/flatten
smoke scenarios use `buildFormPdf()` instead). To reproduce, send that document to the
child with an `op:"fill"` control block and `flatten:true`.

## Suggested follow-up (not done here)

- Decide and document whether a widget without `/AP` is a supported input.
- If it is: replace the count-equality tripwire with a property that does not depend on
  `pdf-lib`'s internal cleanup — e.g. assert that **no widget reference that still exists
  in the document remains in any `/Annots`**, which is true in both behaviours above.
- If it is not: detect the missing `/AP` before calling `flatten()` and refuse with a
  specific code, instead of surfacing an internal-count mismatch as
  `FORM_OUTPUT_UNVERIFIED`.
