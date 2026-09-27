# DIP Structural Grayscale Engine - Stage 3C Linux Sandbox Gate

## Decision

Stage 3C adds an isolated, fail-closed GitHub Actions gate for the bounded Stage 3A feature set. It does not approve production adoption, add a production dependency, register Grayscale, or expose a UI/API/Workflow/Agent path. Phase 1 remains **NOT COMPLETE** until the new Linux job executes successfully and a separate production-adoption Change Request is approved.

The existing nine CI jobs are unchanged. A tenth independent job builds the actual `Dockerfile.worker` image, builds the experiment as a derivative, and runs only synthetic review fixtures. The current Windows host has no Docker/Podman/WSL runtime, so Linux sandbox execution is an **ENVIRONMENT-GATED TEST**, not a local pass.

## Implemented CI gate

The job performs these mandatory steps:

1. generate the independent Chromium Arabic source and expected PDFs;
2. download the exact CPython 3.11 Linux wheels specified by the experimental requirements;
3. fail on reviewed pikepdf/Pillow wheel hash drift and record every downloaded wheel hash;
4. generate wheel audit evidence and a supplemental CycloneDX SBOM;
5. build the production worker unchanged, then build the Stage 3C derivative;
6. run as UID/GID 10001 with read-only root, `--network none`, `--cap-drop ALL`, `no-new-privileges`, 1 CPU, 768 MiB RAM/swap, 128 PIDs, bounded file/process/CPU ulimits, `/tmp` 64 MiB, and `/tmp/dip` 256 MiB;
7. enforce a 420-second outer container timeout and a 300-second corpus timeout;
8. run Stage 2, Stage 3A, Stage 3B, Unicode-widget, and deterministic mutation probes;
9. prove cleanup after success, malformed-input failure, and forced timeout;
10. reject any PDF in the published artifact directory and upload sanitized JSON only.

There is no `continue-on-error`, conditional success, or missing-runtime skip. Docker, cgroup v2, native-library, tmpfs, network, qpdf, or Ghostscript assertions fail the job.

## Dependency and SBOM evidence required in Linux

The sandbox probe asserts the following exact runtime identities:

| Component | Required identity | Evidence |
| --- | --- | --- |
| production qpdf CLI | Debian `11.3.0-1+deb12u1` | `dpkg-query` and `qpdf --version` inside the derivative |
| pikepdf | `10.13.0.post1` | installed metadata and reviewed wheel SHA-256 `365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8` |
| embedded libqpdf | `12.3.2` | `pikepdf.__libqpdf_version__` and ELF `ldd` inventory |
| Pillow | `12.3.0` | installed metadata and reviewed wheel SHA-256 `23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd` |
| LittleCMS | runtime `2.19`; Pillow SBOM component `2.19.1` | Pillow feature API, bundled SONAME/ELF inventory, and supplemental SBOM |
| libimagequant | disabled and not linked | Pillow feature API plus ELF inventory |
| Ghostscript | absent | executable/path assertions before build completion and during processing |

All auxiliary package versions remain exact in the experimental requirements. The generated wheel manifest hashes every transitive wheel. The supplemental SBOM explicitly inventories bundled libqpdf because the upstream pikepdf auditwheel SBOM omits it. These are technical findings, not legal approval. Direct pikepdf/Pillow adoption and MPL-2.0 obligations remain a licensing gate.

## Local corpus evidence

The isolated Stage 3C orchestrator passed locally with the exact experimental package versions. It reran both Stage 2 locales, six Stage 2 fail-closed cases, eleven Stage 3A fail-closed cases, the nine-natural-JPEG/two-renderer Stage 3B corpus, twelve Stage 3B mutation cases, and the independent Chromium Arabic reader checks.

The new Unicode widget corpus uses independent Chromium-generated appearances, an embedded Unicode-capable Arabic font, and two editable values (Arabic and mixed Arabic/English/numeric/email). This replaced a rejected ReportLab fallback whose font was Unicode-capable but whose missing bidi helper produced incorrect visual word order. Results:

- two widgets and all six `/AP/N`, `/AP/R`, `/AP/D` references survived;
- six embedded Unicode-font references survived;
- field names, `/Tx` types, indirect object identities, and values were identical before and after transformation;
- output and independent grayscale expected render were pixel-identical: MAE 0, maximum delta 0, zero changed pixels at 893 x 1263;
- actual edits to the existing field objects retained their names, types, indirect identities, and both new values; after bounded whole-document processing the regenerated appearances were pixel-identical to the independent expected fixture;
- deliberately colored external regeneration differed from grayscale as expected (MAE 0.096165, maximum delta 93, 3,798 changed pixels);
- whole-document reprocessing restored a pixel-identical grayscale appearance while retaining the edited field values.

PDFium form rendering uses RGB subpixel antialiasing, which creates channel differences even for an independently generated grayscale text appearance. Stage 3C therefore does not misclassify antialiasing as PDF color content. It requires zero residual structural color operators/resources and pixel equality with the independently generated grayscale fixture. The colored control proves that this comparison detects actual reintroduced color.

The additional deterministic mutation corpus contains 24 cases in separate subprocesses bounded to 20 seconds each. Locally, 12 were accepted and independently reopened/validated, 12 were rejected, zero timed out, and zero partial outputs remained; elapsed fuzz time was 121,297 ms. Any timeout is forcibly killed and is accepted only as a safe rejection when no partial output exists. This is a bounded security probe, not coverage-guided fuzzing.

## Sanitized artifacts

The job uploads only:

- sandbox UID/GID, mount, network, cgroup, rlimit, version, and ELF evidence;
- wheel audit and all-wheel SHA-256 manifest;
- supplemental CycloneDX SBOM;
- corpus metrics;
- malformed-input and timeout cleanup results;
- base/derivative image identifiers and a minimal CI diagnostic.

No credentials, environment dump, user PDF, generated PDF, or raw process input is published.

## Unsupported scope

Stage 3C deliberately does not expand Stage 3A. The engine still rejects or does not claim support for JPX, JBIG2, CCITT, compound image filters, unprofiled CMYK images, DeviceN/NChannel, arbitrary tint functions, mesh/multi-function shadings, uncolored/complex patterns, complex masks, signed/encrypted/XFA PDFs, JavaScript appearances, and external proprietary-reader appearance regeneration.

## Remaining blockers

- **ENVIRONMENT-GATED TEST:** the new job has not run in GitHub Actions from this uncommitted working tree; local Windows execution cannot prove Linux cgroup, tmpfs, ELF, or network isolation.
- **SECURITY GATE:** successful Linux evidence and broader coverage-guided fuzzing are required before production adoption.
- **LICENSING GATE:** technical inventory is implemented, but direct pikepdf/Pillow use, MPL obligations, and the complete production SBOM require owner/legal approval.
- **CAPABILITY/PoC BLOCKER:** all Stage 3A unsupported features remain unsupported; proprietary reader/editor regeneration remains unproved.
- **CHANGE REQUEST REQUIRED:** production dependency adoption, worker integration, Tool Registry registration, Web/API/Workflow/Agent exposure, and product claims are not approved by Stage 3C.

## Proposed production-adoption Change Request

After the Stage 3C Linux job is green, request separate approval to:

1. accept the bounded feature matrix and fail-closed unsupported policy;
2. approve the exact reviewed Linux wheels and license obligations;
3. merge the supplemental libqpdf component into the full production SBOM;
4. integrate the engine into the existing worker without changing qpdf CLI `11.3.0-1+deb12u1`, sandbox constraints, or Ghostscript prohibition;
5. add production Tool Registry v1, Job/Worker, Workflow, Agent, Public API, EN/AR/RTL UI, SEO, output validation, and observability contracts;
6. require signed/encrypted rejection, corpus expansion, coverage-guided fuzzing, and the existing nine CI jobs plus Stage 3C to remain green.

No part of this document grants that approval.
