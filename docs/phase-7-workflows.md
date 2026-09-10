# Phase 7 — Workflow orchestration

Phase 7 adds deterministic reusable workflows above the existing execution system. It does **not** include the Document Agent, natural-language planning, dynamic tool selection, memory, arbitrary code, shell/network nodes, schedules, webhooks, or external connectors.

## Architecture

`Workflow` owns the user-visible saved definition. Every edit creates an immutable `WorkflowVersion`; historical `WorkflowRun` rows retain a restrictive foreign key to the exact version they started with. Each tool node creates one ordinary `Job`, linked by `workflow_run_id` and `workflow_node_id`. The existing `JobStep` and `ToolExecution` rows remain the detailed execution source of truth.

The orchestrator validates before save and again before run, resolves explicit bindings to authorized `File` IDs, and calls the same trusted job-creation boundary used by ordinary tools. That boundary reapplies Tool Registry limits, server-derived entitlements, concurrency/usage policy, credit accounting, queues, workers, AI Gateway, output validation, and private object storage. Workflow code never calls PDF, Office, OCR, or AI processors directly.

## Graph and bindings

MVP graphs are finite deterministic DAGs with at most 20 nodes. Node IDs are explicit and unique. Every node pins a registered tool version, lists dependencies, and has explicit inputs from either a named workflow input or a numbered upstream output. Validation rejects malformed definitions, cycles, missing dependencies, disabled/unregistered tools, unsupported versions, empty bindings, incompatible known MIME chains, excess nodes, and applicable plan restrictions.

Browsers provide file IDs, never object keys. At execution time every file is re-authorized against the run owner and its MIME type is checked against the target tool. Upstream multi-output results retain their existing ordered `outputFileIds` semantics.

## State, retry, failure, and cancellation

Phase 7 schedules one ready node at a time. PostgreSQL is the durable source of truth; BullMQ remains the delivery/retry mechanism. Node idempotency keys are `workflow:<run-id>:<node-id>`, so retries reuse the existing job and completed side effects. Worker completion advances the run. A reconciliation call may safely advance a non-terminal run after restart.

If a node exhausts retries, the run becomes failed with the failing node/job reference. Dependents never start; prior valid artifacts remain. Empty or stalled graphs fail with a structured terminal code. Cancellation marks the run terminal and cancels queued/retrying jobs; active processors observe the existing cooperative cancellation boundary, while completed artifacts and audit history are preserved.

## Tenant security and retention

`workflows`, `workflow_versions`, and `workflow_runs` enable PostgreSQL RLS. Policies use transaction-local `app.current_user_id` and fail closed without context. The runtime role receives only table DML grants and retains no superuser, BYPASSRLS, CREATEDB, CREATEROLE, ownership, or schema-creation privileges. Existing job/file RLS protects linked execution and artifacts.

Retention must treat files referenced by active workflow jobs exactly like ordinary active-job files. Successful artifacts follow the existing plan retention policy.

## Templates

The built-in, version-1 registry-contract templates are:

- Merge PDF → Compress PDF
- OCR PDF → Summarize PDF
- Word to PDF → Compress PDF
- Excel to PDF → Compress PDF (CR-002)

## Operations

Use workflow/run/correlation/job/node IDs in structured logs when diagnosing a run. Inspect PostgreSQL first, then the appropriate BullMQ queue and worker logs. A non-terminal run with no queued/running/retrying job is safe to reconcile through the orchestration service; it will schedule exactly one eligible node or set a terminal `WORKFLOW_STALLED`/binding error. Never repair a run by editing object keys or manually fabricating tool outputs.
