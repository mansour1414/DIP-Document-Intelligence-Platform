# CR-003 Groq Production Routing

## Decision

Current: Gemini is DIP's production AI provider through the AI Gateway.

Proposed and approved: make Groq the production AI provider using `openai/gpt-oss-120b`. Groq passed the CR-002 live evaluation for the bilingual document-AI corpus. Gemini Free repeatedly prevented Full Release B closure with HTTP 429 `RESOURCE_EXHAUSTED`, including the approved fifth and final attempt.

## Routing and safety boundary

All production calls continue through Task → Policy → Routing → Provider Adapter → Response Validation → Usage Accounting. Business logic must not call either provider directly. `AI_PROVIDER` defaults to `groq`; `GROQ_MODEL` and route-class model variables remain configurable, with `openai/gpt-oss-120b` as the approved default. Gemini remains registered and can be selected explicitly with `AI_PROVIDER=gemini`; it is not deleted and is not an automatic fallback.

The existing structured-output validation, grounding and citations, document scope, untrusted-document handling, prompt-injection protections, credits, limits, safe error classification, provider token accounting, and approved price configuration remain mandatory. The queue retry policy remains exactly five attempts. This CR adds no automatic fallback.

## Release B closure

Full Release B supplies the same production `AI_PROVIDER=groq` route and `GROQ_API_KEY` to both the production worker and the Public API/Agent Planner process. Summarize PDF, Chat with PDF, Extract Data, and Agent planning therefore use `executeAiGateway` and `routeAiTask`; the workflow does not call the CR-002 evaluation gateway and does not use a mock or test-only provider bypass.
