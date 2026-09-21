# CR-002 Groq GPT-OSS Evaluation

## Decision

Gemini remains DIP's initial and only production-routed AI provider. CR-002 authorizes a Groq adapter for evaluation and testing of `openai/gpt-oss-120b`; it does not authorize production routing, fallback, or closure of the Full Release B production gate.

## Evaluation boundary

The evaluation covers Summarize PDF, Chat with PDF, and Extract Data in Arabic and English. All calls retain the existing Task → Policy → Routing → Provider Adapter → Response Validation → Usage Accounting sequence, document-scoped prompts, structured output validation, citation page checks, token limits, credit boundary, safe diagnostics, and the existing five-attempt queue policy.

Production `routeAiTask` always resolves Gemini. Groq is reachable only through `routeAiEvaluationTask`/`executeAiEvaluationGateway`, requires `GROQ_EVALUATION_ENABLED=1`, and rejects Agent planning. Groq is never a production fallback under this CR.

## Pricing and accounting

CR-002 approves Groq's published `openai/gpt-oss-120b` price of $0.15 input and $0.60 output per million tokens, effective 2026-09-21. The pricing source is `https://console.groq.com/docs/model/openai/gpt-oss-120b`. This schedule lives in the centralized usage-accounting configuration, not business logic. `GROQ_INPUT_USD_PER_MILLION` and `GROQ_OUTPUT_USD_PER_MILLION` remain optional paired contract overrides; a partial override fails closed. Actual prompt and completion token counts returned by Groq flow through the existing accounting contract.

## Evaluation corpus and acceptance gate

The checked-in synthetic corpus contains parallel English and Arabic contract facts and exercises all three document AI tools. Automated checks cover structured JSON, grounding citations within page scope, bilingual task construction, safe transient/permanent error classification, secret/content redaction, provider usage metadata, and one accounting action per call.

The optional live comparison records only fixture ID, locale, tool, provider/model, token counts, latency, and citation count. It never logs document text, questions, prompts, answers, or credentials.

Groq passes the Evaluation Gate only after the live comparison succeeds with approved pricing and a reviewed result demonstrates acceptable Arabic and English accuracy, structured extraction, citation grounding, prompt-injection resistance, latency, rate-limit behavior, and commercial terms. Automated contract tests alone do not pass the gate.
