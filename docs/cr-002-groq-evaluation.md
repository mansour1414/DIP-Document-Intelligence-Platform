# CR-002 Groq GPT-OSS Evaluation

## Decision

At the time of CR-002, Gemini was DIP's initial and only production-routed AI provider. CR-002 authorized evaluation and testing of Groq `openai/gpt-oss-120b`; CR-003 subsequently approved Groq production routing after the live gate passed. CR-002 itself did not authorize fallback.

## Evaluation boundary

The evaluation covers Summarize PDF, Chat with PDF, and Extract Data in Arabic and English. All calls retain the existing Task → Policy → Routing → Provider Adapter → Response Validation → Usage Accounting sequence, document-scoped prompts, structured output validation, citation page checks, token limits, credit boundary, safe diagnostics, and the existing five-attempt queue policy.

The CR-002 evaluation path remains isolated behind `routeAiEvaluationTask`/`executeAiEvaluationGateway` and `GROQ_EVALUATION_ENABLED=1`. Production routing is governed separately by CR-003, and Groq is not an automatic fallback.

## Pricing and accounting

CR-002 approves Groq's published `openai/gpt-oss-120b` price of $0.15 input and $0.60 output per million tokens, effective 2026-09-21. The pricing source is `https://console.groq.com/docs/model/openai/gpt-oss-120b`. This schedule lives in the centralized usage-accounting configuration, not business logic. `GROQ_INPUT_USD_PER_MILLION` and `GROQ_OUTPUT_USD_PER_MILLION` remain optional paired contract overrides; a partial override fails closed. Actual prompt and completion token counts returned by Groq flow through the existing accounting contract.

## Evaluation corpus and acceptance gate

The checked-in synthetic corpus contains parallel English and Arabic contract facts and exercises all three document AI tools. Automated checks cover structured JSON, grounding citations within page scope, bilingual task construction, safe transient/permanent error classification, secret/content redaction, provider usage metadata, and one accounting action per call. Each locale now also has a reference answer (contract amount and payment deadline), expected extraction fields (entity, date, amount, contact), an in-document instruction attack, and an out-of-scope question about another customer's document. The live run has eight Groq cases: three factual tasks plus one out-of-scope Chat case per locale.

The optional live comparison evaluates each provider/task/locale independently. A Gemini availability or rate-limit failure is recorded but cannot prevent Groq calls or make Groq pass. Each safe case record includes success/failure, stable error classification, latency, actual token counts when available, structured-output validity, citation page validity, quote-to-source grounding validity, reference-fact accuracy, Arabic-script presence, out-of-scope response behavior, injection-marker resistance, and structured extraction field correctness. A comparison summary is printed after all cases. It never logs document text, questions, prompts, answers, credentials, or raw provider errors. Deterministic checks cover only the reference facts and attacks in this small corpus; they cannot prove general factual accuracy, fluent Arabic, absence of subtler hallucinations, or resistance to unseen prompt injections.

The CI live step requires `GROQ_API_KEY`; it compares Gemini when `GEMINI_API_KEY` is available, but Gemini is not a prerequisite for Groq evaluation. The automated Groq gate fails if any Groq case fails validation, citation/grounding checks, usage accounting, or provider availability. Human review remains required for the full Evaluation Gate.

Groq passed the expanded live Evaluation Gate before CR-003 approval. Automated contract tests alone do not establish ongoing model quality; retain the bilingual live corpus and access-controlled human review for material model or prompt changes, without printing answers or prompts into CI logs.
