# DIP worker boundary

Workers consume `document-jobs` from Redis and execute only the capabilities
declared by the Tool Registry. They must run separately from the web process
and use an isolated, resource-limited runtime for untrusted documents.

Each execution must persist its idempotency key, engine version, step status,
and terminal result before acknowledging queue work. Phase 1 introduces the
PDF worker implementation; this boundary deliberately contains no document
processing code.
