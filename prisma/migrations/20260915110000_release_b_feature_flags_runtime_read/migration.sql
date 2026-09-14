-- Feature flags are global system configuration read by runtime policy/routing.
-- Keep administration owner-only while allowing the hardened application role
-- to evaluate kill switches and provider/model routing.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON feature_flags FROM dip_app;
GRANT SELECT ON feature_flags TO dip_app;
