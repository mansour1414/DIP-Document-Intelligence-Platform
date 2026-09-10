export type AnalyticsEventName = "tool_page_view" | "tool_started" | "tool_completed" | "tool_failed" | "pricing_view" | "upgrade_intent";
export type AnalyticsEvent = { name: AnalyticsEventName; tool_id?: string; language: "en" | "ar"; page_path: string; duration_ms?: number; error_code?: string; source?: "organic" | "internal" | "direct" };
export type AnalyticsProvider = { track(event: AnalyticsEvent): void | Promise<void> };

const noopProvider: AnalyticsProvider = { track: () => undefined };
let provider: AnalyticsProvider = noopProvider;
export function configureAnalytics(next: AnalyticsProvider) { provider = next; }
export function track(event: AnalyticsEvent) { try { void Promise.resolve(provider.track(event)).catch(() => undefined); } catch { /* Analytics never blocks document processing. */ } }

