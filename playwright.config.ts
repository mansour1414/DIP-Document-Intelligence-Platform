import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./test/browser",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line",
  use: { baseURL: "http://127.0.0.1:3000", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: { command: "node scripts/start-browser-e2e.mjs", url: "http://127.0.0.1:3000/api/health", reuseExistingServer: !process.env.CI, timeout: 120_000, env: { ...process.env, HOSTNAME: "127.0.0.1", PORT: "3000", NEXT_PUBLIC_APP_URL: "http://127.0.0.1:3000" } },
  projects: [
    { name: "chromium-desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "chromium-mobile", use: { ...devices["Pixel 7"] } },
    { name: "chromium-tablet", use: { ...devices["iPad (gen 7)"], browserName: "chromium" } },
  ],
});
