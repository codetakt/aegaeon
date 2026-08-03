import { defineConfig } from "@playwright/test";

const executablePath =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ??
  process.env.CHROME_BIN ??
  undefined;

export default defineConfig({
  testDir: "./browser",
  outputDir: "../test-results/playwright",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "../playwright-report" }],
    ["json", { outputFile: "../test-results/playwright-report.json" }],
  ],
  use: {
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    launchOptions: executablePath
      ? {
          executablePath,
        }
      : undefined,
  },
});
