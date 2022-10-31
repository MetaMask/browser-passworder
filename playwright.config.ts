import { PlaywrightTestConfig, devices } from '@playwright/test';

const FIVE_SECONDS_IN_MILLISECONDS = 5 * 1000;

const config: PlaywrightTestConfig = {
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
  ],
  testDir: './test',
  use: {
    actionTimeout: FIVE_SECONDS_IN_MILLISECONDS,
    headless: true,
    viewport: { width: 1280, height: 720 },
  },
};
export default config;
