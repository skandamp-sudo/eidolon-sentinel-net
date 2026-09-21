const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  try {
    await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
    await page.waitForTimeout(2000); // Wait for data to load
    await page.screenshot({ path: 'real_soc.png' });
    console.log("Screenshot saved to real_soc.png");
  } catch (e) {
    console.error("Error taking screenshot:", e);
  } finally {
    await browser.close();
  }
})();
