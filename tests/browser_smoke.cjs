// Optional development test: npm install playwright; npx playwright install chromium
// node tests/browser_smoke.cjs http://localhost:8080 ./kvm.token
const {chromium} = require('playwright');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.argv[2] || 'http://localhost:8080');
    await page.locator('input[name=token]').fill(fs.readFileSync(process.argv[3] || 'kvm.token', 'utf8').trim());
    await page.locator('button').click();
    await page.waitForFunction(() => document.querySelector('#screen')?.naturalWidth > 0);
    await page.locator('#focus').click();
    await page.keyboard.press('a');
    await page.locator('#screen').click({position:{x:100,y:100}});
    await page.locator('#cad').click();
    await page.locator('#release').click();
    const status = await page.evaluate(async () => (await fetch('/api/status')).json());
    if (status.video_error || errors.length) throw Error(JSON.stringify({status,errors}));
    console.log('Browser login, video and input controls passed', status.demo ? '(demo)' : '(hardware)');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
