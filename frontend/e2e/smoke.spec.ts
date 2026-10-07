import { test, expect } from '@playwright/test';

test.describe('SOC Triage Frontend Smoke Test', () => {
  test('should load the dashboard and verify metrics', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1, name: 'Command Center' })).toBeVisible();
    await expect(page.getByText('API ONLINE').first()).toBeVisible({ timeout: 10000 });
    
    // Screenshot
    await page.screenshot({ path: `e2e/screenshots/dashboard-${page.viewportSize()?.width}.png`, fullPage: true });
  });

  test('should filter incidents and navigate to details', async ({ page }) => {
    await page.goto('/incidents');
    await expect(page.getByRole('heading', { level: 1, name: 'Incident Queue' })).toBeVisible();
    
    // Wait for the queue to load
    await expect(page.getByText('API ONLINE').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('a').filter({ hasText: 'INC-' }).first()).toBeVisible({ timeout: 10000 });

    // Click the first incident
    const firstIncident = page.locator('a').filter({ hasText: 'INC-' }).first();
    const incidentIdText = await firstIncident.innerText();
    const incidentId = incidentIdText.match(/(INC-\d+)/)?.[1];
    
    await firstIncident.click();
    
    // Verify detail page
    if (incidentId) {
      await expect(page.getByRole('heading', { level: 1 })).toContainText(incidentId);
    }
    
    await expect(page.getByRole('button', { name: '✓ CONFIRM' })).toBeVisible();

    // Screenshot
    await page.screenshot({ path: `e2e/screenshots/incident-detail-${page.viewportSize()?.width}.png`, fullPage: true });
  });

  test('should load metrics page', async ({ page }) => {
    await page.goto('/metrics');
    await expect(page.getByRole('heading', { name: 'System Metrics' })).toBeVisible();
    await expect(page.getByText('API ONLINE').first()).toBeVisible({ timeout: 10000 });
    
    // Screenshot
    await page.screenshot({ path: `e2e/screenshots/metrics-${page.viewportSize()?.width}.png`, fullPage: true });
  });
  
  test('should load triage page', async ({ page }) => {
    await page.goto('/triage');
    await expect(page.getByRole('heading', { name: 'Triage Execution Control' })).toBeVisible();
    await expect(page.getByText('API ONLINE').first()).toBeVisible({ timeout: 10000 });
    
    // Screenshot
    await page.screenshot({ path: `e2e/screenshots/triage-${page.viewportSize()?.width}.png`, fullPage: true });
  });
});
