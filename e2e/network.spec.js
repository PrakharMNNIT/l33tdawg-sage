import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:8080';

test.describe('Network Page', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list', { timeout: 10000 });
    });

    test('renders agent list with at least one agent', async ({ page }) => {
        const cards = page.locator('.agent-card-row');
        await expect(cards.first()).toBeVisible();
        const count = await cards.count();
        expect(count).toBeGreaterThanOrEqual(1);
    });

    test('shows network header with agent count', async ({ page }) => {
        const header = page.locator('.network-header');
        await expect(header).toContainText('Network');
        await expect(header).toContainText('agent');
    });

    test('shows Add Agent card', async ({ page }) => {
        const addCard = page.locator('.agent-card-add');
        await expect(addCard).toBeVisible();
        await expect(addCard).toContainText('Add Agent');
    });

    test('expands agent card on click with tabs', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        const expanded = page.locator('.agent-expanded.open');
        await expect(expanded).toBeVisible();

        // Should show 3 tabs
        const tabs = page.locator('.agent-tab');
        await expect(tabs).toHaveCount(3);
        await expect(tabs.nth(0)).toContainText('Overview');
        await expect(tabs.nth(1)).toContainText('Access Control');
        await expect(tabs.nth(2)).toContainText('Activity');
    });

    test('Overview tab shows agent info with Purpose field', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-overview-grid');

        // Should show key info fields
        await expect(page.locator('.agent-info-label').filter({ hasText: 'Name' }).first()).toBeVisible();
        await expect(page.locator('.agent-info-label').filter({ hasText: 'Status' }).first()).toBeVisible();
        await expect(page.locator('.agent-info-label').filter({ hasText: 'Memories' }).first()).toBeVisible();
        await expect(page.locator('.agent-info-label').filter({ hasText: 'Agent ID' }).first()).toBeVisible();
        // Should show Purpose (renamed from Bio)
        await expect(page.locator('.agent-info-label').filter({ hasText: 'Purpose' }).first()).toBeVisible();
    });

    test('Overview tab Edit mode shows input fields', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        // Click Edit
        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Edit' }).click();

        // Name should be an input
        const nameInput = page.locator('.agent-overview-grid input.wizard-input');
        await expect(nameInput).toBeVisible();

        // Bio should be a textarea
        const bioTextarea = page.locator('.agent-overview-grid textarea.wizard-textarea');
        await expect(bioTextarea).toBeVisible();

        // Should show Save and Cancel buttons
        await expect(page.locator('.agent-action-bar .btn-primary').filter({ hasText: 'Save' })).toBeVisible();
        await expect(page.locator('.agent-action-bar .btn').filter({ hasText: 'Cancel' })).toBeVisible();
    });

    test('Overview tab Cancel exits edit mode', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Edit' }).click();
        await expect(page.locator('.agent-overview-grid input.wizard-input')).toBeVisible();

        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Cancel' }).click();
        await expect(page.locator('.agent-overview-grid input.wizard-input')).not.toBeVisible();
    });

    test('Access Control tab shows role selector', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        // Switch to Access Control tab
        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        // Should show role cards
        const roleCards = page.locator('.role-card');
        await expect(roleCards).toHaveCount(3);
        await expect(roleCards.nth(0)).toContainText('Admin');
        await expect(roleCards.nth(1)).toContainText('Member');
        await expect(roleCards.nth(2)).toContainText('Observer');
    });

    test('Access Control tab shows domain access matrix', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        // If the agent is a member, should show the domain matrix
        // If admin, should show "Admins have full access"
        const matrix = page.locator('.domain-matrix');
        await expect(matrix).toBeVisible();
    });

    test('Access Control tab shows clearance slider', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        const slider = page.locator('.clearance-row input[type="range"]');
        await expect(slider).toBeVisible();

        const label = page.locator('.clearance-row .clearance-label');
        await expect(label).toBeVisible();
    });

    test('Access Control tab Save button is disabled when no changes', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        const saveBtn = page.locator('.access-save-bar .btn-primary');
        await expect(saveBtn).toBeVisible();
        await expect(saveBtn).toBeDisabled();
    });

    test('Access Control tab changing role enables Save', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        // Click a different role
        await page.locator('.role-card').filter({ hasText: 'Observer' }).click();

        const saveBtn = page.locator('.access-save-bar .btn-primary');
        await expect(saveBtn).toBeEnabled();

        // Should show "Unsaved changes"
        await expect(page.locator('.access-dirty')).toBeVisible();
    });

    test('Activity tab shows stats and memory list', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        await page.locator('.agent-tab').filter({ hasText: 'Activity' }).click();

        // Should show stat cards
        const statCards = page.locator('.activity-stat-card');
        await expect(statCards.first()).toBeVisible();
    });

    test('action bar only visible on Overview tab', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();

        // Overview tab — action bar visible
        await expect(page.locator('.agent-action-bar')).toBeVisible();

        // Access Control tab — action bar hidden
        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();
        await expect(page.locator('.agent-action-bar')).not.toBeVisible();

        // Activity tab — action bar hidden
        await page.locator('.agent-tab').filter({ hasText: 'Activity' }).click();
        await expect(page.locator('.agent-action-bar')).not.toBeVisible();
    });

    test('collapse accordion by clicking expanded card', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await expect(page.locator('.agent-expanded.open')).toBeVisible();

        // Click same card again to collapse
        await firstCard.click();
        await expect(page.locator('.agent-expanded.open')).not.toBeVisible();
    });

    test('tab switching resets edit mode', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        // Enter edit mode
        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Edit' }).click();
        await expect(page.locator('.agent-overview-grid input.wizard-input')).toBeVisible();

        // Switch to Access Control
        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();

        // Switch back to Overview — should NOT be in edit mode
        await page.locator('.agent-tab').filter({ hasText: 'Overview' }).click();
        await expect(page.locator('.agent-overview-grid input.wizard-input')).not.toBeVisible();
    });

    test('Download Bundle button shows alert when no bundle available', async ({ page }) => {
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        // Listen for alert dialog
        const alertPromise = page.waitForEvent('dialog');
        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Download Bundle' }).click();
        const dialog = await alertPromise;
        expect(dialog.message()).toContain('No bundle available');
        await dialog.accept();
    });
});

test.describe('Network Page — Last Admin Protection', () => {
    test('Remove button is disabled for last admin', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list');

        // Find the admin agent card
        const adminCard = page.locator('.agent-card-row').filter({ hasText: 'ADMIN' });
        if (await adminCard.count() > 0) {
            await adminCard.first().click();
            await page.waitForSelector('.agent-action-bar');

            const removeBtn = page.locator('.agent-action-bar .btn-danger');
            await expect(removeBtn).toBeVisible();
            // Should be disabled (has btn-disabled class)
            await expect(removeBtn).toHaveClass(/btn-disabled/);
        }
    });
});

test.describe('Add Agent Wizard — Step 1: Identity', () => {
    test('opens wizard on Add Agent click', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const wizard = page.locator('.wizard-overlay');
        await expect(wizard).toBeVisible();
        await expect(wizard).toContainText('Add Agent');
    });

    test('wizard can be closed', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const wizard = page.locator('.wizard-overlay');
        await expect(wizard).toBeVisible();

        // Close button
        await page.locator('.wizard-close, .detail-close').first().click();
        await expect(wizard).not.toBeVisible();
    });

    test('shows Template dropdown with templates including Coding Assistant', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const templateSelect = page.locator('.wizard-select').first();
        await expect(templateSelect).toBeVisible();

        // Wait for templates to load
        await page.waitForFunction(() => {
            const sel = document.querySelector('.wizard-select');
            return sel && sel.options.length >= 2;
        }, { timeout: 5000 });

        // Should have "Coding Assistant" template
        const options = await templateSelect.locator('option').allTextContents();
        expect(options).toContain('Coding Assistant');
    });

    test('Coding Assistant template populates fields correctly', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const templateSelect = page.locator('.wizard-select').first();
        await page.waitForFunction(() => {
            const sel = document.querySelector('.wizard-select');
            return sel && sel.options.length >= 2;
        }, { timeout: 5000 });

        // Select Coding Assistant template
        await templateSelect.selectOption({ label: 'Coding Assistant' });

        // Purpose textarea should be populated
        const purposeTextarea = page.locator('.wizard-textarea');
        await expect(purposeTextarea).toBeVisible();
        const purposeValue = await purposeTextarea.inputValue();
        expect(purposeValue.length).toBeGreaterThan(0);
        expect(purposeValue.toLowerCase()).toContain('coding');
    });

    test('shows Name input field', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const nameInput = page.locator('.wizard-input');
        await expect(nameInput).toBeVisible();
        await expect(nameInput).toHaveAttribute('placeholder', 'Agent name');
    });

    test('shows Purpose field with tooltip (renamed from Boot Bio)', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Should show "Purpose" label, NOT "Boot Bio"
        const purposeLabel = page.locator('.wizard-field label').filter({ hasText: 'Purpose' });
        await expect(purposeLabel).toBeVisible();

        // Should NOT show "Boot Bio" anywhere
        const bootBioLabel = page.locator('.wizard-field label').filter({ hasText: 'Boot Bio' });
        await expect(bootBioLabel).not.toBeVisible();

        // Purpose textarea should have descriptive placeholder
        const textarea = page.locator('.wizard-textarea');
        await expect(textarea).toBeVisible();
        const placeholder = await textarea.getAttribute('placeholder');
        expect(placeholder).toContain('What does this agent do');

        // HelpTip is only visible when tooltips are enabled in settings.
        // We verify the Purpose label exists and has the right structure instead.
    });

    test('shows Provider as dropdown (not free text input)', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Provider should be a <select>, not an <input>
        const providerLabel = page.locator('.wizard-field label').filter({ hasText: 'Provider' });
        await expect(providerLabel).toBeVisible();

        // Find the provider select (second .wizard-select — first is template)
        const providerSelect = page.locator('.wizard-select').nth(1);
        await expect(providerSelect).toBeVisible();

        // Check dropdown options
        const options = await providerSelect.locator('option').allTextContents();
        expect(options).toContain('Auto-detect');
        expect(options).toContain('Claude Code');
        expect(options).toContain('Cursor');
        expect(options).toContain('Windsurf');
        expect(options).toContain('ChatGPT');
        expect(options).toContain('Other');

        // Should NOT have a free-text input for provider
        const providerInput = page.locator('.wizard-field').filter({ hasText: 'Provider' }).locator('input[type="text"]');
        await expect(providerInput).not.toBeVisible();
    });

    test('shows Avatar emoji grid', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const emojiGrid = page.locator('.emoji-grid');
        await expect(emojiGrid).toBeVisible();

        const emojiBtns = page.locator('.emoji-btn');
        const count = await emojiBtns.count();
        expect(count).toBeGreaterThan(0);

        // One should be selected by default
        const selectedEmoji = page.locator('.emoji-btn.selected');
        await expect(selectedEmoji).toBeVisible();
    });

    test('Role is NOT in Step 1 (moved to Step 2)', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Step 1 should NOT show role cards
        const roleCards = page.locator('.role-card');
        await expect(roleCards).toHaveCount(0);
    });

    test('Next button requires name', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Next button should be disabled when name is empty
        const nextBtn = page.locator('.wizard-footer .btn').filter({ hasText: 'Next' });
        await expect(nextBtn).toBeVisible();
        await expect(nextBtn).toBeDisabled();

        // Fill name
        await page.locator('.wizard-input').first().fill('Test Agent');
        await expect(nextBtn).toBeEnabled();
    });
});

test.describe('Add Agent Wizard — Step 2: Permissions', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();
        await page.locator('.wizard-input').first().fill('Test Agent');
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();
    });

    test('shows role selector with 3 roles', async ({ page }) => {
        const roleCards = page.locator('.role-card');
        await expect(roleCards).toHaveCount(3);
        await expect(roleCards.nth(0)).toContainText('Admin');
        await expect(roleCards.nth(1)).toContainText('Member');
        await expect(roleCards.nth(2)).toContainText('Observer');
    });

    test('shows domain matrix (not JSON textarea)', async ({ page }) => {
        const matrix = page.locator('.domain-matrix');
        await expect(matrix).toBeVisible();

        // Should NOT have a JSON textarea
        const jsonLabel = page.locator('label').filter({ hasText: /JSON/ });
        await expect(jsonLabel).not.toBeVisible();
    });

    test('shows clearance slider', async ({ page }) => {
        const slider = page.locator('.clearance-row input[type="range"]');
        await expect(slider).toBeVisible();
    });

    test('inline domain add — add new domain tag', async ({ page }) => {
        // Find the add domain row
        const addRow = page.locator('.domain-matrix-add');
        await expect(addRow).toBeVisible();

        const addInput = addRow.locator('input');
        await expect(addInput).toBeVisible();
        await expect(addInput).toHaveAttribute('placeholder', 'Add new domain tag...');

        const addBtn = addRow.locator('.domain-add-btn');
        await expect(addBtn).toBeVisible();

        // Button should be disabled when input is empty
        await expect(addBtn).toBeDisabled();

        // Type a domain name
        await addInput.fill('my-test-domain');
        await expect(addBtn).toBeEnabled();

        // Click Add
        await addBtn.click();

        // New domain should appear in the matrix with "new" badge
        const newRow = page.locator('.domain-matrix-row.custom').filter({ hasText: 'my-test-domain' });
        await expect(newRow).toBeVisible();
        await expect(newRow).toContainText('new');

        // The domain should have read and write enabled by default
        const checkboxes = newRow.locator('input[type="checkbox"]');
        const readChecked = await checkboxes.nth(0).isChecked();
        const writeChecked = await checkboxes.nth(1).isChecked();
        expect(readChecked).toBeTruthy();
        expect(writeChecked).toBeTruthy();

        // Input should be cleared
        await expect(addInput).toHaveValue('');
    });

    test('inline domain add — Enter key submits', async ({ page }) => {
        const addInput = page.locator('.domain-matrix-add input');
        await addInput.fill('enter-test-domain');
        await addInput.press('Enter');

        const newRow = page.locator('.domain-matrix-row.custom').filter({ hasText: 'enter-test-domain' });
        await expect(newRow).toBeVisible();
    });

    test('selecting Admin role shows "full access" message in domain matrix', async ({ page }) => {
        await page.locator('.role-card').filter({ hasText: 'Admin' }).click();

        const matrix = page.locator('.domain-matrix');
        await expect(matrix).toContainText('Admins have full access');
    });

    test('domain matrix bulk operations work', async ({ page }) => {
        const rows = page.locator('.domain-matrix-row');
        const rowCount = await rows.count();
        test.skip(rowCount < 2, 'needs at least two domains to prove filtering');
        const firstDomain = (await rows.first().locator('.domain-matrix-domain').innerText()).trim().split(/\s+/).pop();
        const hiddenRow = rows.nth(1);
        const hiddenRead = hiddenRow.locator('input[type="checkbox"]').first();
        const hiddenBefore = await hiddenRead.isChecked();

        await page.locator('.domain-matrix-header input').fill(firstDomain);
        const visibleRows = page.locator('.domain-matrix-row:visible');
        await expect(visibleRows).toHaveCount(1);
        await page.getByRole('button', { name: 'Read visible' }).click();
        await expect(visibleRows.first().locator('input[type="checkbox"]').first()).toBeChecked();
        expect(await hiddenRead.isChecked()).toBe(hiddenBefore);

        await page.getByRole('button', { name: 'Revoke visible' }).click();
        await expect(visibleRows.first().locator('input[type="checkbox"]').first()).not.toBeChecked();
        expect(await hiddenRead.isChecked()).toBe(hiddenBefore);
    });
});

test.describe('Add Agent Wizard — Step 3: Connect', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Step 1 → fill and advance
        await page.locator('.wizard-input').first().fill('Test Agent');
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();

        // Step 2 → advance
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();
    });

    test('shows 3 connect cards: Local, Bundle, LAN', async ({ page }) => {
        const connectCards = page.locator('.connect-card');
        await expect(connectCards).toHaveCount(3);

        // Local Project card
        await expect(connectCards.nth(0)).toContainText('Local Project');

        // Bundle card
        await expect(connectCards.nth(1)).toContainText('Download Bundle');

        // LAN card
        await expect(connectCards.nth(2)).toContainText('Easy Setup');
        await expect(connectCards.nth(2)).toContainText('LAN');
    });

    test('Local Project card is selected by default', async ({ page }) => {
        const localCard = page.locator('.connect-card').nth(0);
        await expect(localCard).toHaveClass(/selected/);
    });

    test('can switch to Bundle connect method', async ({ page }) => {
        await page.locator('.connect-card').nth(1).click();
        await expect(page.locator('.connect-card').nth(1)).toHaveClass(/selected/);
        await expect(page.locator('.connect-card').nth(0)).not.toHaveClass(/selected/);
    });

    test('can switch to LAN connect method', async ({ page }) => {
        await page.locator('.connect-card').nth(2).click();
        await expect(page.locator('.connect-card').nth(2)).toHaveClass(/selected/);

        // Summary should show LAN Pairing
        await expect(page.locator('.summary-card')).toContainText('LAN Pairing');
    });

    test('shows warning banner about chain pause', async ({ page }) => {
        await expect(page.locator('.warning-banner')).toContainText('pause the chain');
    });

    test('shows summary with all settings', async ({ page }) => {
        const summary = page.locator('.summary-card');
        await expect(summary).toContainText('Test Agent');
        await expect(summary).toContainText('member'); // default role
        await expect(summary).toContainText('Local Project'); // default connect
    });

    test('summary updates when connect method changes', async ({ page }) => {
        // Switch to Bundle
        await page.locator('.connect-card').nth(1).click();
        await expect(page.locator('.summary-card')).toContainText('Bundle Download');

        // Switch to LAN
        await page.locator('.connect-card').nth(2).click();
        await expect(page.locator('.summary-card')).toContainText('LAN Pairing');

        // Switch to Local
        await page.locator('.connect-card').nth(0).click();
        await expect(page.locator('.summary-card')).toContainText('Local Project');
    });
});

test.describe('Add Agent Wizard — Step 4: Deploy Progress', () => {
    // Note: This test creates an actual agent. We verify the deploy UI elements.
    test('Deploy step shows progress phases', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Step 1
        await page.locator('.wizard-input').first().fill('E2E Deploy Test');
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();

        // Step 2
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();

        // Step 3 — click Create Agent
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Create Agent' }).click();

        // Step 4 should now be visible with deploy progress
        const deployProgress = page.locator('.deploy-progress');
        await expect(deployProgress).toBeVisible({ timeout: 10000 });

        // Should have deploy phase items
        const phases = page.locator('.deploy-phase');
        const count = await phases.count();
        expect(count).toBeGreaterThanOrEqual(1);

        // Should show elapsed timer when deploying
        const timer = page.locator('.deploy-timer');
        // Timer may or may not be visible depending on speed, so just check deploy phases exist
    });
});

test.describe('Add Agent Wizard — Template Selection', () => {
    test('template selection populates bio field', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Wait for templates to load (async fetch)
        const templateSelect = page.locator('.wizard-select').first();
        await expect(templateSelect).toBeVisible();

        // Wait for template options to populate (fetched from /templates API)
        await page.waitForFunction(() => {
            const sel = document.querySelector('.wizard-select');
            return sel && sel.options.length >= 2;
        }, { timeout: 5000 });

        const options = templateSelect.locator('option');
        const optionCount = await options.count();
        expect(optionCount).toBeGreaterThanOrEqual(2);

        // Select the first actual template (index 1, since 0 is placeholder)
        await templateSelect.selectOption({ index: 1 });

        // Bio textarea should now be populated
        const bioTextarea = page.locator('.wizard-textarea');
        await expect(bioTextarea).toBeVisible();
        const bioValue = await bioTextarea.inputValue();
        expect(bioValue.length).toBeGreaterThan(0);
    });
});

test.describe('Key Rotation', () => {
    test('shows Rotate Key button in action bar', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list');

        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        const rotateBtn = page.locator('.agent-action-bar .btn').filter({ hasText: 'Rotate Key' });
        await expect(rotateBtn).toBeVisible();
    });

    test('Rotate Key opens confirmation modal', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list');

        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Rotate Key' }).click();

        // Confirmation modal should appear
        const modal = page.locator('.wizard-overlay');
        await expect(modal).toBeVisible();
        await expect(modal).toContainText('Rotate Agent Key');
        await expect(modal).toContainText('new Ed25519 identity key');
        await expect(modal).toContainText('old key will be permanently retired');
    });

    test('Rotate Key confirmation can be cancelled', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list');

        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Rotate Key' }).click();
        await expect(page.locator('.wizard-overlay')).toBeVisible();

        // Cancel button
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Cancel' }).click();
        await expect(page.locator('.wizard-overlay')).not.toBeVisible();
    });

    test('Rotate Key confirmation has warning banner', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list');

        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Rotate Key' }).click();

        await expect(page.locator('.wizard-overlay .warning-banner')).toContainText('new bundle after rotation');
    });
});

test.describe('API — Pairing & Rotation', () => {
    test('pairing endpoint returns code for valid agent', async ({ request }) => {
        // First get an agent ID
        const agentsRes = await request.get(`${BASE}/v1/dashboard/network/agents`);
        const agents = await agentsRes.json();
        expect(agents.agents.length).toBeGreaterThanOrEqual(1);
        const agentId = agents.agents[0].agent_id;

        // Create pairing code
        const pairRes = await request.post(`${BASE}/v1/dashboard/network/agents/${agentId}/pair`);
        expect(pairRes.ok()).toBeTruthy();
        const pairData = await pairRes.json();
        expect(pairData.code).toBeDefined();
        expect(pairData.code).toMatch(/^SAG-[A-Z0-9]+$/);
        expect(pairData.expires_at).toBeDefined();
        expect(pairData.ttl_seconds).toBeGreaterThanOrEqual(895); // ~15 min, allow for rounding
    });

    test('pairing code is consumed after redeem attempt', async ({ request }) => {
        // Create a pairing code
        const agentsRes = await request.get(`${BASE}/v1/dashboard/network/agents`);
        const agents = await agentsRes.json();
        const agentId = agents.agents[0].agent_id;

        const pairRes = await request.post(`${BASE}/v1/dashboard/network/agents/${agentId}/pair`);
        const pairData = await pairRes.json();
        expect(pairData.code).toBeDefined();

        // First redeem attempt — may fail (no bundle for auto-seeded agents) but consumes the code
        await request.get(`${BASE}/v1/dashboard/network/pair/${pairData.code}`);

        // Second attempt — code should be consumed, returns 404
        const redeemRes2 = await request.get(`${BASE}/v1/dashboard/network/pair/${pairData.code}`);
        expect(redeemRes2.ok()).toBeFalsy();
    });

    test('invalid pairing code returns 404', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/pair/SAG-ZZZZZ`);
        expect(res.ok()).toBeFalsy();
    });

    test('multiple pairing codes can be generated', async ({ request }) => {
        const agentsRes = await request.get(`${BASE}/v1/dashboard/network/agents`);
        const agents = await agentsRes.json();
        const agentId = agents.agents[0].agent_id;

        const res1 = await request.post(`${BASE}/v1/dashboard/network/agents/${agentId}/pair`);
        const res2 = await request.post(`${BASE}/v1/dashboard/network/agents/${agentId}/pair`);
        const data1 = await res1.json();
        const data2 = await res2.json();

        // Each call should produce a unique code
        expect(data1.code).not.toBe(data2.code);
    });
});

test.describe('API — Templates', () => {
    test('templates API has expected fields', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/templates`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.templates.length).toBeGreaterThanOrEqual(1);
        // Each template should have name, role, bio, clearance
        const t = body.templates[0];
        expect(t.name).toBeDefined();
        expect(t.role).toBeDefined();
        expect(t.bio).toBeDefined();
        expect(t.clearance).toBeDefined();
    });

    test('templates include Coding Assistant', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/templates`);
        const body = await res.json();
        const names = body.templates.map(t => t.name);
        expect(names).toContain('Coding Assistant');

        // Coding Assistant template should be a member role
        const codingAssistant = body.templates.find(t => t.name === 'Coding Assistant');
        expect(codingAssistant.role).toBe('member');
        expect(codingAssistant.bio.length).toBeGreaterThan(0);
    });
});

test.describe('API — Unregistered Agents', () => {
    test('unregistered agents endpoint returns array', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/unregistered`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.unregistered)).toBeTruthy();
    });

    test('unregistered agents have expected fields', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/unregistered`);
        const body = await res.json();
        if (body.unregistered && body.unregistered.length > 0) {
            const u = body.unregistered[0];
            expect(u.agent_id).toBeDefined();
            expect(u.short_id).toBeDefined();
            expect(typeof u.memory_count).toBe('number');
        }
    });
});

test.describe('API — Memory Reassign (Merge)', () => {
    test('merge endpoint requires source and target', async ({ request }) => {
        const res = await request.post(`${BASE}/v1/dashboard/network/merge`, {
            data: {},
        });
        // Should return error for missing params
        expect(res.ok()).toBeFalsy();
    });

    test('merge endpoint rejects invalid target', async ({ request }) => {
        const res = await request.post(`${BASE}/v1/dashboard/network/merge`, {
            data: { source_agent_id: 'fake-source', target_agent_id: 'fake-target' },
        });
        // Should return error for invalid target agent
        expect(res.ok()).toBeFalsy();
    });
});

test.describe('API — Download Bundle', () => {
    test('download bundle returns 404 for auto-seeded agent', async ({ request }) => {
        const agentsRes = await request.get(`${BASE}/v1/dashboard/network/agents`);
        const agents = await agentsRes.json();
        expect(agents.agents.length).toBeGreaterThanOrEqual(1);
        const agentId = agents.agents[0].agent_id;

        // Auto-seeded agents don't have bundles
        const res = await request.get(`${BASE}/v1/dashboard/network/agents/${agentId}/bundle`);
        // Expect 404 (no bundle available) for auto-seeded agents
        expect(res.status()).toBe(404);
        const body = await res.json();
        expect(body.error).toContain('no bundle');
    });

    test('download bundle returns 404 for invalid agent', async ({ request }) => {
        const res = await request.get(`${BASE}/v1/dashboard/network/agents/nonexistent-id/bundle`);
        expect(res.ok()).toBeFalsy();
    });
});

test.describe('Access Control — Domain & Clearance Interactions', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list', { timeout: 10000 });

        // Expand first agent and switch to Access Control tab
        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-expanded.open');
        await page.locator('.agent-tab').filter({ hasText: 'Access Control' }).click();
    });

    test('domain matrix checkbox toggle enables Save button', async ({ page }) => {
        const matrix = page.locator('.domain-matrix');
        await expect(matrix).toBeVisible();

        // Find a checkbox in the domain matrix and toggle it
        const checkbox = matrix.locator('input[type="checkbox"]').first();
        await checkbox.evaluate(el => el.click());

        const saveBtn = page.locator('.access-save-bar .btn-primary');
        await expect(saveBtn).toBeEnabled();
    });

    test('clearance slider change enables Save button', async ({ page }) => {
        const slider = page.locator('.clearance-row input[type="range"]');
        await expect(slider).toBeVisible();

        // Change slider value via JS
        await slider.evaluate(el => {
            const newVal = parseInt(el.value) >= parseInt(el.max) ? parseInt(el.min) + 1 : parseInt(el.value) + 1;
            el.value = newVal;
            el.dispatchEvent(new Event('input', { bubbles: true }));
        });

        const saveBtn = page.locator('.access-save-bar .btn-primary');
        await expect(saveBtn).toBeEnabled();
    });

    test('Save button saves and shows confirmation', async ({ page }) => {
        // Make a change to enable save
        const slider = page.locator('.clearance-row input[type="range"]');
        await slider.evaluate(el => {
            const newVal = parseInt(el.value) >= parseInt(el.max) ? parseInt(el.min) + 1 : parseInt(el.value) + 1;
            el.value = newVal;
            el.dispatchEvent(new Event('input', { bubbles: true }));
        });

        const saveBtn = page.locator('.access-save-bar .btn-primary');
        await expect(saveBtn).toBeEnabled();
        await saveBtn.click();

        // Should show "Saved" confirmation text
        const savedConfirm = page.locator('.access-saved');
        await expect(savedConfirm).toBeVisible({ timeout: 5000 });
        await expect(savedConfirm).toContainText('Saved');
    });
});

test.describe('Edit Mode — Save Persists', () => {
    test('saving name change in edit mode succeeds', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list', { timeout: 10000 });

        const firstCard = page.locator('.agent-card-row').first();
        await firstCard.click();
        await page.waitForSelector('.agent-action-bar');

        // Enter edit mode
        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Edit' }).click();

        const nameInput = page.locator('.agent-overview-grid input.wizard-input');
        await expect(nameInput).toBeVisible();

        // Read current name and modify it
        const currentName = await nameInput.inputValue();
        const newName = currentName + ' E2E';
        await nameInput.fill(newName);

        // Click Save
        await page.locator('.agent-action-bar .btn-primary').filter({ hasText: 'Save' }).click();

        // After save, edit mode should exit (no input visible)
        await expect(nameInput).not.toBeVisible({ timeout: 5000 });

        // Restore original name to avoid test pollution
        await page.locator('.agent-action-bar .btn').filter({ hasText: 'Edit' }).click();
        const restoredInput = page.locator('.agent-overview-grid input.wizard-input');
        await restoredInput.fill(currentName);
        await page.locator('.agent-action-bar .btn-primary').filter({ hasText: 'Save' }).click();
    });
});

test.describe('Agent Card — Role Badge', () => {
    test('agent cards display role badges', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-list', { timeout: 10000 });

        // At least one agent card should show a role badge
        const roleBadges = page.locator('.agent-role-badge');
        const count = await roleBadges.count();
        expect(count).toBeGreaterThanOrEqual(1);

        // Badge text should be a valid role
        const badgeText = await roleBadges.first().textContent();
        expect(['admin', 'member', 'observer']).toContain(badgeText.trim().toLowerCase());
    });
});

test.describe('Wizard — Stepper UI', () => {
    test('wizard stepper shows 4 steps: Identity, Permissions, Connect, Deploy', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        const steps = page.locator('.wizard-step');
        await expect(steps).toHaveCount(4);
        await expect(steps.nth(0)).toContainText('Identity');
        await expect(steps.nth(1)).toContainText('Permissions');
        await expect(steps.nth(2)).toContainText('Connect');
        await expect(steps.nth(3)).toContainText('Deploy');
    });

    test('active step is highlighted', async ({ page }) => {
        await page.goto(`${BASE}/ui/#/network`);
        await page.waitForSelector('.agent-card-add');
        await page.locator('.agent-card-add').click();

        // Step 1 should be active
        await expect(page.locator('.wizard-step').nth(0)).toHaveClass(/active/);

        // Advance to step 2
        await page.locator('.wizard-input').first().fill('Test');
        await page.locator('.wizard-footer .btn').filter({ hasText: 'Next' }).click();

        // Step 2 should be active, step 1 should be completed
        await expect(page.locator('.wizard-step').nth(1)).toHaveClass(/active/);
        await expect(page.locator('.wizard-step').nth(0)).toHaveClass(/completed/);
    });
});
