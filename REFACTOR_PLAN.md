# VIGILANT Gateway Dashboard — Refactoring Implementation Plan

## Overview

This plan addresses all issues identified in the comprehensive code review. The core decision is to **consolidate on `dashboard.html`** as the primary template (it has the more complete feature set including SNI Monitoring) while fixing its structural issues.

---

## Phase 1: Template Architecture Consolidation (Critical)

### Step 1.1: Split `_settings_form.html` into Dedicated Partials

**Problem:** `_settings_form.html` contains Filtering, Behavioral Control, and Settings tabs — it's misnamed and causes duplicate content when included.

**Action:** Create three new partial files:

1. **`partials/_filtering.html`** — Extract the Filtering tab content from `_settings_form.html`
2. **`partials/_behavioral_control.html`** — Extract the Behavioral Control tab content from `_settings_form.html`  
3. **`partials/_setup.html`** — Extract the Settings/Setup tab content from `_settings_form.html`

**Files to create:** 3 new partials
**Files to delete:** `partials/_settings_form.html` (after extraction)

### Step 1.2: Fix `dashboard.html` — Remove Duplicate Includes

**Problem:** `dashboard.html` includes `_settings_form.html` at the top (which contains Filtering, Behavioral Control, Settings tabs) AND also includes it again inside the Behavioral Control form.

**Action:**
- Remove `{% include 'partials/_settings_form.html' %}` from the top-level content area
- Replace with specific includes: `_filtering.html`, `_behavioral_control.html`, `_setup.html`
- Remove the nested `{% include 'partials/_settings_form.html' %}` inside the Behavioral Control form
- Remove the duplicate inline tab content for Filtering, Behavioral Control, and Settings that currently exists in `dashboard.html` (since these will now come from partials)

### Step 1.3: Fix `index.html` — Add SNI Monitoring & Remove Duplicate Includes

**Problem:** `index.html` is missing the SNI Monitoring tab and has duplicate tab content from the `_settings_form.html` include.

**Action:**
- Add `{% include 'partials/_sni_dashboard.html' %}` to the content area
- Add "SNI Monitoring" nav item to the sidebar
- Remove `{% include 'partials/_settings_form.html' %}` from top-level content
- Replace with specific includes: `_filtering.html`, `_behavioral_control.html`, `_setup.html`
- Remove duplicate inline tab content for Filtering, Behavioral Control, and Settings

---

## Phase 2: CSS Consolidation (Critical)

### Step 2.1: Add Missing CSS Links to `dashboard.html`

**Problem:** `dashboard.html` has ~500 lines of inline `<style>` that duplicates `styles.css`, and it doesn't link to either `styles.css` or `dashboard.css`.

**Action:**
- Add `<link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">` to `<head>`
- Remove the massive inline `<style>` block (all styles are in `styles.css`)
- Do NOT add `dashboard.css` link — it's an orphaned file with a different design system

### Step 2.2: Remove Orphaned `dashboard.css`

**Problem:** `dashboard.css` is never loaded by any template and has a completely different design system (blue primary instead of teal).

**Action:**
- Delete `static/css/dashboard.css` (or archive it)

### Step 2.3: Fix Nerve Center Light Mode

**Problem:** The Nerve Center card has `style="background: var(--primary-dark); color: white;"` which breaks light mode readability.

**Action:**
- Remove inline `color: white` and `background: var(--primary-dark)` from the Nerve Center card
- Use CSS classes instead (`.glassmorphic-card` already has light mode fixes in `styles.css`)
- The theme toggle already exists in `styles.css` with `[data-theme="light"] .glassmorphic-card` overrides

---

## Phase 3: JavaScript Fixes (High Priority)

### Step 3.1: Merge Duplicate DOMContentLoaded Listeners

**Problem:** `dashboard.js` has two `DOMContentLoaded` event listeners — one for general initialization and one for SNI event listeners.

**Action:** Merge both into a single listener.

### Step 3.2: Fix `loadRestraintsRegistry()` References

**Problem:** `switchTab()` calls `loadRestraintsRegistry()` for `tabId === 'restraints'`, but no "restraints" tab exists in any template.

**Action:**
- Remove the `if (tabId === 'restraints')` branch from `switchTab()`
- Keep the `loadRestraintsRegistry()` function definition (it may be useful later) but remove the dead call

### Step 3.3: Fix `loadKeywords()` Call

**Problem:** `switchTab()` calls `loadKeywords()` when switching to the 'filtering' tab, but `dashboard.html`'s inline Filtering tab doesn't have `id="keywords-table-body"`.

**Action:** After Phase 1, the Filtering tab will come from `_filtering.html` partial which DOES have `id="keywords-table-body"`. This will be fixed automatically.

### Step 3.4: Add Missing DOM Element IDs to `dashboard.html`

**Problem:** Several IDs referenced by JS are missing from `dashboard.html`'s inline content.

**Action:** After Phase 1, these will come from the partials. Verify that the following IDs exist in the partials:
- `id="keyword-form"` ✓ (in `_settings_form.html` → will be in `_filtering.html`)
- `id="category-hint-form"` ✓ (in `_settings_form.html`)
- `id="unified-config-form"` ✓ (in `_settings_form.html`)
- `id="advanced-toggle"` ✓ (in `_settings_form.html`)
- `id="advanced-settings"` ✓ (in `_settings_form.html`)
- `id="theme-preference"` ✓ (in `_settings_form.html`)
- `id="traffic-filter-category"` ✓ (in `_traffic_logs.html`)
- `id="block-reason-filter"` ✓ (in `_traffic_logs.html`)
- `id="pagination-controls"` ✓ (in `_traffic_logs.html`)
- `id="sni-log-table"` ✓ (in `_sni_dashboard.html`)
- `id="sni-empty-state"` ✓ (in `_sni_dashboard.html`)
- `id="throttled-tbody"` ✓ (in `_device_management.html`)
- `id="active-tbody"` ✓ (in `_device_management.html`)
- `id="leased-tbody"` ✓ (in `_device_management.html`)
- `id="category-hints-table-body"` ✓ (in `_settings_form.html`)

---

## Phase 4: Standardization & Cleanup (Medium Priority)

### Step 4.1: Standardize Modal Close Buttons

**Problem:** `dashboard.html` uses `✕` while `index.html` uses `&times;` for modal close buttons.

**Action:** Standardize on `&times;` (HTML entity) across all templates.

### Step 4.2: Standardize Button Classes

**Problem:** `dashboard.html` uses `btn-primary`, `btn-secondary`, `btn-danger` while `index.html` uses `btn btn-primary`, `btn btn-secondary`, `btn btn-danger`.

**Action:** Standardize on the `btn-primary`, `btn-secondary`, `btn-danger` format (without `btn` prefix class) since that's what `styles.css` defines.

### Step 4.3: Fix `index.html` Nerve Center Card

**Problem:** `index.html`'s Nerve Center card uses class `nerve-center` but `dashboard.html` uses `glassmorphic-card`. The light mode CSS fixes target `.glassmorphic-card`.

**Action:** Add `glassmorphic-card` class to the Nerve Center card in `index.html`.

---

## Phase 5: JavaScript Refactoring (Low Priority / Nice-to-Have)

### Step 5.1: Remove `window` Object Attachment

**Problem:** All functions are attached to `window` object for global access.

**Action:** Keep as-is for now (it's a pattern that works for inline `onclick` handlers). Document as intentional.

### Step 5.2: Add Error Boundaries to Polling

**Problem:** The 3-second polling interval has no error boundary to prevent cascading failures.

**Action:** Add try/catch around the entire `fetchSummary` function (already partially done — improve it).

### Step 5.3: Optimize Polling Based on Active Tab

**Problem:** All tabs poll at the same 3-second interval regardless of visibility.

**Action:** Reduce polling frequency when the browser tab is not visible using `document.hidden` API.

---

## Execution Order

```
Phase 1 (Template Architecture)
  ├── Step 1.1: Create _filtering.html, _behavioral_control.html, _setup.html
  ├── Step 1.2: Fix dashboard.html (remove duplicate includes, use new partials)
  └── Step 1.3: Fix index.html (add SNI, use new partials)

Phase 2 (CSS Consolidation)
  ├── Step 2.1: Add CSS links to dashboard.html, remove inline <style>
  ├── Step 2.2: Remove orphaned dashboard.css
  └── Step 2.3: Fix Nerve Center light mode

Phase 3 (JavaScript Fixes)
  ├── Step 3.1: Merge DOMContentLoaded listeners
  ├── Step 3.2: Remove dead loadRestraintsRegistry() call
  └── Step 3.3-3.4: Verify DOM IDs (auto-fixed by Phase 1)

Phase 4 (Standardization)
  ├── Step 4.1: Standardize modal close buttons
  ├── Step 4.2: Standardize button classes
  └── Step 4.3: Fix index.html Nerve Center class

Phase 5 (Nice-to-Have)
  ├── Step 5.2: Improve polling error boundaries
  └── Step 5.3: Tab visibility-based polling optimization
```

---

## Files to Create
1. `src/templates/partials/_filtering.html`
2. `src/templates/partials/_behavioral_control.html`
3. `src/templates/partials/_setup.html`

## Files to Modify
1. `src/templates/dashboard.html`
2. `src/templates/index.html`
3. `src/static/js/dashboard.js`

## Files to Delete
1. `src/templates/partials/_settings_form.html`
2. `src/static/css/dashboard.css`

## Files to Keep Unchanged
1. `src/templates/partials/_device_management.html` (no issues)
2. `src/templates/partials/_traffic_logs.html` (no issues)
3. `src/templates/partials/_sni_dashboard.html` (no issues)
4. `src/static/css/styles.css` (no issues — already has all fixes)
5. `src/app.py` (no frontend issues)
