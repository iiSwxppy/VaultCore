// Form detection + injection.
//
// The content script runs in every frame on every page. On load, we look for
// password inputs. If we find any, we ask the background worker for matching
// credentials. We don't auto-fill silently — we attach a small visible badge
// to the username/password fields so the user opts in by clicking it.
//
// Why opt-in? Auto-fill on page load is a known phishing risk: an invisible
// password field on the page can scrape the password without the user
// realizing. Click-to-fill makes the action visible.
//
// SPA gotcha: forms appear after navigation without page reload. We use a
// MutationObserver with debounce.

import type { CredentialMatch, IpcResponse } from './protocol';

const BADGE_CLASS = 'vaultcore-badge-' + Math.random().toString(36).slice(2, 10);
const BADGE_DATA_KEY = 'vaultcore-attached';

let cachedMatches: CredentialMatch[] | null = null;
let lastFetchUrl: string | null = null;

function isVisible(el: HTMLElement): boolean {
  if (!el.isConnected) return false;
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return false;
  const cs = getComputedStyle(el);
  return cs.visibility !== 'hidden' && cs.display !== 'none';
}

function findPasswordFields(root: ParentNode): HTMLInputElement[] {
  const out: HTMLInputElement[] = [];
  for (const el of Array.from(root.querySelectorAll<HTMLInputElement>('input[type=password]'))) {
    if (!isVisible(el)) continue;
    // Skip signup forms — autofill on a "new-password" field would fill the
    // user's existing credentials into the new-password field. Save-on-submit
    // still handles signup (see below).
    const ac = (el.getAttribute('autocomplete') ?? '').toLowerCase();
    if (ac.includes('new-password')) continue;
    out.push(el);
  }
  return out;
}

function findUsernameForPassword(pwd: HTMLInputElement): HTMLInputElement | null {
  // Walk back through previous form inputs; closest text/email field wins.
  const form = pwd.closest('form');
  const scope: ParentNode = form ?? document;
  const candidates = Array.from(scope.querySelectorAll<HTMLInputElement>(
    'input[type=text], input[type=email], input[type=tel], input:not([type])'
  ));
  let best: HTMLInputElement | null = null;
  for (const c of candidates) {
    if (!isVisible(c)) continue;
    if (c.compareDocumentPosition(pwd) & Node.DOCUMENT_POSITION_FOLLOWING) {
      // c precedes pwd in document order — keep the latest one before pwd.
      best = c;
    }
  }
  return best;
}

/// Find a likely TOTP code input on the page. Modern sites mark these with
/// autocomplete="one-time-code" or inputmode="numeric". Older sites just use
/// a plain text input with name/id matching otp|totp|2fa|code.
function findTotpInput(root: ParentNode = document): HTMLInputElement | null {
  // Pass 1: explicit autocomplete (most reliable, MUST not be type=password).
  for (const el of Array.from(root.querySelectorAll<HTMLInputElement>(
    'input[autocomplete~="one-time-code"]'
  ))) {
    if (el.type !== 'password' && isVisible(el)) return el;
  }
  // Pass 2: semantic naming.
  const re = /\b(otp|totp|2fa|mfa|code|verification|verify|token)\b/i;
  for (const el of Array.from(root.querySelectorAll<HTMLInputElement>(
    'input[type=text], input[type=tel], input[type=number], input:not([type])'
  ))) {
    if (!isVisible(el)) continue;
    const haystack = `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute('aria-label') ?? ''}`;
    if (re.test(haystack)) return el;
  }
  return null;
}

/// Detect a 6-cell TOTP input cluster: 6 single-character inputs in close
/// proximity (sibling order or shared parent), typically with maxlength=1.
/// Returns the cells in order, or null if no cluster found.
function findTotpCellCluster(root: ParentNode = document): HTMLInputElement[] | null {
  const candidates = Array.from(root.querySelectorAll<HTMLInputElement>(
    'input[maxlength="1"]'
  )).filter(el => isVisible(el) && (el.type === 'text' || el.type === 'tel' || el.type === 'number' || !el.type));

  if (candidates.length < 6) return null;

  // Group by shared parent. The cluster is the parent with exactly 6 such inputs.
  const byParent = new Map<HTMLElement, HTMLInputElement[]>();
  for (const c of candidates) {
    const p = c.parentElement;
    if (!p) continue;
    if (!byParent.has(p)) byParent.set(p, []);
    byParent.get(p)!.push(c);
  }
  for (const [_, group] of byParent) {
    if (group.length === 6) {
      // Order by document position.
      group.sort((a, b) =>
        (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) ? -1 : 1);
      return group;
    }
  }
  return null;
}

function fillTotpCells(cells: HTMLInputElement[], code: string) {
  for (let i = 0; i < cells.length && i < code.length; i++) {
    setInputValue(cells[i]!, code[i]!);
  }
  // Focus the last cell so any "submit when full" handler triggers.
  cells[cells.length - 1]?.focus();
}

async function fetchMatches(force = false): Promise<CredentialMatch[]> {
  const url = location.href;
  if (!force && cachedMatches !== null && lastFetchUrl === url) return cachedMatches;

  const resp = await chrome.runtime.sendMessage({ kind: 'find_credentials', url }) as IpcResponse;
  lastFetchUrl = url;
  cachedMatches = resp.ok && resp.credentials ? resp.credentials : [];
  return cachedMatches;
}

function setInputValue(input: HTMLInputElement, value: string) {
  // React/Vue/etc. hook into the value setter. We must use the native setter
  // and then dispatch input + change events so the framework picks up the
  // new value.
  const proto = Object.getPrototypeOf(input);
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function fillCredential(usernameEl: HTMLInputElement | null, passwordEl: HTMLInputElement, cred: CredentialMatch) {
  if (usernameEl && cred.username) setInputValue(usernameEl, cred.username);
  if (cred.password) setInputValue(passwordEl, cred.password);
  passwordEl.focus();
}

function ensureStyles() {
  if (document.getElementById('vaultcore-styles')) return;
  const style = document.createElement('style');
  style.id = 'vaultcore-styles';
  style.textContent = `
    .${BADGE_CLASS} {
      position: absolute;
      z-index: 2147483647;
      width: 22px;
      height: 22px;
      border-radius: 4px;
      background: #2D7AF6;
      color: white;
      font: bold 12px/22px system-ui, sans-serif;
      text-align: center;
      cursor: pointer;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
      user-select: none;
    }
    .${BADGE_CLASS}:hover { background: #1E5BBF; }
    .${BADGE_CLASS}-menu {
      position: absolute;
      z-index: 2147483647;
      background: white;
      color: #1A1A1A;
      border: 1px solid #DCDCDC;
      border-radius: 6px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.18);
      min-width: 240px;
      max-height: 300px;
      overflow: auto;
      padding: 4px;
      font: 13px system-ui, sans-serif;
    }
    .${BADGE_CLASS}-item {
      padding: 8px 10px;
      cursor: pointer;
      border-radius: 4px;
    }
    .${BADGE_CLASS}-item:hover { background: #F0F4FF; }
    .${BADGE_CLASS}-title { font-weight: 600; }
    .${BADGE_CLASS}-sub { color: #666; font-size: 11px; }
    .${BADGE_CLASS}-empty {
      padding: 10px;
      color: #888;
    }
  `;
  document.documentElement.appendChild(style);
}

function positionBadge(badge: HTMLElement, target: HTMLInputElement) {
  const rect = target.getBoundingClientRect();
  const top = window.scrollY + rect.top + (rect.height - 22) / 2;
  const left = window.scrollX + rect.right - 22 - 4;
  badge.style.top = `${top}px`;
  badge.style.left = `${left}px`;
}

function attachBadge(passwordEl: HTMLInputElement) {
  if ((passwordEl as any)[BADGE_DATA_KEY]) return;
  (passwordEl as any)[BADGE_DATA_KEY] = true;

  ensureStyles();

  const badge = document.createElement('div');
  badge.className = BADGE_CLASS;
  badge.textContent = 'V';
  badge.title = 'VaultCore: fill credentials';
  document.body.appendChild(badge);
  positionBadge(badge, passwordEl);

  const reposition = () => positionBadge(badge, passwordEl);
  window.addEventListener('scroll', reposition, true);
  window.addEventListener('resize', reposition);

  badge.addEventListener('click', async (e) => {
    e.stopPropagation();
    e.preventDefault();
    const matches = await fetchMatches();
    showMenu(badge, passwordEl, matches);
  });
}

function showMenu(anchor: HTMLElement, passwordEl: HTMLInputElement, matches: CredentialMatch[]) {
  document.querySelectorAll(`.${BADGE_CLASS}-menu`).forEach(n => n.remove());

  const menu = document.createElement('div');
  menu.className = `${BADGE_CLASS}-menu`;
  const ar = anchor.getBoundingClientRect();
  menu.style.top = `${window.scrollY + ar.bottom + 4}px`;
  menu.style.left = `${window.scrollX + ar.right - 240}px`;

  if (matches.length === 0) {
    const empty = document.createElement('div');
    empty.className = `${BADGE_CLASS}-empty`;
    empty.textContent = 'No matching credentials. Open VaultCore to add one.';
    menu.appendChild(empty);
  } else {
    for (const m of matches) {
      const item = document.createElement('div');
      item.className = `${BADGE_CLASS}-item`;
      const title = document.createElement('div');
      title.className = `${BADGE_CLASS}-title`;
      title.textContent = m.title;
      const sub = document.createElement('div');
      sub.className = `${BADGE_CLASS}-sub`;
      sub.textContent = m.username ?? '(no username)';
      item.appendChild(title);
      item.appendChild(sub);
      item.addEventListener('click', () => {
        const usernameEl = findUsernameForPassword(passwordEl);
        fillCredential(usernameEl, passwordEl, m);
        menu.remove();
      });
      menu.appendChild(item);

      // If the credential has TOTP and the page has a TOTP input, offer a
      // direct "Fill TOTP" sub-action. This is shown as a small button row
      // attached to the item so it's discoverable without an extra click.
      if (m.hasTotp && findTotpInput()) {
        const totpRow = document.createElement('div');
        totpRow.style.display = 'flex';
        totpRow.style.padding = '0 10px 8px 10px';
        const totpBtn = document.createElement('button');
        totpBtn.textContent = 'Fill TOTP';
        totpBtn.style.cssText = 'background:#2D7AF6;color:white;border:none;border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;';
        totpBtn.addEventListener('click', async (ev) => {
          ev.stopPropagation();
          const resp = await chrome.runtime.sendMessage({
            kind: 'get_totp', itemId: m.itemId,
          }) as IpcResponse;
          if (resp.ok && resp.totpCode) {
            const target = findTotpInput();
            if (target) {
              setInputValue(target, resp.totpCode);
              target.focus();
            }
          }
          menu.remove();
        });
        totpRow.appendChild(totpBtn);
        menu.appendChild(totpRow);
      }
    }
  }

  document.body.appendChild(menu);

  const close = (e: MouseEvent) => {
    if (!menu.contains(e.target as Node)) {
      menu.remove();
      document.removeEventListener('click', close, true);
    }
  };
  setTimeout(() => document.addEventListener('click', close, true), 0);
}

function scan() {
  for (const pwd of findPasswordFields(document)) {
    attachBadge(pwd);
  }
  // TOTP-only page: single OTP input.
  const totpInput = findTotpInput();
  if (totpInput && !(totpInput as any)[BADGE_DATA_KEY]) {
    attachTotpBadge(totpInput, null);
  }
  // TOTP-only page: 6-cell cluster.
  const cells = findTotpCellCluster();
  if (cells && !(cells[0] as any)[BADGE_DATA_KEY]) {
    attachTotpBadge(cells[0]!, cells);
  }
}

function attachTotpBadge(anchorEl: HTMLInputElement, cells: HTMLInputElement[] | null) {
  if ((anchorEl as any)[BADGE_DATA_KEY]) return;
  (anchorEl as any)[BADGE_DATA_KEY] = true;
  if (cells) for (const c of cells) (c as any)[BADGE_DATA_KEY] = true;

  ensureStyles();

  const badge = document.createElement('div');
  badge.className = BADGE_CLASS;
  badge.textContent = 'V';
  badge.title = 'VaultCore: fill TOTP code';
  badge.style.background = '#1FA365';
  document.body.appendChild(badge);
  positionBadge(badge, anchorEl);

  const reposition = () => positionBadge(badge, anchorEl);
  window.addEventListener('scroll', reposition, true);
  window.addEventListener('resize', reposition);

  const fillInto = async (itemId: string) => {
    const resp = await chrome.runtime.sendMessage({
      kind: 'get_totp', itemId,
    }) as IpcResponse;
    if (resp.ok && resp.totpCode) {
      if (cells) fillTotpCells(cells, resp.totpCode);
      else { setInputValue(anchorEl, resp.totpCode); anchorEl.focus(); }
    }
  };

  badge.addEventListener('click', async (e) => {
    e.stopPropagation();
    e.preventDefault();
    const matches = await fetchMatches();
    const withTotp = matches.filter(m => m.hasTotp);
    if (withTotp.length === 0) {
      showMenu(badge, anchorEl, []);
      return;
    }
    if (withTotp.length === 1) {
      await fillInto(withTotp[0]!.itemId);
      return;
    }
    showTotpMenu(badge, withTotp, fillInto);
  });
}

function showTotpMenu(anchor: HTMLElement, matches: CredentialMatch[], onPick: (id: string) => Promise<void>) {
  document.querySelectorAll(`.${BADGE_CLASS}-menu`).forEach(n => n.remove());
  const menu = document.createElement('div');
  menu.className = `${BADGE_CLASS}-menu`;
  const ar = anchor.getBoundingClientRect();
  menu.style.top = `${window.scrollY + ar.bottom + 4}px`;
  menu.style.left = `${window.scrollX + ar.right - 240}px`;

  for (const m of matches) {
    const item = document.createElement('div');
    item.className = `${BADGE_CLASS}-item`;
    const title = document.createElement('div');
    title.className = `${BADGE_CLASS}-title`;
    title.textContent = m.title;
    const sub = document.createElement('div');
    sub.className = `${BADGE_CLASS}-sub`;
    sub.textContent = m.username ?? '(no username)';
    item.appendChild(title);
    item.appendChild(sub);
    item.addEventListener('click', async () => {
      await onPick(m.itemId);
      menu.remove();
    });
    menu.appendChild(item);
  }
  document.body.appendChild(menu);
  const close = (e: MouseEvent) => {
    if (!menu.contains(e.target as Node)) {
      menu.remove();
      document.removeEventListener('click', close, true);
    }
  };
  setTimeout(() => document.addEventListener('click', close, true), 0);
}

// Re-scan on DOM changes (SPA route changes etc.) with debounce.
let scanTimer: ReturnType<typeof setTimeout> | null = null;
const observer = new MutationObserver(() => {
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(() => {
    scanTimer = null;
    scan();
  }, 250);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
});

// Initial scan.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scan, { once: true });
} else {
  scan();
}

// =========================================================================
// Save-on-submit
// =========================================================================
// On form submit / button click that triggers credential submission, capture
// the username + password values and ask the user whether to save them. We
// only prompt if no existing credential matches — avoids duplicate spam.
//
// Detection: hook all forms with a password input, plus the click on any
// submit button inside such a form. We also listen for "Enter" on inputs
// because many sites use JS to handle login without a real <form>.

function captureFormCreds(scope: HTMLElement): { username: string | null; password: string; isSignup: boolean } | null {
  const pwd = scope.querySelector<HTMLInputElement>('input[type=password]');
  if (!pwd || !pwd.value) return null;
  const username = findUsernameForPassword(pwd)?.value || null;
  const ac = (pwd.getAttribute('autocomplete') ?? '').toLowerCase();
  // Heuristic: if there are TWO password fields in the same scope (password +
  // confirm password), or autocomplete says "new-password", treat as signup.
  const passwordFields = scope.querySelectorAll('input[type=password]').length;
  const isSignup = ac.includes('new-password') || passwordFields >= 2;
  return { password: pwd.value, username, isSignup };
}

async function maybePromptSave(creds: { username: string | null; password: string; isSignup: boolean }) {
  const matches = await fetchMatches(true);
  if (matches.some(m =>
    (m.username ?? '') === (creds.username ?? '') &&
    (m.password ?? '') === creds.password
  )) {
    return;
  }
  showSaveBanner(creds);
}

function showSaveBanner(creds: { username: string | null; password: string; isSignup: boolean }) {
  document.querySelectorAll(`.${BADGE_CLASS}-banner`).forEach(n => n.remove());

  ensureBannerStyles();

  const banner = document.createElement('div');
  banner.className = `${BADGE_CLASS}-banner`;

  const text = document.createElement('div');
  text.style.flex = '1';
  const verb = creds.isSignup ? 'Save new credentials for' : 'Save credentials for';
  text.innerHTML = `${verb} <b>${escapeHtml(location.host)}</b>${
    creds.username ? ` (${escapeHtml(creds.username)})` : ''
  }?`;
  banner.appendChild(text);

  const saveBtn = document.createElement('button');
  saveBtn.textContent = 'Save';
  saveBtn.className = `${BADGE_CLASS}-banner-btn primary`;
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    const resp = await chrome.runtime.sendMessage({
      kind: 'add_credential',
      url: location.href,
      title: location.host,
      username: creds.username ?? undefined,
      password: creds.password,
    }) as IpcResponse;
    if (resp.ok) {
      banner.remove();
      // Invalidate cache so next badge click sees the new credential.
      cachedMatches = null;
    } else {
      saveBtn.disabled = false;
      saveBtn.textContent = `Failed: ${resp.error ?? 'unknown'}`;
    }
  });
  banner.appendChild(saveBtn);

  const dismissBtn = document.createElement('button');
  dismissBtn.textContent = 'Not now';
  dismissBtn.className = `${BADGE_CLASS}-banner-btn`;
  dismissBtn.addEventListener('click', () => banner.remove());
  banner.appendChild(dismissBtn);

  document.body.appendChild(banner);

  // Auto-dismiss after 30s if user ignores.
  setTimeout(() => banner.remove(), 30_000);
}

function ensureBannerStyles() {
  if (document.getElementById('vaultcore-banner-styles')) return;
  const style = document.createElement('style');
  style.id = 'vaultcore-banner-styles';
  style.textContent = `
    .${BADGE_CLASS}-banner {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 2147483647;
      background: #2C2C2C;
      color: #FFFFFF;
      border: 1px solid #444;
      border-radius: 8px;
      padding: 12px 14px;
      font: 13px system-ui, sans-serif;
      box-shadow: 0 6px 24px rgba(0,0,0,0.4);
      display: flex;
      align-items: center;
      gap: 10px;
      max-width: 420px;
    }
    .${BADGE_CLASS}-banner-btn {
      background: #3A3A3A;
      color: #E8E8E8;
      border: 1px solid #555;
      border-radius: 4px;
      padding: 6px 12px;
      font-size: 12px;
      cursor: pointer;
    }
    .${BADGE_CLASS}-banner-btn.primary {
      background: #2D7AF6;
      color: white;
      border-color: #2D7AF6;
    }
    .${BADGE_CLASS}-banner-btn:hover { filter: brightness(1.15); }
    .${BADGE_CLASS}-banner-btn:disabled { opacity: 0.6; cursor: default; }
  `;
  document.documentElement.appendChild(style);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]!));
}

// Hook all forms containing a password field.
document.addEventListener('submit', (e) => {
  const target = e.target as HTMLElement | null;
  if (!target || !(target instanceof HTMLFormElement)) return;
  if (!target.querySelector('input[type=password]')) return;
  const creds = captureFormCreds(target);
  if (creds) {
    // Defer the prompt slightly so we don't interfere with the submission.
    setTimeout(() => maybePromptSave(creds), 200);
  }
}, true);

// SPAs without a real <form>: detect Enter key on a password input, and
// click on a button that's in the same scope as a password input.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const target = e.target as HTMLElement | null;
  if (!(target instanceof HTMLInputElement)) return;
  if (target.type !== 'password' && target.type !== 'text' && target.type !== 'email') return;
  const scope = target.closest('form') as HTMLElement | null
    ?? findScopeWithPassword(target);
  if (!scope) return;
  const creds = captureFormCreds(scope);
  if (creds) setTimeout(() => maybePromptSave(creds), 400);
}, true);

function findScopeWithPassword(el: HTMLElement): HTMLElement | null {
  let cur: HTMLElement | null = el.parentElement;
  let depth = 0;
  while (cur && depth < 6) {
    if (cur.querySelector('input[type=password]')) return cur;
    cur = cur.parentElement;
    depth++;
  }
  return null;
}
