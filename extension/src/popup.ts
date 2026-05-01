import type { IpcResponse, CredentialMatch } from './protocol';

const statusEl = document.getElementById('status') as HTMLDivElement;
const resultsEl = document.getElementById('results') as HTMLDivElement;
const refreshBtn = document.getElementById('refresh') as HTMLButtonElement;

function setStatus(text: string, kind: 'ok' | 'warn' | 'err') {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

async function send(message: unknown): Promise<IpcResponse> {
  return await chrome.runtime.sendMessage(message) as IpcResponse;
}

async function getActiveTabUrl(): Promise<string | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? null;
}

async function copyToClipboard(text: string) {
  await navigator.clipboard.writeText(text);
}

function renderMatches(matches: CredentialMatch[], hostLabel: string) {
  resultsEl.innerHTML = '';
  if (matches.length === 0) {
    const div = document.createElement('div');
    div.className = 'empty';
    div.textContent = `No credentials saved for ${hostLabel}.`;
    resultsEl.appendChild(div);
    return;
  }

  for (const m of matches) {
    const item = document.createElement('div');
    item.className = 'item';

    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = m.title;

    const sub = document.createElement('div');
    sub.className = 'item-sub';
    sub.textContent = m.username ?? '(no username)';

    item.appendChild(title);
    item.appendChild(sub);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '4px';
    actions.style.marginTop = '6px';

    if (m.username) {
      const b = document.createElement('button');
      b.className = 'secondary';
      b.textContent = 'Copy user';
      b.style.padding = '4px 8px';
      b.style.fontSize = '11px';
      b.addEventListener('click', async (e) => {
        e.stopPropagation();
        await copyToClipboard(m.username!);
        setStatus('Username copied', 'ok');
      });
      actions.appendChild(b);
    }
    if (m.password) {
      const b = document.createElement('button');
      b.textContent = 'Copy pass';
      b.style.padding = '4px 8px';
      b.style.fontSize = '11px';
      b.addEventListener('click', async (e) => {
        e.stopPropagation();
        await copyToClipboard(m.password!);
        setStatus('Password copied', 'ok');
      });
      actions.appendChild(b);
    }
    if (m.hasTotp) {
      const b = document.createElement('button');
      b.className = 'secondary';
      b.textContent = 'TOTP';
      b.style.padding = '4px 8px';
      b.style.fontSize = '11px';
      b.addEventListener('click', async (e) => {
        e.stopPropagation();
        const resp = await send({ kind: 'get_totp', itemId: m.itemId });
        if (resp.ok && resp.totpCode) {
          await copyToClipboard(resp.totpCode);
          setStatus(`TOTP copied (${resp.totpRemaining}s remaining)`, 'ok');
        } else {
          setStatus(`TOTP failed: ${resp.error ?? 'unknown'}`, 'err');
        }
      });
      actions.appendChild(b);
    }
    item.appendChild(actions);

    resultsEl.appendChild(item);
  }
}

async function refresh() {
  setStatus('Checking...', 'warn');
  resultsEl.innerHTML = '';
  try {
    const status = await send({ kind: 'status' });
    if (!status.ok) {
      setStatus(status.error ?? 'Desktop not reachable.', 'err');
      return;
    }
    if (!status.unlocked) {
      setStatus('Vault is locked. Open the desktop app to unlock.', 'warn');
      return;
    }
    const url = await getActiveTabUrl();
    if (!url) {
      setStatus('No active tab.', 'err');
      return;
    }
    const host = new URL(url).host;
    const resp = await send({ kind: 'find_credentials', url });
    if (!resp.ok) {
      setStatus(resp.error ?? 'Lookup failed.', 'err');
      return;
    }
    setStatus(`Vault unlocked. Site: ${host}`, 'ok');
    renderMatches(resp.credentials ?? [], host);
  } catch (e) {
    setStatus((e as Error).message, 'err');
  }
}

refreshBtn.addEventListener('click', refresh);
refresh();
