// Background service worker.
// Owns the connection to the native messaging host. Content scripts and the
// popup talk to this worker via chrome.runtime.sendMessage; the worker
// forwards to the native host and returns the response.
//
// MV3 service workers are stoppable: Chrome shuts us down after ~30s of
// inactivity. We open a fresh connectNative() per request — cheap, and avoids
// holding a long-lived port that survives worker termination unpredictably.

import {
  IpcRequest,
  IpcResponse,
  NATIVE_HOST_NAME,
  makeRequestId,
} from './protocol';

interface PendingRequest {
  resolve(resp: IpcResponse): void;
  reject(err: Error): void;
  timer: ReturnType<typeof setTimeout>;
}

const REQUEST_TIMEOUT_MS = 5000;

async function callNative(req: Omit<IpcRequest, 'v' | 'id'>): Promise<IpcResponse> {
  return new Promise<IpcResponse>((resolve, reject) => {
    let port: chrome.runtime.Port;
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    } catch (e) {
      reject(new Error(`Failed to connect to native host: ${(e as Error).message}`));
      return;
    }

    const id = makeRequestId();
    const pending: PendingRequest = {
      resolve(resp) {
        clearTimeout(pending.timer);
        try { port.disconnect(); } catch { /* ignore */ }
        resolve(resp);
      },
      reject(err) {
        clearTimeout(pending.timer);
        try { port.disconnect(); } catch { /* ignore */ }
        reject(err);
      },
      timer: setTimeout(() => {
        pending.reject(new Error('Native host timed out'));
      }, REQUEST_TIMEOUT_MS),
    };

    port.onMessage.addListener((msg: IpcResponse) => {
      if (msg && msg.id === id) {
        pending.resolve(msg);
      }
    });
    port.onDisconnect.addListener(() => {
      const lastError = chrome.runtime.lastError;
      pending.reject(new Error(
        lastError?.message ?? 'Native host disconnected before responding'
      ));
    });

    const fullReq: IpcRequest = { v: 1, id, ...req };
    try {
      port.postMessage(fullReq);
    } catch (e) {
      pending.reject(new Error(`postMessage failed: ${(e as Error).message}`));
    }
  });
}

// Routing for messages from content script + popup.
type RouterMessage =
  | { kind: 'status' }
  | { kind: 'find_credentials'; url: string }
  | { kind: 'get_totp'; itemId: string }
  | { kind: 'add_credential'; url: string; title?: string; username?: string; password: string };

chrome.runtime.onMessage.addListener((message: RouterMessage, _sender, sendResponse) => {
  (async () => {
    try {
      let resp: IpcResponse;
      switch (message.kind) {
        case 'status':
          resp = await callNative({ type: 'status' });
          break;
        case 'find_credentials':
          resp = await callNative({ type: 'find_credentials', url: message.url });
          break;
        case 'get_totp':
          resp = await callNative({ type: 'get_totp', url: message.itemId });
          break;
        case 'add_credential':
          resp = await callNative({
            type: 'add_credential',
            url: message.url,
            title: message.title,
            username: message.username,
            password: message.password,
          });
          break;
        default:
          resp = { v: 1, id: '', ok: false, error: 'Unknown message kind' };
      }
      sendResponse(resp);
    } catch (e) {
      const err = e as Error;
      sendResponse({ v: 1, id: '', ok: false, error: err.message } satisfies IpcResponse);
    }
  })();
  return true;
});

// Light installation logging.
chrome.runtime.onInstalled.addListener(() => {
  console.log('[VaultCore] background worker installed');
});
