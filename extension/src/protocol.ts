// Mirror of Vault.Ipc.IpcRequest / IpcResponse. Keep these in sync with
// the C# side; if you change one, change the other.

export interface IpcRequest {
  v: number;
  id: string;
  type: 'status' | 'find_credentials' | 'get_totp' | 'add_credential';
  url?: string;
  origin?: string;
  title?: string;
  username?: string;
  password?: string;
}

export interface CredentialMatch {
  itemId: string;
  title: string;
  username?: string | null;
  password?: string | null;
  hasTotp: boolean;
}

export interface IpcResponse {
  v: number;
  id: string;
  ok: boolean;
  error?: string;
  credentials?: CredentialMatch[];
  unlocked?: boolean;
  totpCode?: string;
  totpRemaining?: number;
}

export const NATIVE_HOST_NAME = 'io.vaultcore.host';

export function makeRequestId(): string {
  // crypto.randomUUID is available in MV3 service workers and content scripts.
  return crypto.randomUUID();
}
