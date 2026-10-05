import { invoke } from '@tauri-apps/api/core';
import type {
  AppSettings,
  AppState,
  EntryFilter,
  EntryInput,
  EntrySummary,
  PasswordEntry,
  PasswordOptions,
} from './types';

export const api = {
  getAppState: () => invoke<AppState>('get_app_state'),
  getSettings: () => invoke<AppSettings>('get_settings'),
  setSettings: (settings: AppSettings) =>
    invoke<AppSettings>('set_settings', {
      autoLockSeconds: settings.autoLockSeconds,
      clipboardClearSeconds: settings.clipboardClearSeconds,
    }),
  createVault: (masterPassword: string) => invoke<void>('create_vault', { masterPassword }),
  openVault: (masterPassword: string, selectedPath?: string | null) =>
    invoke<void>('open_vault', { masterPassword, selectedPath: selectedPath ?? null }),
  lockVault: () => invoke<void>('lock_vault'),
  closeVault: () => invoke<void>('close_vault'),
  recordActivity: () => invoke<void>('record_activity'),
  changeMasterPassword: (oldPassword: string, newPassword: string) =>
    invoke<void>('change_master_password', { oldPassword, newPassword }),
  createBackup: () => invoke<string>('create_backup'),
  exportVault: (destinationPath: string) => invoke<void>('export_vault', { destinationPath }),
  listEntries: (query: string, filter: EntryFilter, sort: string) =>
    invoke<EntrySummary[]>('list_entries', { query, filter, sort }),
  getEntry: (id: string) => invoke<PasswordEntry>('get_entry', { id }),
  createEntry: (input: EntryInput) => invoke<EntrySummary>('create_entry', { input }),
  updateEntry: (id: string, input: EntryInput) =>
    invoke<EntrySummary>('update_entry', { id, input }),
  deleteEntry: (id: string) => invoke<void>('delete_entry', { id }),
  setFavorite: (id: string, value: boolean) => invoke<void>('set_favorite', { id, value }),
  generatePassword: (options: PasswordOptions) =>
    invoke<string>('generate_password', { ...options }),
  copySensitiveValue: (value: string, clearAfterSeconds?: number) =>
    invoke<{ clearAfterSeconds: number }>('copy_sensitive_value', {
      value,
      clearAfterSeconds: clearAfterSeconds ?? null,
    }),
  clearManagedClipboard: () => invoke<void>('clear_managed_clipboard'),
};

export function errorMessage(error: unknown, fallback = '操作失败，请稍后重试。'): string {
  if (typeof error === 'string') return error;
  if (error && typeof error === 'object' && 'message' in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string' && message.trim()) return message;
  }
  return fallback;
}
