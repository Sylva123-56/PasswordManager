export type View = 'all' | 'favorites' | 'recent' | 'settings';

export interface AppState {
  vaultExists: boolean;
  locked: boolean;
  vaultPathDisplayName: string | null;
  autoLockSecondsRemaining: number | null;
  appVersion: string;
}

export interface AppSettings {
  autoLockSeconds: number;
  clipboardClearSeconds: number;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  tags: string[];
  favorite: boolean;
  updatedAt: string;
}

export interface PasswordEntry extends EntrySummary {
  password: string;
  notes: string;
  createdAt: string;
  customFields: Record<string, string>;
}

export interface EntryInput {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  favorite: boolean;
  customFields?: Record<string, string>;
}

export interface EntryFilter {
  scope: 'all' | 'favorites';
  tag?: string | null;
}

export interface PasswordOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeAmbiguous: boolean;
}

export interface CommandError {
  code?: string;
  message?: string;
}
