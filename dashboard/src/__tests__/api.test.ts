import { describe, it, expect, beforeEach } from 'vitest';
import { api } from '../services/api';

const store: Record<string, string> = {};
(globalThis as any).localStorage = {
  getItem: (key: string) => store[key] || null,
  setItem: (key: string, val: string) => { store[key] = val; },
  removeItem: (key: string) => { delete store[key]; },
  clear: () => { Object.keys(store).forEach(k => delete store[k]); },
};

describe('API Service Test Suite', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('handles token storage and logout correctly', () => {
    api.setToken('test_token_123');
    expect(api.getToken()).toBe('test_token_123');
    expect(localStorage.getItem('access_token')).toBe('test_token_123');

    api.logout();
    expect(api.getToken()).toBeNull();
    expect(localStorage.getItem('access_token')).toBeNull();
  });
});
