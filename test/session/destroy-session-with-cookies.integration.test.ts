import { SessionData, SessionOptions } from '@wristband/typescript-session';
import {
  getMutableSessionFromCookies,
  saveSessionWithCookies,
  destroySessionWithCookies,
} from '../../src/session/from-cookies-session';
import { NextJsCookieStore } from '../../src/types';

interface TestSessionData extends SessionData {
  email?: string;
  cartId?: string;
}

// Helper to create a mock cookie store that actually stores cookies
function createMockCookieStore(): NextJsCookieStore {
  const cookies = new Map<string, string>();

  return {
    get(name: string) {
      const value = cookies.get(name);
      return value !== undefined ? { value } : undefined;
    },
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, no-unused-vars
    set(name: string, value: string, _options?: any) {
      cookies.set(name, value);
    },
  };
}

describe('destroySessionWithCookies - Integration Tests', () => {
  const sessionOptions: SessionOptions = {
    secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
    cookieName: 'test-session',
    maxAge: 3600,
  };

  describe('End-to-End Session Destruction', () => {
    it('should destroy session cookie', async () => {
      const cookieStore = createMockCookieStore();

      // Save session
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      expect(cookieStore.get('test-session')).toBeDefined();
      expect(cookieStore.get('test-session')?.value).toBeTruthy();

      // Destroy session
      destroySessionWithCookies(cookieStore, session);

      // Cookie should be empty (deletion cookie)
      const cookie = cookieStore.get('test-session');
      expect(cookie).toBeDefined();
      expect(cookie?.value).toBe('');
    });

    it('should clear session data after destruction', async () => {
      const cookieStore = createMockCookieStore();

      // Save session with data
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      session.email = 'test@example.com';
      await saveSessionWithCookies(cookieStore, session);

      // Destroy session
      destroySessionWithCookies(cookieStore, session);

      // Try to retrieve - should be empty session
      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.userId).toBeUndefined();
      expect(retrievedSession.email).toBeUndefined();
    });

    it('should work with custom cookie name', async () => {
      const customOptions: SessionOptions = {
        secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
        cookieName: 'custom-session',
        maxAge: 3600,
      };

      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, customOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      destroySessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('custom-session');
      expect(cookie).toBeDefined();
      expect(cookie?.value).toBe('');
    });

    it('should work even if session was never saved', async () => {
      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      // Don't save

      // Destroy without saving first
      destroySessionWithCookies(cookieStore, session);

      // Should set deletion cookie
      const cookie = cookieStore.get('test-session');
      expect(cookie).toBeDefined();
      expect(cookie?.value).toBe('');
    });

    it('should work on empty session', async () => {
      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      // Don't set any data

      destroySessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('test-session');
      expect(cookie).toBeDefined();
      expect(cookie?.value).toBe('');
    });

    it('should clear all session data fields', async () => {
      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      session.email = 'test@example.com';
      session.cartId = 'cart-abc';
      await saveSessionWithCookies(cookieStore, session);

      destroySessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('test-session');
      expect(cookie?.value).toBe('');

      // Verify all data is gone
      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.userId).toBeUndefined();
      expect(retrievedSession.email).toBeUndefined();
      expect(retrievedSession.cartId).toBeUndefined();
    });
  });

  describe('CSRF Protection Integration', () => {
    it('should destroy CSRF cookie when CSRF protection is enabled', async () => {
      const csrfOptions: SessionOptions = {
        secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
        cookieName: 'test-session',
        maxAge: 3600,
        enableCsrfProtection: true,
        csrfCookieName: 'CSRF-TOKEN',
      };

      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, csrfOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      expect(cookieStore.get('test-session')).toBeDefined();
      expect(cookieStore.get('CSRF-TOKEN')).toBeDefined();

      destroySessionWithCookies(cookieStore, session);

      // Both cookies should be destroyed
      const sessionCookie = cookieStore.get('test-session');
      const csrfCookie = cookieStore.get('CSRF-TOKEN');

      expect(sessionCookie?.value).toBe('');
      expect(csrfCookie?.value).toBe('');
    });

    it('should work with custom CSRF cookie name', async () => {
      const csrfOptions: SessionOptions = {
        secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
        cookieName: 'test-session',
        maxAge: 3600,
        enableCsrfProtection: true,
        csrfCookieName: 'CUSTOM-CSRF',
      };

      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, csrfOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      destroySessionWithCookies(cookieStore, session);

      const csrfCookie = cookieStore.get('CUSTOM-CSRF');
      expect(csrfCookie?.value).toBe('');
    });
  });

  describe('Wristband Authentication Data', () => {
    it('should destroy session with Wristband auth data', async () => {
      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.isAuthenticated = true;
      session.userId = 'user-123';
      session.tenantId = 'tenant-456';
      session.accessToken = 'eyJhbGc...';
      session.expiresAt = Date.now() + 3600000;
      await saveSessionWithCookies(cookieStore, session);

      destroySessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('test-session');
      expect(cookie?.value).toBe('');

      // Verify auth data is cleared
      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.isAuthenticated).toBeUndefined();
      expect(retrievedSession.userId).toBeUndefined();
      expect(retrievedSession.tenantId).toBeUndefined();
      expect(retrievedSession.accessToken).toBeUndefined();
    });
  });

  describe('Custom Session Data Types', () => {
    it('should work with custom session data types', async () => {
      interface CustomSessionData extends SessionData {
        preferences?: {
          theme: string;
          language: string;
        };
      }

      const cookieStore = createMockCookieStore();

      const session = await getMutableSessionFromCookies<CustomSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      session.preferences = {
        theme: 'dark',
        language: 'en',
      };
      await saveSessionWithCookies(cookieStore, session);

      destroySessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('test-session');
      expect(cookie?.value).toBe('');

      // Verify data is cleared
      const retrievedSession = await getMutableSessionFromCookies<CustomSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.userId).toBeUndefined();
      expect(retrievedSession.preferences).toBeUndefined();
    });
  });
});
