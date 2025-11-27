import { SessionData, SessionOptions } from '@wristband/typescript-session';
import { getMutableSessionFromCookies, saveSessionWithCookies } from '../../src/session/from-cookies-session';
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

describe('saveSessionWithCookies - Integration Tests', () => {
  const sessionOptions: SessionOptions = {
    secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
    cookieName: 'test-session',
    maxAge: 3600,
  };

  describe('End-to-End Session Persistence', () => {
    it('should save and retrieve session data', async () => {
      const cookieStore = createMockCookieStore();

      // Save session
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      session.email = 'test@example.com';
      await saveSessionWithCookies(cookieStore, session);

      // Retrieve session
      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);

      expect(retrievedSession.userId).toBe('user-123');
      expect(retrievedSession.email).toBe('test@example.com');
    });

    it('should update existing session cookie', async () => {
      const cookieStore = createMockCookieStore();

      // Initial save
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      // Update session
      const updatedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      updatedSession.email = 'newemail@example.com';
      await saveSessionWithCookies(cookieStore, updatedSession);

      // Verify update
      const finalSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(finalSession.userId).toBe('user-123');
      expect(finalSession.email).toBe('newemail@example.com');
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

      const cookie = cookieStore.get('custom-session');
      expect(cookie).toBeDefined();
      expect(cookie?.value).toBeTruthy();

      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, customOptions);
      expect(retrievedSession.userId).toBe('user-123');
    });

    it('should handle multiple saves and updates', async () => {
      const cookieStore = createMockCookieStore();
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);

      // First save
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      // Second save
      session.email = 'test@example.com';
      await saveSessionWithCookies(cookieStore, session);

      // Third save
      session.cartId = 'cart-abc';
      await saveSessionWithCookies(cookieStore, session);

      // Verify all data persisted
      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.userId).toBe('user-123');
      expect(retrievedSession.email).toBe('test@example.com');
      expect(retrievedSession.cartId).toBe('cart-abc');
    });
  });

  describe('CSRF Protection Integration', () => {
    it('should set CSRF cookie when CSRF protection is enabled', async () => {
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

      // Both session and CSRF cookies should be set
      const sessionCookie = cookieStore.get('test-session');
      const csrfCookie = cookieStore.get('CSRF-TOKEN');

      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.value).toBeTruthy();
      expect(csrfCookie).toBeDefined();
      expect(csrfCookie?.value).toBeTruthy();
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

      const csrfCookie = cookieStore.get('CUSTOM-CSRF');
      expect(csrfCookie).toBeDefined();
      expect(csrfCookie?.value).toBeTruthy();
    });

    it('should persist CSRF token across session updates', async () => {
      const csrfOptions: SessionOptions = {
        secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
        cookieName: 'test-session',
        maxAge: 3600,
        enableCsrfProtection: true,
        csrfCookieName: 'CSRF-TOKEN',
      };

      const cookieStore = createMockCookieStore();

      // Initial save
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, csrfOptions);
      session.userId = 'user-123';
      await saveSessionWithCookies(cookieStore, session);

      const initialCsrfToken = cookieStore.get('CSRF-TOKEN')?.value;
      expect(initialCsrfToken).toBeTruthy();

      // Update session
      const updatedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, csrfOptions);
      updatedSession.email = 'test@example.com';
      await saveSessionWithCookies(cookieStore, updatedSession);

      const updatedCsrfToken = cookieStore.get('CSRF-TOKEN')?.value;
      expect(updatedCsrfToken).toBeTruthy();
      // CSRF token should remain the same across updates
      expect(updatedCsrfToken).toBe(initialCsrfToken);
    });
  });

  describe('Wristband Authentication Data', () => {
    it('should save and retrieve Wristband authentication data', async () => {
      const cookieStore = createMockCookieStore();
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);

      session.isAuthenticated = true;
      session.userId = 'user-123';
      session.tenantId = 'tenant-456';
      session.accessToken = 'eyJhbGc...';
      session.expiresAt = Date.now() + 3600000;

      await saveSessionWithCookies(cookieStore, session);

      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.isAuthenticated).toBe(true);
      expect(retrievedSession.userId).toBe('user-123');
      expect(retrievedSession.tenantId).toBe('tenant-456');
      expect(retrievedSession.accessToken).toBe('eyJhbGc...');
      expect(retrievedSession.expiresAt).toBeDefined();
    });
  });

  describe('Empty and Edge Cases', () => {
    it('should handle empty session data', async () => {
      const cookieStore = createMockCookieStore();
      const session = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);

      // Don't set any data
      await saveSessionWithCookies(cookieStore, session);

      const cookie = cookieStore.get('test-session');
      expect(cookie).toBeDefined();

      const retrievedSession = await getMutableSessionFromCookies<TestSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession).toBeDefined();
    });

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

      const retrievedSession = await getMutableSessionFromCookies<CustomSessionData>(cookieStore, sessionOptions);
      expect(retrievedSession.userId).toBe('user-123');
      expect(retrievedSession.preferences).toEqual({
        theme: 'dark',
        language: 'en',
      });
    });
  });
});
