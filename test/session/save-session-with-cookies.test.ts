import { SessionData } from '@wristband/typescript-session';
import { saveSessionWithCookies } from '../../src/session/from-cookies-session';
import { WristbandError } from '../../src/error';
import { NextJsCookieStore, ReadonlySession, SERVER_COMPONENT_SESSION } from '../../src/types';

describe('saveSessionWithCookies', () => {
  let mockCookieStore: NextJsCookieStore;

  beforeEach(() => {
    jest.clearAllMocks();

    mockCookieStore = {
      get: jest.fn(),
      set: jest.fn(),
    };
  });

  const createMockSession = (
    options: {
      isServerComponent?: boolean;
      cookieData?: Array<{ name: string; value: string; options?: any }>;
    } = {}
  ) => {
    const session: any = {
      userId: 'user-123',
      getCookieDataForSave: jest.fn().mockResolvedValue(
        options.cookieData || [
          {
            name: 'session',
            value: 'encrypted-session-value',
            options: {
              httpOnly: true,
              secure: true,
              sameSite: 'lax',
              path: '/',
              maxAge: 86400,
            },
          },
        ]
      ),
    };

    // Add SERVER_COMPONENT_SESSION marker if requested
    if (options.isServerComponent) {
      Object.defineProperty(session, SERVER_COMPONENT_SESSION, {
        value: true,
        enumerable: false,
        writable: false,
      });
    }

    return session as ReadonlySession<SessionData> & SessionData;
  };

  describe('Happy Path', () => {
    it('should save session cookies to cookie store', async () => {
      const session = createMockSession();

      await saveSessionWithCookies(mockCookieStore, session);

      expect(session.getCookieDataForSave).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledWith('session', 'encrypted-session-value', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 86400,
      });
    });

    it('should handle multiple cookies', async () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: 'encrypted-session-value',
            options: { httpOnly: true, secure: true },
          },
          {
            name: 'session.sig',
            value: 'signature-value',
            options: { httpOnly: true, secure: true },
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(1, 'session', 'encrypted-session-value', {
        httpOnly: true,
        secure: true,
      });
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(2, 'session.sig', 'signature-value', {
        httpOnly: true,
        secure: true,
      });
    });

    it('should pass through cookie options correctly', async () => {
      const customOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict' as const,
        path: '/app',
        maxAge: 3600,
        domain: '.example.com',
      };

      const session = createMockSession({
        cookieData: [
          {
            name: 'custom-session',
            value: 'custom-value',
            options: customOptions,
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledWith('custom-session', 'custom-value', customOptions);
    });

    it('should handle cookies without options', async () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: 'encrypted-value',
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledWith('session', 'encrypted-value', undefined);
    });

    it('should work with custom session data types', async () => {
      interface CustomSessionData extends SessionData {
        theme: string;
        preferences: {
          language: string;
        };
      }

      const session = createMockSession() as ReadonlySession<CustomSessionData> & CustomSessionData;

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
    });
  });

  describe('CSRF Protection', () => {
    it('should save CSRF cookie when CSRF protection is enabled', async () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: 'encrypted-session',
            options: { httpOnly: true, secure: true },
          },
          {
            name: 'CSRF-TOKEN',
            value: 'csrf-token-value',
            options: { httpOnly: false, secure: true, sameSite: 'strict' },
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(1, 'session', 'encrypted-session', {
        httpOnly: true,
        secure: true,
      });
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(2, 'CSRF-TOKEN', 'csrf-token-value', {
        httpOnly: false,
        secure: true,
        sameSite: 'strict',
      });
    });

    it('should use custom CSRF cookie name', async () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: 'encrypted-session',
            options: { httpOnly: true, secure: true },
          },
          {
            name: 'CUSTOM-CSRF',
            value: 'csrf-value',
            options: { httpOnly: false, secure: true },
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenCalledWith('CUSTOM-CSRF', 'csrf-value', { httpOnly: false, secure: true });
    });

    it('should save only session cookie when CSRF protection is disabled', async () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: 'encrypted-session',
            options: { httpOnly: true, secure: true },
          },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledWith('session', 'encrypted-session', {
        httpOnly: true,
        secure: true,
      });
    });
  });

  describe('Server Component Protection', () => {
    it('should throw WristbandError when trying to save a Server Component session', async () => {
      const session = createMockSession({ isServerComponent: true });

      await expect(saveSessionWithCookies(mockCookieStore, session)).rejects.toThrow(WristbandError);

      await expect(saveSessionWithCookies(mockCookieStore, session)).rejects.toThrow(
        'Cannot save a Server Component session'
      );

      // Should not attempt to save cookies
      expect(mockCookieStore.set).not.toHaveBeenCalled();
      expect(session.getCookieDataForSave).not.toHaveBeenCalled();
    });

    it('should throw with correct error code for Server Component session', async () => {
      const session = createMockSession({ isServerComponent: true });

      try {
        await saveSessionWithCookies(mockCookieStore, session);
        fail('Should have thrown');
      } catch (e) {
        const error = e as WristbandError;
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.code).toBe('SESSION_READ_ONLY');
        expect(error.message).toContain('Server Components are read-only');
        expect(error.message).toContain('Use getMutableSessionFromCookies() in Server Actions instead');
      }
    });
  });

  describe('Error Handling', () => {
    it('should propagate errors from getCookieDataForSave', async () => {
      const session: any = {
        getCookieDataForSave: jest.fn().mockRejectedValue(new Error('Encryption failed')),
      };

      await expect(saveSessionWithCookies(mockCookieStore, session as any)).rejects.toThrow('Encryption failed');

      expect(mockCookieStore.set).not.toHaveBeenCalled();
    });

    it('should propagate errors from cookie store set()', async () => {
      const session = createMockSession();
      (mockCookieStore.set as jest.Mock).mockImplementation(() => {
        throw new Error('Cookie write failed');
      });

      await expect(saveSessionWithCookies(mockCookieStore, session)).rejects.toThrow('Cookie write failed');
    });
  });

  describe('Empty Cookie Data', () => {
    it('should handle empty cookie data array', async () => {
      const session = createMockSession({ cookieData: [] });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(session.getCookieDataForSave).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).not.toHaveBeenCalled();
    });
  });

  describe('Cookie Store Integration', () => {
    it('should call cookie store for each cookie in order', async () => {
      const callOrder: string[] = [];
      (mockCookieStore.set as jest.Mock).mockImplementation((name: string) => {
        callOrder.push(name);
      });

      const session = createMockSession({
        cookieData: [
          { name: 'cookie-1', value: 'value-1' },
          { name: 'cookie-2', value: 'value-2' },
          { name: 'cookie-3', value: 'value-3' },
        ],
      });

      await saveSessionWithCookies(mockCookieStore, session);

      expect(callOrder).toEqual(['cookie-1', 'cookie-2', 'cookie-3']);
    });

    it('should not modify the session object', async () => {
      const session = createMockSession();
      const originalSession = { ...session };

      await saveSessionWithCookies(mockCookieStore, session);

      // Session data should remain unchanged
      expect(session.userId).toBe(originalSession.userId);
    });
  });
});
