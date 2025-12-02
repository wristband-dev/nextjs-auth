import { SessionData } from '@wristband/typescript-session';
import { destroySessionWithCookies } from '../../src/session/from-cookies-session';
import { WristbandError } from '../../src/error';
import { NextJsCookieStore, ReadonlySession, SERVER_COMPONENT_SESSION } from '../../src/types';

describe('destroySessionWithCookies', () => {
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
      getCookieDataForDestroy: jest.fn().mockReturnValue(
        options.cookieData || [
          {
            name: 'session',
            value: '',
            options: {
              httpOnly: true,
              secure: true,
              sameSite: 'lax',
              path: '/',
              maxAge: 0,
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
    it('should destroy session cookies in cookie store', () => {
      const session = createMockSession();

      destroySessionWithCookies(mockCookieStore, session);

      expect(session.getCookieDataForDestroy).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledWith('session', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 0,
      });
    });

    it('should handle multiple cookies', () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: '',
            options: { httpOnly: true, secure: true, maxAge: 0 },
          },
          {
            name: 'session.sig',
            value: '',
            options: { httpOnly: true, secure: true, maxAge: 0 },
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(1, 'session', '', {
        httpOnly: true,
        secure: true,
        maxAge: 0,
      });
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(2, 'session.sig', '', {
        httpOnly: true,
        secure: true,
        maxAge: 0,
      });
    });

    it('should pass through cookie options correctly', () => {
      const customOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict' as const,
        path: '/app',
        maxAge: 0,
        domain: '.example.com',
      };

      const session = createMockSession({
        cookieData: [
          {
            name: 'custom-session',
            value: '',
            options: customOptions,
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledWith('custom-session', '', customOptions);
    });

    it('should handle cookies without options', () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: '',
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledWith('session', '', undefined);
    });

    it('should work with custom session data types', () => {
      interface CustomSessionData extends SessionData {
        theme: string;
        preferences: {
          language: string;
        };
      }

      const session = createMockSession() as ReadonlySession<CustomSessionData> & CustomSessionData;

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
    });
  });

  describe('CSRF Protection', () => {
    it('should destroy CSRF cookie when CSRF protection is enabled', () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: '',
            options: { httpOnly: true, secure: true, maxAge: 0 },
          },
          {
            name: 'CSRF-TOKEN',
            value: '',
            options: { httpOnly: false, secure: true, sameSite: 'strict', maxAge: 0 },
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(1, 'session', '', {
        httpOnly: true,
        secure: true,
        maxAge: 0,
      });
      expect(mockCookieStore.set).toHaveBeenNthCalledWith(2, 'CSRF-TOKEN', '', {
        httpOnly: false,
        secure: true,
        sameSite: 'strict',
        maxAge: 0,
      });
    });

    it('should use custom CSRF cookie name', () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: '',
            options: { httpOnly: true, secure: true, maxAge: 0 },
          },
          {
            name: 'CUSTOM-CSRF',
            value: '',
            options: { httpOnly: false, secure: true, maxAge: 0 },
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(2);
      expect(mockCookieStore.set).toHaveBeenCalledWith('CUSTOM-CSRF', '', { httpOnly: false, secure: true, maxAge: 0 });
    });

    it('should destroy only session cookie when CSRF protection is disabled', () => {
      const session = createMockSession({
        cookieData: [
          {
            name: 'session',
            value: '',
            options: { httpOnly: true, secure: true, maxAge: 0 },
          },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(mockCookieStore.set).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).toHaveBeenCalledWith('session', '', { httpOnly: true, secure: true, maxAge: 0 });
    });
  });

  describe('Server Component Protection', () => {
    it('should throw WristbandError when trying to destroy a Server Component session', () => {
      const session = createMockSession({ isServerComponent: true });

      expect(() => {
        destroySessionWithCookies(mockCookieStore, session);
      }).toThrow(WristbandError);

      expect(() => {
        destroySessionWithCookies(mockCookieStore, session);
      }).toThrow('Cannot destroy a Server Component session');

      // Should not attempt to destroy cookies
      expect(mockCookieStore.set).not.toHaveBeenCalled();
      expect(session.getCookieDataForDestroy).not.toHaveBeenCalled();
    });

    it('should throw with correct error code for Server Component session', () => {
      const session = createMockSession({ isServerComponent: true });

      try {
        destroySessionWithCookies(mockCookieStore, session);
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
    it('should propagate errors from getCookieDataForDestroy', () => {
      const session: any = {
        getCookieDataForDestroy: jest.fn().mockImplementation(() => {
          throw new Error('Failed to prepare destruction data');
        }),
      };

      expect(() => {
        destroySessionWithCookies(mockCookieStore, session as any);
      }).toThrow('Failed to prepare destruction data');

      expect(mockCookieStore.set).not.toHaveBeenCalled();
    });

    it('should propagate errors from cookie store set()', () => {
      const session = createMockSession();
      (mockCookieStore.set as jest.Mock).mockImplementation(() => {
        throw new Error('Cookie write failed');
      });

      expect(() => {
        destroySessionWithCookies(mockCookieStore, session);
      }).toThrow('Cookie write failed');
    });
  });

  describe('Empty Cookie Data', () => {
    it('should handle empty cookie data array', () => {
      const session = createMockSession({ cookieData: [] });

      destroySessionWithCookies(mockCookieStore, session);

      expect(session.getCookieDataForDestroy).toHaveBeenCalledTimes(1);
      expect(mockCookieStore.set).not.toHaveBeenCalled();
    });
  });

  describe('Cookie Store Integration', () => {
    it('should call cookie store for each cookie in order', () => {
      const callOrder: string[] = [];
      (mockCookieStore.set as jest.Mock).mockImplementation((name: string) => {
        callOrder.push(name);
      });

      const session = createMockSession({
        cookieData: [
          { name: 'cookie-1', value: '' },
          { name: 'cookie-2', value: '' },
          { name: 'cookie-3', value: '' },
        ],
      });

      destroySessionWithCookies(mockCookieStore, session);

      expect(callOrder).toEqual(['cookie-1', 'cookie-2', 'cookie-3']);
    });

    it('should not modify the session object', () => {
      const session = createMockSession();
      const originalSession = { ...session };

      destroySessionWithCookies(mockCookieStore, session);

      // Session data should remain unchanged
      expect(session.userId).toBe(originalSession.userId);
    });
  });
});
