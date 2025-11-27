import { SessionData } from '@wristband/typescript-session';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { MutableSession, ServerActionAuthResult } from '../../src/types';
import { WristbandService } from '../../src/wristband-service';

// Import mocked functions
import { getMutableSessionFromCookies, saveSessionWithCookies } from '../../src/session';

// Mock dependencies
jest.mock('../../src/wristband-service');
jest.mock('../../src/session', () => {
  return {
    getMutableSessionFromCookies: jest.fn(),
    saveSessionWithCookies: jest.fn(),
  };
});

const mockedGetMutableSessionFromCookies = getMutableSessionFromCookies as jest.MockedFunction<
  typeof getMutableSessionFromCookies
>;
const mockedSaveSessionWithCookies = saveSessionWithCookies as jest.MockedFunction<typeof saveSessionWithCookies>;

// Helper to create a mock MutableSession
function createMockSession<T extends SessionData>(data: T): MutableSession<T> {
  return {
    ...data,
    get: jest.fn((key: string) => {
      return (data as any)[key];
    }),
    set: jest.fn((key: string, value: any) => {
      // eslint-disable-next-line no-param-reassign
      (data as any)[key] = value;
    }),
    delete: jest.fn((key: string) => {
      // eslint-disable-next-line no-param-reassign
      delete (data as any)[key];
    }),
    toJSON: jest.fn(() => {
      return data;
    }),
  } as any;
}

describe('appRouter.createServerActionAuth()', () => {
  let wristbandAuth: WristbandAuth;
  let mockCookieStore: any;
  let mockWristbandService: jest.Mocked<WristbandService>;
  let requireServerActionAuth: (cookieStore: any) => Promise<ServerActionAuthResult>;

  const sessionOptions = {
    secrets: 'test-secret-must-be-at-least-32-characters-long',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Create mock cookie store
    mockCookieStore = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
    };

    // Create WristbandAuth instance
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: 'https://localhost:6001/api/auth/login',
      redirectUri: 'https://localhost:6001/api/auth/callback',
      wristbandApplicationVanityDomain: 'invotasticb2b-invotastic.dev.wristband.dev',
      autoConfigureEnabled: false,
    });

    // Get mocked WristbandService instance
    mockWristbandService = (wristbandAuth as any).appRouterAuthHandler.wristbandService;

    // Create the auth helper function using the factory
    requireServerActionAuth = wristbandAuth.appRouter.createServerActionAuth({ sessionOptions });
  });

  describe('Authenticated User - No Token Refresh Needed', () => {
    test('should return authenticated result with valid session', async () => {
      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        expiresAt: Date.now() + 3600000, // 1 hour from now
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBe(mockSession);
      expect(result.reason).toBeUndefined();

      // Verify session was retrieved
      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledWith(mockCookieStore, sessionOptions);
      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledTimes(1);

      // Verify session was saved (for rolling expiration)
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledTimes(1);

      // Verify no token refresh attempted
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });

    test('should save session for rolling expiration even without refresh token', async () => {
      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        expiresAt: Date.now() + 3600000,
        isAuthenticated: true,
        // No refreshToken
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBe(mockSession);

      // Verify session was still saved (rolling expiration)
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledTimes(1);
    });

    test('should handle session without expiresAt field', async () => {
      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
        // No expiresAt
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBe(mockSession);

      // Should not attempt token refresh without expiresAt
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();

      // Should still save session
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
    });
  });

  describe('Authenticated User - Token Refresh Required', () => {
    test('should refresh expired access token and update session', async () => {
      const expiredTime = Date.now() - 1000; // Expired 1 second ago
      const mockSessionData: SessionData = {
        accessToken: 'expired-access-token',
        expiresAt: expiredTime,
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      const newTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        id_token: 'new-id-token',
        token_type: 'Bearer',
      };

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockWristbandService.refreshToken.mockResolvedValue(newTokenResponse);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBeTruthy();

      // Verify token was refreshed
      expect(mockWristbandService.refreshToken).toHaveBeenCalledWith('valid-refresh-token');
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);

      // Verify session was updated with new tokens
      expect(result?.session!.accessToken).toBe('new-access-token');
      expect(result?.session!.refreshToken).toBe('new-refresh-token');
      expect(result?.session!.expiresAt).toBeGreaterThan(Date.now());

      // Verify updated session was saved
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledTimes(1);
    });

    test('should handle token refresh with expirationBuffer', async () => {
      // Create WristbandAuth with token expiration buffer of 300 seconds (5 minutes)
      const wristbandAuthWithBuffer = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: 'https://localhost:6001/api/auth/login',
        redirectUri: 'https://localhost:6001/api/auth/callback',
        wristbandApplicationVanityDomain: 'invotasticb2b-invotastic.dev.wristband.dev',
        tokenExpirationBuffer: 300, // 5 minutes buffer (300 seconds)
        autoConfigureEnabled: false,
      });

      const requireServerActionAuthWithBuffer = wristbandAuthWithBuffer.appRouter.createServerActionAuth({
        sessionOptions,
      });

      // The buffer was already applied when the token was stored
      // So if a token has expiresAt in the past, it should trigger refresh
      const pastExpiration = Date.now() - 1000; // Expired 1 second ago (after buffer was applied)
      const mockSessionData: SessionData = {
        accessToken: 'expiring-access-token',
        expiresAt: pastExpiration,
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      const newTokenResponse = {
        access_token: 'refreshed-access-token',
        refresh_token: 'refreshed-refresh-token',
        expires_in: 3600,
        id_token: 'refreshed-id-token',
        token_type: 'Bearer',
      };

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      const mockServiceWithBuffer = (wristbandAuthWithBuffer as any).appRouterAuthHandler.wristbandService;
      mockServiceWithBuffer.refreshToken.mockResolvedValue(newTokenResponse);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuthWithBuffer(mockCookieStore);

      expect(result.authenticated).toBe(true);

      // Verify token was refreshed (expiresAt is in the past)
      expect(mockServiceWithBuffer.refreshToken).toHaveBeenCalledWith('valid-refresh-token');
    });

    test('should return failure when token refresh fails', async () => {
      const expiredTime = Date.now() - 1000;
      const mockSessionData: SessionData = {
        accessToken: 'expired-access-token',
        expiresAt: expiredTime,
        isAuthenticated: true,
        refreshToken: 'invalid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockWristbandService.refreshToken.mockRejectedValue(new Error('Token refresh failed'));
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      // Spy on console.error
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('token_refresh_failed');

      // Verify session was NOT saved after failed refresh
      expect(mockedSaveSessionWithCookies).not.toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });

    test('should not attempt refresh if no refresh token exists', async () => {
      const expiredTime = Date.now() - 1000;
      const mockSessionData: SessionData = {
        accessToken: 'expired-access-token',
        expiresAt: expiredTime,
        isAuthenticated: true,
        // No refreshToken
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBe(mockSession);

      // Verify no refresh attempted without refresh token
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();

      // Should still save session
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
    });
  });

  describe('Unauthenticated User', () => {
    test('should return not_authenticated when session is not authenticated', async () => {
      const mockSessionData: SessionData = {
        isAuthenticated: false,
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('not_authenticated');

      // Verify session was NOT saved
      expect(mockedSaveSessionWithCookies).not.toHaveBeenCalled();

      // Verify no token refresh attempted
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });

    test('should return not_authenticated when isAuthenticated is missing', async () => {
      const mockSessionData: SessionData = {
        accessToken: 'some-token',
        // No isAuthenticated field
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('not_authenticated');

      // Verify no session operations performed
      expect(mockedSaveSessionWithCookies).not.toHaveBeenCalled();
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('should return unexpected_error when getMutableSessionFromCookies throws', async () => {
      mockedGetMutableSessionFromCookies.mockRejectedValue(new Error('Session retrieval failed'));

      // Spy on console.error
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('unexpected_error');

      // Verify no session save attempted
      expect(mockedSaveSessionWithCookies).not.toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });

    test('should return unexpected_error when saveSessionWithCookies throws', async () => {
      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        expiresAt: Date.now() + 3600000,
        isAuthenticated: true,
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockRejectedValue(new Error('Session save failed'));

      // Spy on console.error
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('unexpected_error');

      consoleErrorSpy.mockRestore();
    });

    test('should handle unexpected error types', async () => {
      mockedGetMutableSessionFromCookies.mockRejectedValue('String error instead of Error object');

      // Spy on console.error
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(false);
      expect(result.session).toBeUndefined();
      expect(result.reason).toBe('unexpected_error');

      consoleErrorSpy.mockRestore();
    });
  });

  describe('Custom Session Data Types', () => {
    interface CustomSessionData extends SessionData {
      userId?: string;
      roles?: string[];
      metadata?: Record<string, any>;
    }

    test('should support custom session data types', async () => {
      const requireCustomAuth = wristbandAuth.appRouter.createServerActionAuth<CustomSessionData>({
        sessionOptions,
      });

      const mockCustomSessionData: CustomSessionData = {
        accessToken: 'valid-access-token',
        expiresAt: Date.now() + 3600000,
        isAuthenticated: true,
        userId: 'user-123',
        roles: ['admin', 'user'],
        metadata: { orgId: 'org-456' },
      };
      const mockCustomSession = createMockSession(mockCustomSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockCustomSession as any);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult<CustomSessionData> = await requireCustomAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result?.session!.userId).toBe('user-123');
      expect(result?.session!.roles).toEqual(['admin', 'user']);
      expect(result?.session!.metadata?.orgId).toBe('org-456');
    });

    test('should preserve custom fields through token refresh', async () => {
      const requireCustomAuth = wristbandAuth.appRouter.createServerActionAuth<CustomSessionData>({
        sessionOptions,
      });

      const mockCustomSessionData: CustomSessionData = {
        accessToken: 'expired-token',
        expiresAt: Date.now() - 1000,
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
        userId: 'user-123',
        roles: ['admin'],
      };
      const mockCustomSession = createMockSession(mockCustomSessionData);

      const newTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        id_token: 'new-id-token',
        token_type: 'Bearer',
      };

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockCustomSession as any);
      mockWristbandService.refreshToken.mockResolvedValue(newTokenResponse);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult<CustomSessionData> = await requireCustomAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result?.session!.accessToken).toBe('new-access-token');
      expect(result?.session!.refreshToken).toBe('new-refresh-token');
      // Custom fields preserved
      expect(result?.session!.userId).toBe('user-123');
      expect(result?.session!.roles).toEqual(['admin']);
    });
  });

  describe('CSRF Protection Not Required', () => {
    test('should not perform CSRF validation for Server Actions', async () => {
      // Server Actions have built-in CSRF protection via Next.js Origin/Host header comparison
      // This method should NOT attempt any CSRF validation

      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        expiresAt: Date.now() + 3600000,
        isAuthenticated: true,
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);

      // Note: There is no CSRF token check in the implementation
      // This is intentional - Server Actions handle CSRF protection at the Next.js framework level
    });
  });

  describe('Factory Function Configuration', () => {
    test('should create reusable auth helper with configured sessionOptions', async () => {
      const customSessionOptions = {
        secrets: 'custom-secret-must-be-at-least-32-characters-long',
        cookieName: 'custom-session',
        maxAge: 7200,
      };

      const customRequireAuth = wristbandAuth.appRouter.createServerActionAuth({
        sessionOptions: customSessionOptions,
      });

      const mockSessionData: SessionData = {
        accessToken: 'valid-access-token',
        isAuthenticated: true,
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      await customRequireAuth(mockCookieStore);

      // Verify the custom session options were passed through
      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledWith(mockCookieStore, customSessionOptions);
    });

    test('should allow multiple auth helpers with different configurations', async () => {
      const sessionOptions1 = { secrets: 'secret-1-must-be-at-least-32-characters-long' };
      const sessionOptions2 = { secrets: 'secret-2-must-be-at-least-32-characters-long' };

      const requireAuth1 = wristbandAuth.appRouter.createServerActionAuth({ sessionOptions: sessionOptions1 });
      const requireAuth2 = wristbandAuth.appRouter.createServerActionAuth({ sessionOptions: sessionOptions2 });

      const mockSessionData: SessionData = { isAuthenticated: false };
      const mockSession = createMockSession(mockSessionData);
      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);

      await requireAuth1(mockCookieStore);
      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledWith(mockCookieStore, sessionOptions1);

      await requireAuth2(mockCookieStore);
      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledWith(mockCookieStore, sessionOptions2);
    });

    test('should pass sessionOptions with minimal configuration', async () => {
      const minimalOptions = {
        secrets: 'minimal-secret-must-be-at-least-32-characters',
      };

      const minimalRequireAuth = wristbandAuth.appRouter.createServerActionAuth({
        sessionOptions: minimalOptions,
      });

      const mockSessionData: SessionData = {
        isAuthenticated: false,
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);

      await minimalRequireAuth(mockCookieStore);

      expect(mockedGetMutableSessionFromCookies).toHaveBeenCalledWith(mockCookieStore, minimalOptions);
    });
  });

  describe('Edge Cases', () => {
    test('should handle session with missing optional fields', async () => {
      const mockSessionData: SessionData = {
        isAuthenticated: true,
        // Missing accessToken, expiresAt, etc.
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);
      expect(result.session).toBe(mockSession);

      // Should still save session
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
    });

    test('should handle session that just became expired', async () => {
      const justExpired = Date.now() - 100; // Expired 100ms ago
      const mockSessionData: SessionData = {
        accessToken: 'just-expired-token',
        expiresAt: justExpired,
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      const newTokenResponse = {
        access_token: 'refreshed-token',
        refresh_token: 'refreshed-refresh-token',
        expires_in: 3600,
        id_token: 'refreshed-id-token',
        token_type: 'Bearer',
      };

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockWristbandService.refreshToken.mockResolvedValue(newTokenResponse);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);

      // Should have attempted refresh
      expect(mockWristbandService.refreshToken).toHaveBeenCalled();
    });

    test('should handle very long session expiry time', async () => {
      const farFuture = Date.now() + 365 * 24 * 60 * 60 * 1000; // 1 year
      const mockSessionData: SessionData = {
        accessToken: 'long-lived-token',
        expiresAt: farFuture,
        isAuthenticated: true,
        refreshToken: 'valid-refresh-token',
      };
      const mockSession = createMockSession(mockSessionData);

      mockedGetMutableSessionFromCookies.mockResolvedValue(mockSession);
      mockedSaveSessionWithCookies.mockResolvedValue(undefined);

      const result: ServerActionAuthResult = await requireServerActionAuth(mockCookieStore);

      expect(result.authenticated).toBe(true);

      // Should NOT attempt refresh for far-future expiry
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();

      // Should still save for rolling expiration
      expect(mockedSaveSessionWithCookies).toHaveBeenCalledWith(mockCookieStore, mockSession);
    });
  });
});
