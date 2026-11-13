import { NextRequest, NextResponse } from 'next/server';
import { SessionData } from '@wristband/typescript-session';
import { WristbandAuthImpl } from '../../src/auth/wristband-auth-impl';
import { getSessionFromRequest } from '../../src/session';
import {
  isProtectedApi,
  isProtectedPage,
  isValidCsrf,
  normalizeMiddlewareConfig,
  resolveOnPageUnauthenticated,
  copyResponseHeaders,
  setSessionCookieOnRequest,
} from '../../src/utils/middleware';
import { AuthConfig, AuthMiddlewareConfig, TokenData } from '../../src/types';

jest.mock('../../src/session');
jest.mock('../../src/utils/middleware', () => {
  return {
    isProtectedApi: jest.fn(),
    isProtectedPage: jest.fn(),
    isValidCsrf: jest.fn(),
    normalizeMiddlewareConfig: jest.fn(),
    resolveOnPageUnauthenticated: jest.fn(),
    copyResponseHeaders: jest.fn((source, target) => {
      return target;
    }),
    setSessionCookieOnRequest: jest.fn(),
  };
});

const mockGetSessionFromRequest = getSessionFromRequest as jest.MockedFunction<typeof getSessionFromRequest>;
const mockIsProtectedApi = isProtectedApi as jest.MockedFunction<typeof isProtectedApi>;
const mockIsProtectedPage = isProtectedPage as jest.MockedFunction<typeof isProtectedPage>;
const mockIsValidCsrf = isValidCsrf as jest.MockedFunction<typeof isValidCsrf>;
const mockNormalizeMiddlewareConfig = normalizeMiddlewareConfig as jest.Mock;
const mockResolveOnPageUnauthenticated = resolveOnPageUnauthenticated as jest.Mock;
const mockCopyResponseHeaders = copyResponseHeaders as jest.MockedFunction<typeof copyResponseHeaders>;
const mockSetSessionCookieOnRequest = setSessionCookieOnRequest as jest.MockedFunction<
  typeof setSessionCookieOnRequest
>;

const originalConsoleLog = console.log;
const originalConsoleError = console.error;

// The middleware skips the SESSION strategy when the request has no session cookie, so every request
// in these tests carries one. The name matches the cookieName in mockMiddlewareConfig.
const SESSION_COOKIE = 'test-session=encrypted-session-value';

function createRequestWithSession(url: string, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest(url, { headers: { cookie: SESSION_COOKIE, ...headers } });
}

describe('WristbandAuth Middleware - Session Strategy', () => {
  let wristbandAuth: WristbandAuthImpl;
  let mockAuthConfig: AuthConfig;
  let mockMiddlewareConfig: AuthMiddlewareConfig;
  let mockRequest: NextRequest;
  let mockOnPageUnauthenticated: jest.Mock;
  let defaultNormalizedConfig: any;

  beforeAll(() => {
    console.log = jest.fn();
    console.error = jest.fn();
  });

  afterAll(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  beforeEach(() => {
    jest.clearAllMocks();

    mockAuthConfig = {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      wristbandApplicationVanityDomain: 'test.wristband.dev',
      loginUrl: 'https://test.com/api/auth/login',
      redirectUri: 'https://test.com/api/auth/callback',
    };

    mockOnPageUnauthenticated = jest.fn().mockResolvedValue(NextResponse.redirect('https://test.com/login'));

    mockMiddlewareConfig = {
      authStrategies: ['SESSION'],
      sessionConfig: {
        sessionOptions: {
          secrets: ['test-secret'],
          cookieName: 'test-session',
        },
      },
      protectedPages: ['/dashboard(.*)'],
      protectedApis: ['/api/v1/.*'],
      onPageUnauthenticated: mockOnPageUnauthenticated,
    };

    wristbandAuth = new WristbandAuthImpl(mockAuthConfig);

    defaultNormalizedConfig = {
      authStrategies: ['SESSION'],
      sessionConfig: {
        sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
        sessionEndpoint: '/api/auth/session',
        tokenEndpoint: '/api/auth/token',
        csrfTokenHeaderName: 'X-CSRF-TOKEN',
      },
      jwtConfig: {},
      protectedPages: mockMiddlewareConfig.protectedPages || [],
      protectedApis: mockMiddlewareConfig.protectedApis || [],
      onPageUnauthenticated: mockOnPageUnauthenticated,
    };
    mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);

    mockResolveOnPageUnauthenticated.mockReturnValue(mockOnPageUnauthenticated);

    mockRequest = createRequestWithSession('https://test.com/dashboard');

    mockIsProtectedApi.mockReturnValue(false);
    mockIsProtectedPage.mockReturnValue(false);
    mockIsValidCsrf.mockResolvedValue(true);

    mockCopyResponseHeaders.mockImplementation((source, target) => {
      return target;
    });
  });

  describe('Session Retrieval', () => {
    it('should check session for protected routes', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalledWith(
        mockRequest,
        mockMiddlewareConfig.sessionConfig!.sessionOptions
      );
    });
  });

  describe('Session Retrieval Errors', () => {
    it('should return 500 for protected API when session retrieval fails (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session read failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result).toBeInstanceOf(NextResponse);
      expect(result.status).toBe(500); // ← Changed from 401 to 500
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should return 500 for protected API when session retrieval fails (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session read failed'));

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(result).toBeInstanceOf(NextResponse);
      expect(result.status).toBe(500); // ← Changed from 401 to 500
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should call onPageUnauthenticated for protected page when session retrieval fails (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session read failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockResolveOnPageUnauthenticated).toHaveBeenCalledWith(
        defaultNormalizedConfig,
        'https://test.com/api/auth/login'
      );
      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'unexpected_error'); // ← Added reason
      expect(result).toEqual(NextResponse.redirect('https://test.com/login'));
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should call onPageUnauthenticated for protected page when session retrieval fails (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session read failed'));

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });
  });

  describe('Authentication Checks', () => {
    it('should return 401 for unauthenticated API request (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const mockSession = {
        isAuthenticated: false,
        csrfToken: 'test-csrf-token',
        refreshToken: null,
        expiresAt: null,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result).toBeInstanceOf(NextResponse);
      expect(result.status).toBe(401);
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should return 401 for unauthenticated API request (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const mockSession = {
        isAuthenticated: false,
        csrfToken: 'test-csrf-token',
        refreshToken: null,
        expiresAt: null,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(result.status).toBe(401);
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should call onPageUnauthenticated for unauthenticated page request (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      const mockSession = {
        isAuthenticated: false,
        csrfToken: null,
        refreshToken: null,
        expiresAt: null,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated'); // ← Added reason
      expect(result).toEqual(NextResponse.redirect('https://test.com/login'));
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should call onPageUnauthenticated for unauthenticated page request (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      const mockSession = {
        isAuthenticated: false,
        csrfToken: null,
        refreshToken: null,
        expiresAt: null,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should allow authenticated requests to continue and save session (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSessionResponse = new Response();
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(mockSessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockSession.saveToResponse).toHaveBeenCalledWith(new Response());
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(mockSessionResponse, expect.any(NextResponse));
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should allow authenticated requests to continue and save session (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSessionResponse = new Response();
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(mockSessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // previousResponse headers are copied first, then the session headers, onto a new forwarded response.
      expect(result).not.toBe(previousResponse);
      expect(mockCopyResponseHeaders).toHaveBeenCalledTimes(2);
      expect(mockCopyResponseHeaders).toHaveBeenNthCalledWith(1, previousResponse, result);
      expect(mockCopyResponseHeaders).toHaveBeenNthCalledWith(2, mockSessionResponse, result);
    });
  });

  describe('CSRF Protection', () => {
    it('should skip CSRF validation when CSRF protection is disabled', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // CSRF disabled in sessionOptions (default is false)
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockIsValidCsrf).not.toHaveBeenCalled();
    });

    it('should validate CSRF token for protected API routes when CSRF protection is enabled', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users', { 'X-CSRF-TOKEN': 'test-csrf-token' });
      mockIsProtectedApi.mockReturnValue(true);

      // CSRF enabled in sessionOptions
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
          enableCsrfProtection: true,
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockResolvedValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockIsValidCsrf).toHaveBeenCalledWith(mockRequest, 'test-csrf-token', 'X-CSRF-TOKEN');
    });

    it('should return 403 when CSRF validation fails for API routes (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // CSRF enabled in sessionOptions
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
          enableCsrfProtection: true,
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockResolvedValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result).toBeInstanceOf(NextResponse);
      expect(result.status).toBe(403);
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
      // Session should NOT be saved since CSRF failed
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });

    it('should return 403 when CSRF validation fails for API routes (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // CSRF enabled in sessionOptions
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
          enableCsrfProtection: true,
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockResolvedValue(false);

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(result.status).toBe(403);
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
      // Session should NOT be saved since CSRF failed
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });

    it('should not validate CSRF for protected page routes', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      // CSRF enabled in sessionOptions
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
          enableCsrfProtection: true,
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockIsValidCsrf).not.toHaveBeenCalled();
    });

    it('should handle missing CSRF token in session when CSRF is enabled', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // CSRF enabled in sessionOptions
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
          enableCsrfProtection: true,
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: undefined,
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockResolvedValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockIsValidCsrf).toHaveBeenCalledWith(mockRequest, undefined, 'X-CSRF-TOKEN');
      expect(result.status).toBe(403);
      // Session should NOT be saved since CSRF failed
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });
  });

  describe('Token Refresh', () => {
    it('should refresh token when expired', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const newTokenData: TokenData = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt: Date.now() + 3600000,
        expiresIn: 3600,
        idToken: 'new-id-token',
      };
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(newTokenData);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).toHaveBeenCalledWith('test-refresh-token', expiredTime);
      expect(mockSession.accessToken).toBe('new-access-token');
      expect(mockSession.refreshToken).toBe('new-refresh-token');
      expect(mockSession.expiresAt).toBe(newTokenData.expiresAt);
    });

    it('should not refresh token when not expired', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const futureTime = Date.now() + 3600000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: futureTime,
        accessToken: 'valid-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).toHaveBeenCalledWith('test-refresh-token', futureTime);
      expect(mockSession.accessToken).toBe('valid-access-token');
    });

    it('should return 401 for API route when token refresh fails (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Token refresh failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result).toBeInstanceOf(NextResponse);
      expect(result.status).toBe(401);
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should return 401 for API route when token refresh fails (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Token refresh failed'));

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(result.status).toBe(401);
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should call onPageUnauthenticated when token refresh fails for page route (no previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Token refresh failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'token_refresh_failed'); // ← Added reason
      expect(result).toEqual(NextResponse.redirect('https://test.com/login'));
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });

    it('should call onPageUnauthenticated when token refresh fails for page route (with previous response)', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Token refresh failed'));

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should skip token refresh when refreshToken is missing', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: undefined,
        expiresAt: Date.now() - 1000,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).not.toHaveBeenCalled();
      expect(mockSession.accessToken).toBe('old-access-token');
    });

    it('should skip token refresh when expiresAt is undefined', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: undefined,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).not.toHaveBeenCalled();
      expect(mockSession.accessToken).toBe('old-access-token');
    });

    it('should skip token refresh when both refreshToken and expiresAt are missing', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: undefined,
        expiresAt: undefined,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).not.toHaveBeenCalled();
      expect(mockSession.accessToken).toBe('old-access-token');
    });

    it('should skip token refresh when refreshToken is null', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: null,
        expiresAt: Date.now() - 1000,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(wristbandAuth.refreshTokenIfExpired).not.toHaveBeenCalled();
      expect(mockSession.accessToken).toBe('old-access-token');
    });

    it('should refresh token and save session with previous response', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSessionResponse = new Response();
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
        accessToken: 'old-access-token',
        saveToResponse: jest.fn().mockResolvedValue(mockSessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const newTokenData: TokenData = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt: Date.now() + 3600000,
        expiresIn: 3600,
        idToken: 'new-id-token',
      };
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockResolvedValue(newTokenData);

      const previousResponse = NextResponse.next();
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(wristbandAuth.refreshTokenIfExpired).toHaveBeenCalledWith('test-refresh-token', expiredTime);
      expect(mockSession.accessToken).toBe('new-access-token');
      expect(mockSession.refreshToken).toBe('new-refresh-token');
      expect(mockSession.expiresAt).toBe(newTokenData.expiresAt);

      // Should copy the previous response headers, then the session headers, onto a new forwarded response
      expect(result).not.toBe(previousResponse);
      expect(mockCopyResponseHeaders).toHaveBeenCalledTimes(2);
      expect(mockCopyResponseHeaders).toHaveBeenNthCalledWith(1, previousResponse, result);
      expect(mockCopyResponseHeaders).toHaveBeenNthCalledWith(2, mockSessionResponse, result);
      // The refreshed session cookie is put on the request for the route handler
      expect(mockSetSessionCookieOnRequest).toHaveBeenCalledWith(mockRequest, mockSessionResponse, 'test-session');
    });
  });

  describe('Custom Session Data Types', () => {
    interface CustomSessionData extends SessionData {
      userId: string;
      email: string;
      roles: string[];
    }

    it('should support custom session data types', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession: CustomSessionData = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        userId: 'user-123',
        email: 'test@example.com',
        roles: ['admin', 'user'],
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      } as any;
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth<CustomSessionData>(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalledWith(
        mockRequest,
        mockMiddlewareConfig.sessionConfig!.sessionOptions
      );
    });
  });

  describe('Session Strategy Error Reasons', () => {
    it('should return 401 with not_authenticated reason when session is not authenticated', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should return 401 with token_refresh_failed reason when token refresh fails for API', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Token refresh failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should return 500 with unexpected_error reason when session retrieval throws for API', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      mockGetSessionFromRequest.mockRejectedValue(new Error('Session service crashed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(500);
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
    });

    it('should return 403 with csrf_failed reason when CSRF validation fails', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockResolvedValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(403);
      const body = await result.json();
      expect(body.error).toBe('Forbidden');
    });

    it('should pass not_authenticated reason to onPageUnauthenticated when session not authenticated', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated');
    });

    it('should pass token_refresh_failed reason to onPageUnauthenticated when refresh fails', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);
      const expiredTime = Date.now() - 1000;

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expiredTime,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      jest.spyOn(wristbandAuth, 'refreshTokenIfExpired').mockRejectedValue(new Error('Refresh failed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'token_refresh_failed');
    });

    it('should pass unexpected_error reason to onPageUnauthenticated when session throws', async () => {
      mockRequest = createRequestWithSession('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      mockGetSessionFromRequest.mockRejectedValue(new Error('Session crashed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'unexpected_error');
    });

    it('should verify error message text matches HTTP status code', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // Test 401
      const mockSession401 = { isAuthenticated: false };
      mockGetSessionFromRequest.mockResolvedValue(mockSession401 as any);
      const result401 = await wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig)(mockRequest);
      expect(result401.status).toBe(401);
      const body401 = await result401.json();
      expect(body401.error).toBe('Unauthorized');

      // Test 403
      const configWithCsrf = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(configWithCsrf);
      const mockSession403 = {
        isAuthenticated: true,
        csrfToken: 'test-csrf',
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession403 as any);
      mockIsValidCsrf.mockResolvedValue(false);
      const result403 = await wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig)(mockRequest);
      expect(result403.status).toBe(403);
      const body403 = await result403.json();
      expect(body403.error).toBe('Forbidden');

      // Test 500
      mockGetSessionFromRequest.mockRejectedValue(new Error('Crash'));
      const result500 = await wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig)(mockRequest);
      expect(result500.status).toBe(500);
      const body500 = await result500.json();
      expect(body500.error).toBe('Internal Server Error');
    });
  });

  describe('Session Cookie Detection', () => {
    it('should return 401 without reading the session when the request has no session cookie', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should pass not_authenticated to onPageUnauthenticated when a page request has no session cookie', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated');
    });

    it('should treat an empty session cookie as missing', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', { headers: { cookie: 'test-session=' } });
      mockIsProtectedApi.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
    });

    it('should ignore a default-named session cookie when a custom cookieName is configured', async () => {
      // mockMiddlewareConfig uses cookieName 'test-session', so a 'session' cookie isn't the session credential.
      mockRequest = new NextRequest('https://test.com/api/v1/users', { headers: { cookie: 'session=some-value' } });
      mockIsProtectedApi.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
    });

    it('should read the session when the configured custom cookieName is present', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { cookie: 'other=1; test-session=encrypted-session-value' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it("should use typescript-session's default cookie name when cookieName isn't configured", async () => {
      const defaultCookieSessionOptions = { secrets: ['test-secret'] };
      mockNormalizeMiddlewareConfig.mockReturnValue({
        ...defaultNormalizedConfig,
        sessionConfig: { ...defaultNormalizedConfig.sessionConfig, sessionOptions: defaultCookieSessionOptions },
      });
      mockRequest = new NextRequest('https://test.com/api/v1/users', { headers: { cookie: 'session=some-value' } });
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth({
        ...mockMiddlewareConfig,
        sessionConfig: { sessionOptions: defaultCookieSessionOptions },
      });
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalledWith(mockRequest, defaultCookieSessionOptions);
      expect(result.status).not.toBe(401);
    });
  });

  describe('Session Cookie Forwarding', () => {
    function mockAuthenticatedSession(sessionResponse: Response) {
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(sessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      return mockSession;
    }

    it('should put the saved session cookie on the request using the configured cookie name', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const mockSessionResponse = new Response();
      mockAuthenticatedSession(mockSessionResponse);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockSetSessionCookieOnRequest).toHaveBeenCalledTimes(1);
      expect(mockSetSessionCookieOnRequest).toHaveBeenCalledWith(mockRequest, mockSessionResponse, 'test-session');
    });

    it("should use typescript-session's default cookie name when cookieName isn't configured", async () => {
      const defaultCookieSessionOptions = { secrets: ['test-secret'] };
      mockNormalizeMiddlewareConfig.mockReturnValue({
        ...defaultNormalizedConfig,
        sessionConfig: { ...defaultNormalizedConfig.sessionConfig, sessionOptions: defaultCookieSessionOptions },
      });
      mockRequest = new NextRequest('https://test.com/api/v1/users', { headers: { cookie: 'session=some-value' } });
      mockIsProtectedApi.mockReturnValue(true);
      const mockSessionResponse = new Response();
      mockAuthenticatedSession(mockSessionResponse);

      const middleware = wristbandAuth.createMiddlewareAuth({
        ...mockMiddlewareConfig,
        sessionConfig: { sessionOptions: defaultCookieSessionOptions },
      });
      await middleware(mockRequest);

      expect(mockSetSessionCookieOnRequest).toHaveBeenCalledWith(mockRequest, mockSessionResponse, 'session');
    });

    it('should return a forwarded response that passes the updated request headers to the route handler', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      mockAuthenticatedSession(new Response());

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // NextResponse.next({ request: { headers } }) marks the response with the request headers to forward.
      expect(result.headers.get('x-middleware-override-headers')).toContain('cookie');
      expect(result.headers.get('x-middleware-request-cookie')).toBe(mockRequest.headers.get('cookie'));
    });

    it('should add the session cookies to a redirect previousResponse without forwarding the request', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      const mockSessionResponse = new Response();
      mockAuthenticatedSession(mockSessionResponse);

      const previousResponse = NextResponse.redirect('https://test.com/elsewhere');
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(result).toBe(previousResponse);
      expect(result.status).toBe(307);
      expect(mockCopyResponseHeaders).toHaveBeenCalledTimes(1);
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(mockSessionResponse, previousResponse);
      expect(mockSetSessionCookieOnRequest).not.toHaveBeenCalled();
    });

    it('should not put the session cookie on the request when authentication fails', async () => {
      mockRequest = createRequestWithSession('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);
      mockGetSessionFromRequest.mockResolvedValue({ isAuthenticated: false } as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      expect(mockSetSessionCookieOnRequest).not.toHaveBeenCalled();
    });
  });
});
