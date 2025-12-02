import { NextRequest, NextResponse } from 'next/server';
import { WristbandAuthImpl } from '../../src/auth/wristband-auth-impl';
import { getSessionFromRequest } from '../../src/session';
import {
  isProtectedApi,
  isProtectedPage,
  isValidCsrf,
  normalizeMiddlewareConfig,
  resolveOnPageUnauthenticated,
  copyResponseHeaders,
} from '../../src/utils/middleware';
import { AuthConfig, AuthMiddlewareConfig } from '../../src/types';

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
  };
});

const mockGetSessionFromRequest = getSessionFromRequest as jest.MockedFunction<typeof getSessionFromRequest>;
const mockIsProtectedApi = isProtectedApi as jest.MockedFunction<typeof isProtectedApi>;
const mockIsProtectedPage = isProtectedPage as jest.MockedFunction<typeof isProtectedPage>;
const mockIsValidCsrf = isValidCsrf as jest.MockedFunction<typeof isValidCsrf>;
const mockNormalizeMiddlewareConfig = normalizeMiddlewareConfig as jest.Mock;
const mockResolveOnPageUnauthenticated = resolveOnPageUnauthenticated as jest.Mock;
const mockCopyResponseHeaders = copyResponseHeaders as jest.MockedFunction<typeof copyResponseHeaders>;

const originalConsoleLog = console.log;
const originalConsoleError = console.error;

describe('WristbandAuth Middleware - Chaining', () => {
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
        enableCsrfProtection: false,
      },
      jwtConfig: {},
      protectedPages: mockMiddlewareConfig.protectedPages || [],
      protectedApis: mockMiddlewareConfig.protectedApis || [],
      onPageUnauthenticated: mockOnPageUnauthenticated,
    };
    mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);

    mockResolveOnPageUnauthenticated.mockReturnValue(mockOnPageUnauthenticated);

    mockRequest = new NextRequest('https://test.com/dashboard');

    mockIsProtectedApi.mockReturnValue(false);
    mockIsProtectedPage.mockReturnValue(false);
    mockIsValidCsrf.mockReturnValue(true);

    mockCopyResponseHeaders.mockImplementation((source, target) => {
      return target;
    });
  });

  describe('Unprotected Route Chaining', () => {
    it('should preserve previous response for unprotected routes without modification', async () => {
      mockRequest = new NextRequest('https://test.com/public');
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');
      previousResponse.headers.set('x-timestamp', '1234567890');

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Should return the exact same response object
      expect(result).toBe(previousResponse);

      // Previous headers should be preserved
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
      expect(result.headers.get('x-timestamp')).toBe('1234567890');

      // No auth checks should happen
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();

      // copyResponseHeaders should not be called for unprotected routes
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });
  });

  describe('Protected Route Chaining with SESSION Strategy', () => {
    it('should preserve headers from previous middleware and add session headers', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // Create a previous response with custom headers
      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');
      previousResponse.headers.set('x-timestamp', '1234567890');

      const mockSessionResponse = new Response(null, {
        headers: {
          'set-cookie': 'session=encrypted; Path=/; HttpOnly',
        },
      });

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(mockSessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // Use real copyResponseHeaders implementation
      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Verify previous headers are preserved
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
      expect(result.headers.get('x-timestamp')).toBe('1234567890');

      // Verify session headers are added
      expect(result.headers.get('set-cookie')).toContain('session=encrypted');

      // Should be the same response object (mutated)
      expect(result).toBe(previousResponse);

      // copyResponseHeaders should have been called to merge session headers
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(mockSessionResponse, previousResponse);
    });

    it('should work with multiple middleware in sequence', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // Simulate middleware 01 adding a header
      const middleware01Response = NextResponse.next();
      middleware01Response.headers.set('x-middleware-01', 'value-01');

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(
          new Response(null, {
            headers: { 'set-cookie': 'session=abc; Path=/' },
          })
        ),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);

      // Pass through Wristband middleware
      const wristbandResponse = await middleware(mockRequest, middleware01Response);

      // Simulate middleware 02 adding another header
      const middleware02Response = wristbandResponse;
      middleware02Response.headers.set('x-middleware-02', 'value-02');

      // Verify full chain preserved all headers
      expect(middleware02Response.headers.get('x-middleware-01')).toBe('value-01');
      expect(middleware02Response.headers.get('set-cookie')).toContain('session=abc');
      expect(middleware02Response.headers.get('x-middleware-02')).toBe('value-02');

      // All should be the same response object
      expect(middleware02Response).toBe(middleware01Response);
    });

    it('should preserve previous response headers when auth fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');

      // Session is not authenticated
      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Should get 401 response
      expect(result.status).toBe(401);

      // Previous response headers should still be preserved
      expect(result.headers.get('x-custom-header')).toBe('custom-value');

      // copyResponseHeaders should have been called to merge onto the 401 response
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });

    it('should preserve previous response headers when calling onPageUnauthenticated', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');

      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Should get redirect response from onPageUnauthenticated
      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated'); // ← Added reason parameter

      // Previous headers should be preserved on the redirect response
      expect(result.headers.get('x-custom-header')).toBe('custom-value');

      // copyResponseHeaders should have been called
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });
  });

  describe('No Previous Response', () => {
    it('should work correctly without previous response for protected routes', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSessionResponse = new Response(null, {
        headers: {
          'set-cookie': 'session=encrypted; Path=/; HttpOnly',
        },
      });

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(mockSessionResponse),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest); // No previousResponse

      // Should still work and add session headers
      expect(result.headers.get('set-cookie')).toContain('session=encrypted');

      // copyResponseHeaders should still be called (with session response and new NextResponse)
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(mockSessionResponse, expect.any(NextResponse));
    });

    it('should work correctly without previous response for unprotected routes', async () => {
      mockRequest = new NextRequest('https://test.com/public');
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest); // No previousResponse

      // Should return a new NextResponse.next()
      expect(result).toBeInstanceOf(NextResponse);
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
    });
  });

  describe('Middleware Chaining with Auth Failure Reasons', () => {
    it('should pass not_authenticated reason to onPageUnauthenticated when no session', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-chain-id', '123');

      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated');
    });

    it('should pass csrf_failed reason and preserve previous headers when CSRF validation fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-request-id', 'req-456');

      // Enable CSRF protection in config
      const csrfConfig = {
        ...defaultNormalizedConfig,
        sessionConfig: {
          ...defaultNormalizedConfig.sessionConfig,
          sessionOptions: {
            ...defaultNormalizedConfig.sessionConfig.sessionOptions,
            enableCsrfProtection: true,
          },
        },
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(csrfConfig);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'valid-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockReturnValue(false); // CSRF validation fails

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Should return 403
      expect(result.status).toBe(403);
      const body = await result.json();
      expect(body.error).toBe('Forbidden');

      // Previous headers should be preserved
      expect(result.headers.get('x-request-id')).toBe('req-456');
    });

    it('should pass token_refresh_failed reason and preserve headers when refresh fails', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-tracking-id', 'track-789');

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'expired-refresh-token',
        expiresAt: Date.now() - 1000, // Expired
        accessToken: 'old-token',
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // Mock refreshTokenIfExpired to throw
      const mockRefreshTokenIfExpired = jest.spyOn(wristbandAuth, 'refreshTokenIfExpired' as any);
      mockRefreshTokenIfExpired.mockRejectedValue(new Error('Refresh failed'));

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'token_refresh_failed');

      mockRefreshTokenIfExpired.mockRestore();
    });

    it('should pass unexpected_error reason when session retrieval throws', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-correlation-id', 'corr-999');

      mockGetSessionFromRequest.mockRejectedValue(new Error('Session service crashed'));

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest, previousResponse);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'unexpected_error');
    });
  });
});
