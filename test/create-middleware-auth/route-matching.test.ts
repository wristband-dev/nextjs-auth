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

describe('WristbandAuth Middleware - Route Matching', () => {
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

  describe('Route Matching', () => {
    it('should allow unprotected routes to continue without checking session (no previous response)', async () => {
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false);
      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockIsProtectedApi).toHaveBeenCalledWith('/dashboard', expect.any(Object));
      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(mockResolveOnPageUnauthenticated).not.toHaveBeenCalled();
      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should allow unprotected routes and preserve previous response headers', async () => {
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false);

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      expect(mockCopyResponseHeaders).not.toHaveBeenCalled();
      expect(result).toBe(previousResponse);
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
    });

    it('should identify protected API routes', async () => {
      mockRequest = new NextRequest('https://test.com/api/users');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(false);

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

      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/users', expect.any(Object));
    });

    it('should identify protected page routes', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard/settings');
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(true);

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

      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
    });

    it('should handle routes that are both API and page protected', async () => {
      mockRequest = new NextRequest('https://test.com/api/dashboard');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(true);

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

      expect(mockIsProtectedApi).toHaveBeenCalled();
      expect(mockIsProtectedPage).toHaveBeenCalled();
    });
  });

  describe('Server Action Bypass', () => {
    it('should NOT protect Server Actions (POST with next-action header)', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard', {
        method: 'POST',
        headers: { 'next-action': 'abc123' },
      });
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false); // Should NOT be protected due to Server Action

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Verify isProtectedPage was called and returned false (Server Action bypass)
      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      // Verify session was NOT checked (unprotected route behavior)
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      // Route should pass through
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should protect regular POST to protected pages without next-action header', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard', {
        method: 'POST',
        // No next-action header
      });
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(true); // SHOULD be protected (regular POST)

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

      // Verify isProtectedPage identified it as protected
      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      // Verify session was checked (protected route behavior)
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should protect GET requests to protected pages (Server Actions are POST-only)', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard', {
        method: 'GET',
        headers: { 'next-action': 'abc123' }, // next-action header should be ignored for GET
      });
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(true); // SHOULD be protected (GET request)

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

      // Verify isProtectedPage identified it as protected (GET with next-action doesn't bypass)
      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      // Verify session was checked
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should require BOTH POST method AND next-action header for Server Action bypass', async () => {
      // Test 1: POST without next-action header
      mockRequest = new NextRequest('https://test.com/dashboard', {
        method: 'POST',
      });
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(true); // Should be protected

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

      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should allow Server Actions on protected pages to handle their own auth', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard/profile', {
        method: 'POST',
        headers: { 'next-action': 'updateProfile' },
      });
      mockIsProtectedApi.mockReturnValue(false);
      mockIsProtectedPage.mockReturnValue(false); // Bypass due to Server Action

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Server Action should bypass middleware auth
      expect(mockIsProtectedPage).toHaveBeenCalledWith(mockRequest, expect.any(Object));
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result).toBeInstanceOf(NextResponse);
    });
  });

  describe('Session/Token Endpoint Auto-Protection', () => {
    it('should protect session endpoint when using SESSION strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/session');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(false);

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

      // Verify that isProtectedApi identifies session endpoint as protected
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/auth/session', expect.any(Object));
      // Verify session auth was checked (protected route behavior)
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should protect token endpoint when using SESSION strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/token');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(false);

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

      // Verify that isProtectedApi identifies token endpoint as protected
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/auth/token', expect.any(Object));
      // Verify session auth was checked (protected route behavior)
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should NOT protect session endpoint when using JWT-only strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/session');
      mockIsProtectedApi.mockReturnValue(false); // Not protected with JWT-only
      mockIsProtectedPage.mockReturnValue(false);

      // Use JWT-only strategy
      const jwtOnlyConfig: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      const jwtOnlyNormalizedConfig = {
        authStrategies: ['JWT'],
        sessionConfig: {
          sessionOptions: undefined,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
          enableCsrfProtection: false,
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: ['/api/v1/.*'],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(jwtOnlyNormalizedConfig);

      const middleware = wristbandAuth.createMiddlewareAuth(jwtOnlyConfig);
      const result = await middleware(mockRequest);

      // Verify that isProtectedApi was called and returned false
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/auth/session', jwtOnlyNormalizedConfig);
      // Verify session was NOT checked (unprotected route behavior)
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      // Route should pass through
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should NOT protect token endpoint when using JWT-only strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/token');
      mockIsProtectedApi.mockReturnValue(false); // Not protected with JWT-only
      mockIsProtectedPage.mockReturnValue(false);

      // Use JWT-only strategy
      const jwtOnlyConfig: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      const jwtOnlyNormalizedConfig = {
        authStrategies: ['JWT'],
        sessionConfig: {
          sessionOptions: undefined,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
          enableCsrfProtection: false,
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: ['/api/v1/.*'],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(jwtOnlyNormalizedConfig);

      const middleware = wristbandAuth.createMiddlewareAuth(jwtOnlyConfig);
      const result = await middleware(mockRequest);

      // Verify that isProtectedApi was called and returned false
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/auth/token', jwtOnlyNormalizedConfig);
      // Verify session was NOT checked (unprotected route behavior)
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      // Route should pass through
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should protect custom session endpoint path when configured', async () => {
      mockRequest = new NextRequest('https://test.com/api/custom/session');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(false);

      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
          sessionEndpoint: '/api/custom/session',
        },
        protectedApis: ['/api/v1/.*'],
      };

      const customNormalizedConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: customConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/custom/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
          enableCsrfProtection: false,
        },
        jwtConfig: {},
        protectedPages: [],
        protectedApis: ['/api/v1/.*'],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(customNormalizedConfig);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(customConfig);
      await middleware(mockRequest);

      // Verify custom session endpoint is protected
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/custom/session', customNormalizedConfig);
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });

    it('should protect custom token endpoint path when configured', async () => {
      mockRequest = new NextRequest('https://test.com/api/custom/token');
      mockIsProtectedApi.mockReturnValue(true);
      mockIsProtectedPage.mockReturnValue(false);

      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
          tokenEndpoint: '/api/custom/token',
        },
        protectedApis: ['/api/v1/.*'],
      };

      const customNormalizedConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: customConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/custom/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
          enableCsrfProtection: false,
        },
        jwtConfig: {},
        protectedPages: [],
        protectedApis: ['/api/v1/.*'],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(customNormalizedConfig);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(customConfig);
      await middleware(mockRequest);

      // Verify custom token endpoint is protected
      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/custom/token', customNormalizedConfig);
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
    });
  });
});
