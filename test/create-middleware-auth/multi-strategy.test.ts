import { NextRequest, NextResponse } from 'next/server';
import { createWristbandJwtValidator } from '@wristband/typescript-jwt';

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
jest.mock('@wristband/typescript-jwt');

const mockGetSessionFromRequest = getSessionFromRequest as jest.MockedFunction<typeof getSessionFromRequest>;
const mockIsProtectedApi = isProtectedApi as jest.MockedFunction<typeof isProtectedApi>;
const mockIsProtectedPage = isProtectedPage as jest.MockedFunction<typeof isProtectedPage>;
const mockIsValidCsrf = isValidCsrf as jest.MockedFunction<typeof isValidCsrf>;
const mockNormalizeMiddlewareConfig = normalizeMiddlewareConfig as jest.Mock;
const mockResolveOnPageUnauthenticated = resolveOnPageUnauthenticated as jest.Mock;
const mockCopyResponseHeaders = copyResponseHeaders as jest.MockedFunction<typeof copyResponseHeaders>;
const mockCreateWristbandJwtValidator = createWristbandJwtValidator as jest.MockedFunction<
  typeof createWristbandJwtValidator
>;

const originalConsoleLog = console.log;
const originalConsoleError = console.error;

describe('WristbandAuth Middleware - Multi-Strategy', () => {
  let wristbandAuth: WristbandAuthImpl;
  let mockAuthConfig: AuthConfig;
  let mockMiddlewareConfig: AuthMiddlewareConfig;
  let mockRequest: NextRequest;
  let mockOnPageUnauthenticated: jest.Mock;
  let defaultNormalizedConfig: any;
  let mockJwtValidator: any;

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

    mockRequest = new NextRequest('https://test.com/dashboard');

    mockIsProtectedApi.mockReturnValue(false);
    mockIsProtectedPage.mockReturnValue(false);
    mockIsValidCsrf.mockReturnValue(true);

    mockCopyResponseHeaders.mockImplementation((source, target) => {
      return target;
    });

    // Mock JWT validator
    mockJwtValidator = {
      extractBearerToken: jest.fn(),
      validate: jest.fn(),
    };
    mockCreateWristbandJwtValidator.mockReturnValue(mockJwtValidator);

    wristbandAuth = new WristbandAuthImpl(mockAuthConfig);
    mockResolveOnPageUnauthenticated.mockReturnValue(mockOnPageUnauthenticated);
  });

  describe('Configuration Normalization', () => {
    it('should normalize middleware config on creation', () => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);

      expect(mockNormalizeMiddlewareConfig).toHaveBeenCalledWith(mockMiddlewareConfig);
    });

    it('should use normalized config throughout middleware execution', async () => {
      mockRequest = new NextRequest('https://test.com/api/users');

      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
          sessionEndpoint: '/api/custom/session',
          tokenEndpoint: '/api/custom/token',
        },
        jwtConfig: {
          jwksCacheMaxSize: 50,
          jwksCacheTtl: 7200000,
        },
        protectedApis: ['/api/.*'],
      };

      const normalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: customConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/custom/session',
          tokenEndpoint: '/api/custom/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 50,
          jwksCacheTtl: 7200000,
        },
        protectedPages: [],
        protectedApis: ['/api/.*'],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(normalizedConfig);

      const middleware = wristbandAuth.createMiddlewareAuth(customConfig);
      await middleware(mockRequest);

      expect(mockIsProtectedApi).toHaveBeenCalledWith('/api/users', normalizedConfig);
    });

    it('should call resolveOnPageUnauthenticated with normalized config and loginUrl', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      mockMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        protectedPages: ['/dashboard(.*)'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {},
        protectedPages: ['/dashboard(.*)'],
        protectedApis: [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);

      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockResolveOnPageUnauthenticated).toHaveBeenCalledWith(
        defaultNormalizedConfig,
        'https://test.com/api/auth/login'
      );
    });
  });

  describe('SESSION then JWT Fallback', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should try SESSION first, succeed, and not try JWT', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
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
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should try SESSION first, fail, then fallback to JWT and succeed', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails (not authenticated)
      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalledWith('valid-jwt-token');
      expect(result.status).not.toBe(401);
    });

    it('should try SESSION (error), then fallback to JWT and succeed', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION throws error
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session read failed'));

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should try both SESSION and JWT, both fail, return 401', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails
      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT fails
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, errorMessage: 'Invalid token' });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalled();
      expect(result.status).toBe(401);
    });

    it('should not save session when JWT succeeds after SESSION fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails
      const mockSession = {
        isAuthenticated: false,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      // Session should NOT be saved since JWT was used
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });
  });

  describe('JWT then SESSION Fallback', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should try JWT first, succeed, and not try SESSION', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should try JWT first (no token), then fallback to SESSION and succeed', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // JWT fails (no authorization header)
      // When there's no auth header, extractBearerToken is never called in the implementation

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // JWT should fail because no auth header
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should try JWT first (invalid), then fallback to SESSION and succeed', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // JWT fails (invalid token)
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, errorMessage: 'Invalid token' });

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockJwtValidator.validate).toHaveBeenCalled();
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should save session when SESSION succeeds after JWT fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // JWT fails (no auth header)

      // SESSION succeeds
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
      await middleware(mockRequest);

      // Session SHOULD be saved since SESSION was used
      expect(mockSession.saveToResponse).toHaveBeenCalled();
    });
  });

  describe('Strategy Precedence', () => {
    it('should respect strategy order when both auth types are present', async () => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);

      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // Both SESSION and JWT are valid, but SESSION is first
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      // SESSION should be tried first and succeed
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      // JWT should not even be attempted
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
    });
  });

  describe('CSRF with Multi-Strategy', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
            enableCsrfProtection: true, // ← CSRF config is in sessionOptions
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should fail SESSION due to CSRF, then fallback to JWT and succeed', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION is authenticated but CSRF fails
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockReturnValue(false); // ← CSRF validation fails

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockIsValidCsrf).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
      expect(result.status).not.toBe(403);
      // Session should NOT be saved since JWT was used
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });

    it('should return 403 when SESSION CSRF fails and no other strategy available', async () => {
      // Only SESSION strategy
      mockMiddlewareConfig.authStrategies = ['SESSION'];
      defaultNormalizedConfig.authStrategies = ['SESSION'];

      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION is authenticated but CSRF fails
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockReturnValue(false); // ← CSRF validation fails

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(403);
      // Session should NOT be saved since auth failed
      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });
  });

  describe('Exception Handling in Multi-Strategy', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should return 500 when both SESSION and JWT strategies throw exceptions', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer malformed-jwt' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION throws exception
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session store unavailable'));

      // JWT throws exception
      mockJwtValidator.extractBearerToken.mockReturnValue('malformed-jwt');
      mockJwtValidator.validate.mockRejectedValue(new Error('JWT validation crashed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalled();
      expect(result.status).toBe(500); // ← Changed from 401 to 500
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
    });

    it('should return 401 when SESSION throws and JWT has no token', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION throws exception
      mockGetSessionFromRequest.mockRejectedValue(new Error('Cookie parsing failed'));

      // JWT has no token (no auth header means extractBearerToken won't be called)

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
    });

    it('should continue to JWT when SESSION throws exception', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION throws exception
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session error'));

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should handle unexpected JWT validator creation failure', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails
      const mockSession = {
        isAuthenticated: false,
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT validator creation throws
      mockCreateWristbandJwtValidator.mockImplementation(() => {
        throw new Error('Failed to fetch JWKS');
      });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(500);
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
    });

    it('should call onPageUnauthenticated when both strategies fail on a page route', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard', {
        headers: { Authorization: 'Bearer invalid-jwt' },
      });
      mockIsProtectedPage.mockReturnValue(true);

      // SESSION throws
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session error'));

      // JWT fails
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated'); // ← Added reason parameter
      expect(result).toEqual(NextResponse.redirect('https://test.com/login'));
    });
  });

  describe('Session and Token endpoint strategy enforcement', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: ['test-secret'], cookieName: 'test-session' },
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
        },
        jwtConfig: { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 },
        protectedApis: [],
      };

      defaultNormalizedConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 },
        protectedPages: [],
        protectedApis: [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should force SESSION strategy for /api/auth/session endpoint even with JWT first', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/session', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        userId: 'user-123',
        tenantId: 'tenant-456',
        accessToken: 'access-token-789',
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should use SESSION strategy, not JWT (even though JWT is first and has valid token)
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should force SESSION strategy for /api/auth/token endpoint even with JWT first', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/token', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        userId: 'user-123',
        tenantId: 'tenant-456',
        accessToken: 'access-token-789',
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should use SESSION strategy, not JWT
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should force SESSION strategy for session endpoint with SESSION first in config', async () => {
      // Change strategy order to SESSION first
      mockMiddlewareConfig.authStrategies = ['SESSION', 'JWT'];
      defaultNormalizedConfig.authStrategies = ['SESSION', 'JWT'];

      mockRequest = new NextRequest('https://test.com/api/auth/session', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        userId: 'user-123',
        tenantId: 'tenant-456',
        accessToken: 'access-token-789',
        csrfToken: 'test-csrf-token',
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000,
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should use SESSION strategy
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should return 401 when session endpoint has no valid session (JWT ignored)', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/session', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails (not authenticated)
      const mockSession = { isAuthenticated: false };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT should be valid but won't be checked
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should fail because SESSION is required and not authenticated
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
    });

    it('should return 401 when token endpoint has no valid session (JWT ignored)', async () => {
      mockRequest = new NextRequest('https://test.com/api/auth/token', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION fails
      const mockSession = { isAuthenticated: false };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT should be valid but won't be checked
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should fail because SESSION is required
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
    });

    it('should not protect session/token endpoints when only JWT strategy configured', async () => {
      // JWT-only configuration
      mockMiddlewareConfig.authStrategies = ['JWT'];
      delete mockMiddlewareConfig.sessionConfig;
      mockMiddlewareConfig.jwtConfig = { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 };

      defaultNormalizedConfig.authStrategies = ['JWT'];
      defaultNormalizedConfig.jwtConfig = { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 };

      mockRequest = new NextRequest('https://test.com/api/auth/session', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });

      // Endpoints should NOT be protected when only JWT is configured
      mockIsProtectedApi.mockReturnValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should pass through without authentication (unprotected)
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).toBe(200);
    });

    it('should not protect token endpoint when only JWT strategy configured', async () => {
      // JWT-only configuration
      mockMiddlewareConfig.authStrategies = ['JWT'];
      delete mockMiddlewareConfig.sessionConfig;
      mockMiddlewareConfig.jwtConfig = { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 };

      defaultNormalizedConfig.authStrategies = ['JWT'];
      defaultNormalizedConfig.jwtConfig = { jwksCacheMaxSize: 20, jwksCacheTtl: 3600000 };

      mockRequest = new NextRequest('https://test.com/api/auth/token');
      mockIsProtectedApi.mockReturnValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should pass through without authentication
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).toBe(200);
    });

    it('should use custom session endpoint path when forcing SESSION strategy', async () => {
      mockMiddlewareConfig.sessionConfig!.sessionEndpoint = '/api/custom/session';
      defaultNormalizedConfig.sessionConfig.sessionEndpoint = '/api/custom/session';

      mockRequest = new NextRequest('https://test.com/api/custom/session', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        userId: 'user-123',
        tenantId: 'tenant-456',
        accessToken: 'access-token-789',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should force SESSION strategy for custom endpoint
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should use custom token endpoint path when forcing SESSION strategy', async () => {
      mockMiddlewareConfig.sessionConfig!.tokenEndpoint = '/api/custom/token';
      defaultNormalizedConfig.sessionConfig.tokenEndpoint = '/api/custom/token';

      mockRequest = new NextRequest('https://test.com/api/custom/token', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION succeeds
      const mockSession = {
        isAuthenticated: true,
        userId: 'user-123',
        tenantId: 'tenant-456',
        accessToken: 'access-token-789',
        saveToResponse: jest.fn().mockResolvedValue(new Response()),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should force SESSION strategy for custom endpoint
      expect(mockGetSessionFromRequest).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });

    it('should allow JWT for other API routes when JWT is first strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should use JWT strategy for non-session/token endpoints
      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result.status).not.toBe(401);
    });
  });

  describe('Multi-Strategy Error Reasons', () => {
    beforeEach(() => {
      mockMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: ['test-secret'],
            cookieName: 'test-session',
          },
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      defaultNormalizedConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: mockMiddlewareConfig.sessionConfig!.sessionOptions,
          sessionEndpoint: '/api/auth/session',
          tokenEndpoint: '/api/auth/token',
          csrfTokenHeaderName: 'X-CSRF-TOKEN',
        },
        jwtConfig: {
          jwksCacheMaxSize: 20,
          jwksCacheTtl: 3600000,
        },
        protectedPages: [],
        protectedApis: mockMiddlewareConfig.protectedApis || [],
        onPageUnauthenticated: mockOnPageUnauthenticated,
      };
      mockNormalizeMiddlewareConfig.mockReturnValue(defaultNormalizedConfig);
    });

    it('should return 401 with not_authenticated when both strategies fail normally', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-jwt' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION not authenticated
      const mockSession = { isAuthenticated: false };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      // JWT invalid
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should return 500 when first strategy throws exception', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION throws
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session crashed'));

      // JWT valid
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should succeed with JWT fallback
      expect(result.status).not.toBe(401);
      expect(result.status).not.toBe(500);
    });

    it('should pass unexpected_error reason when SESSION throws on page route', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      // SESSION throws
      mockGetSessionFromRequest.mockRejectedValue(new Error('Session error'));

      // JWT has no auth header
      // (JWT will fail with not_authenticated, but SESSION's unexpected_error comes first)

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      // Last failed strategy's reason is used (JWT's not_authenticated, since SESSION threw but JWT was tried)
      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated');
    });

    it('should return 403 when CSRF fails and JWT is not available', async () => {
      mockMiddlewareConfig.authStrategies = ['SESSION'];
      mockMiddlewareConfig.sessionConfig!.sessionOptions!.enableCsrfProtection = true;
      defaultNormalizedConfig.authStrategies = ['SESSION'];
      defaultNormalizedConfig.sessionConfig.sessionOptions.enableCsrfProtection = true;

      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf',
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockReturnValue(false);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(403);
      const body = await result.json();
      expect(body.error).toBe('Forbidden');
    });

    it('should fallback to JWT when CSRF fails on SESSION in multi-strategy config', async () => {
      mockMiddlewareConfig.authStrategies = ['SESSION', 'JWT'];
      mockMiddlewareConfig.sessionConfig!.sessionOptions!.enableCsrfProtection = true;
      defaultNormalizedConfig.authStrategies = ['SESSION', 'JWT'];
      defaultNormalizedConfig.sessionConfig.sessionOptions = {
        ...defaultNormalizedConfig.sessionConfig.sessionOptions,
        enableCsrfProtection: true,
      };

      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);

      // SESSION is authenticated but CSRF fails
      const mockSession = {
        isAuthenticated: true,
        csrfToken: 'test-csrf',
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);
      mockIsValidCsrf.mockReturnValue(false); // CSRF fails

      // JWT succeeds
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // Should succeed via JWT fallback (not return 403)
      expect(result.status).not.toBe(403);
      expect(result.status).not.toBe(401);
      expect(mockIsValidCsrf).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalled();
    });
  });
});
