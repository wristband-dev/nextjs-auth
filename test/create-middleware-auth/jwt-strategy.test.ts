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

describe('WristbandAuth Middleware - JWT Strategy', () => {
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

    mockMiddlewareConfig = {
      authStrategies: ['JWT'],
      jwtConfig: {
        jwksCacheMaxSize: 20,
        jwksCacheTtl: 3600000,
      },
      protectedPages: ['/dashboard(.*)'],
      protectedApis: ['/api/v1/.*'],
      onPageUnauthenticated: mockOnPageUnauthenticated,
    };

    wristbandAuth = new WristbandAuthImpl(mockAuthConfig);

    defaultNormalizedConfig = {
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

    // Mock JWT validator
    mockJwtValidator = {
      extractBearerToken: jest.fn(),
      validate: jest.fn(),
    };
    mockCreateWristbandJwtValidator.mockReturnValue(mockJwtValidator);
  });

  describe('JWT Bearer Token Extraction', () => {
    it('should extract bearer token from authorization header', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer test-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('test-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('Bearer test-jwt-token');
    });

    it('should return 401 when bearer token extraction returns null', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'InvalidFormat token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue(null);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('InvalidFormat token');
      expect(result.status).toBe(401);
      expect(mockJwtValidator.validate).not.toHaveBeenCalled();
    });

    it('should return 401 when authorization header is missing', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      // No auth header means extractBearerToken is never called
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(result.status).toBe(401);
    });
  });

  describe('JWT Validation', () => {
    it('should validate JWT token successfully', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockJwtValidator.validate).toHaveBeenCalledWith('valid-jwt-token');
      expect(result.status).not.toBe(401);
    });

    it('should return 401 when JWT validation fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({
        isValid: false,
        errorMessage: 'Token expired',
      });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
    });

    it('should handle unexpected JWT validation errors', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer malformed-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('malformed-jwt-token');
      mockJwtValidator.validate.mockRejectedValue(new Error('JWT malformed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(500);
    });
  });

  describe('JWT-Only Strategy Configuration', () => {
    it('should not attempt session retrieval when using JWT-only strategy', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
    });

    it('should create JWT validator with custom config', async () => {
      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
        jwtConfig: {
          jwksCacheMaxSize: 50,
          jwksCacheTtl: 7200000,
        },
        protectedApis: ['/api/v1/.*'],
      };

      mockNormalizeMiddlewareConfig.mockReturnValue({
        ...defaultNormalizedConfig,
        jwtConfig: {
          jwksCacheMaxSize: 50,
          jwksCacheTtl: 7200000,
        },
      });

      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(customConfig);
      await middleware(mockRequest);

      expect(mockCreateWristbandJwtValidator).toHaveBeenCalledWith({
        wristbandApplicationVanityDomain: 'test.wristband.dev',
        jwksCacheMaxSize: 50,
        jwksCacheTtl: 7200000,
      });
    });

    it('should lazy load JWT validator only when JWT strategy is used', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);

      // JWT validator should not be created until first request
      expect(mockCreateWristbandJwtValidator).not.toHaveBeenCalled();

      await middleware(mockRequest);

      // Now it should be created
      expect(mockCreateWristbandJwtValidator).toHaveBeenCalledTimes(1);

      // Second request should reuse the same validator
      await middleware(mockRequest);
      expect(mockCreateWristbandJwtValidator).toHaveBeenCalledTimes(1);
    });
  });

  describe('No Session Saving with JWT', () => {
    it('should not save session when JWT authentication succeeds', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockGetSessionFromRequest).not.toHaveBeenCalled();
      expect(result).toBeInstanceOf(NextResponse);
    });

    it('should not call session saveToResponse when using JWT auth', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const mockSession = {
        isAuthenticated: true,
        saveToResponse: jest.fn(),
      };
      mockGetSessionFromRequest.mockResolvedValue(mockSession as any);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockSession.saveToResponse).not.toHaveBeenCalled();
    });
  });

  describe('JWT Authentication for Protected Routes', () => {
    it('should allow JWT-authenticated requests to protected API routes', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).not.toBe(401);
    });

    it('should allow JWT-authenticated requests to protected page routes', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard/profile', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedPage.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).not.toBe(401);
    });

    it('should call onPageUnauthenticated for unauthenticated page requests with JWT strategy', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated'); // ← Added reason parameter
      expect(result).toEqual(NextResponse.redirect('https://test.com/login'));
    });
  });

  describe('JWT with Middleware Chaining', () => {
    it('should preserve headers from previous middleware when JWT auth succeeds', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer valid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true });

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Previous headers should be preserved
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
      // But no session cookies should be added since JWT doesn't use sessions
      expect(result.headers.get('set-cookie')).toBeNull();
      // Should return the same response object
      expect(result).toBe(previousResponse);
    });

    it('should preserve headers from previous middleware when JWT auth fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-jwt-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-jwt-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, errorMessage: 'Invalid token' });

      const previousResponse = NextResponse.next();
      previousResponse.headers.set('x-custom-header', 'custom-value');

      const { copyResponseHeaders: realCopyResponseHeaders } = jest.requireActual('../../src/utils/middleware');
      mockCopyResponseHeaders.mockImplementation(realCopyResponseHeaders);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest, previousResponse);

      // Should get 401 response
      expect(result.status).toBe(401);
      // Previous headers should still be preserved
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
      // copyResponseHeaders should have been called
      expect(mockCopyResponseHeaders).toHaveBeenCalledWith(previousResponse, expect.any(NextResponse));
    });
  });

  describe('JWT Authentication Error Reasons', () => {
    it('should return 401 with not_authenticated reason when no auth header', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users');
      mockIsProtectedApi.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should return 401 with not_authenticated reason when JWT validation fails', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer invalid-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false });

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(401);
      const body = await result.json();
      expect(body.error).toBe('Unauthorized');
    });

    it('should return 500 with unexpected_error reason when JWT validation throws', async () => {
      mockRequest = new NextRequest('https://test.com/api/v1/users', {
        headers: { Authorization: 'Bearer malformed-token' },
      });
      mockIsProtectedApi.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('malformed-token');
      mockJwtValidator.validate.mockRejectedValue(new Error('JWT service down'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      const result = await middleware(mockRequest);

      expect(result.status).toBe(500);
      const body = await result.json();
      expect(body.error).toBe('Internal Server Error');
    });

    it('should pass not_authenticated reason to onPageUnauthenticated for missing auth header', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard');
      mockIsProtectedPage.mockReturnValue(true);

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'not_authenticated');
    });

    it('should pass unexpected_error reason to onPageUnauthenticated when JWT validator throws', async () => {
      mockRequest = new NextRequest('https://test.com/dashboard', {
        headers: { Authorization: 'Bearer bad-token' },
      });
      mockIsProtectedPage.mockReturnValue(true);
      mockJwtValidator.extractBearerToken.mockReturnValue('bad-token');
      mockJwtValidator.validate.mockRejectedValue(new Error('Validator crashed'));

      const middleware = wristbandAuth.createMiddlewareAuth(mockMiddlewareConfig);
      await middleware(mockRequest);

      expect(mockOnPageUnauthenticated).toHaveBeenCalledWith(mockRequest, 'unexpected_error');
    });
  });
});
