import { NextRequest, NextResponse } from 'next/server';
import { SessionOptions } from '@wristband/typescript-session';
import {
  normalizeMiddlewareConfig,
  createRouteMatcher,
  isProtectedApi,
  isProtectedPage,
  isValidCsrf,
  copyResponseHeaders,
  resolveOnPageUnauthenticated,
} from '../../src/utils/middleware';
import { AuthMiddlewareConfig, AuthStrategy } from '../../src/types';

describe('middleware-utils', () => {
  describe('normalizeMiddlewareConfig', () => {
    const minimalConfig: AuthMiddlewareConfig = {
      authStrategies: [AuthStrategy.SESSION],
      sessionConfig: {
        sessionOptions: {
          secrets: 'test-secret-must-be-at-least-32-characters-long',
        },
      },
    };

    it('should apply default values for all optional fields', () => {
      const result = normalizeMiddlewareConfig(minimalConfig);

      expect(result.authStrategies).toEqual([AuthStrategy.SESSION]);
      expect(result.protectedApis).toEqual([]);
      expect(result.protectedPages).toEqual([]);
      expect(result.sessionConfig.sessionEndpoint).toBe('/api/auth/session');
      expect(result.sessionConfig.tokenEndpoint).toBe('/api/auth/token');
      expect(result.sessionConfig.csrfTokenHeaderName).toBe('X-CSRF-TOKEN');
      expect(result.jwtConfig).toEqual({ jwksCacheMaxSize: undefined, jwksCacheTtl: undefined });
    });

    it('should preserve user-provided values over defaults', () => {
      const customConfig: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.SESSION, AuthStrategy.JWT],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret-must-be-at-least-32-characters-long',
            enableCsrfProtection: true, // ← CSRF config moved to sessionOptions
          },
          sessionEndpoint: '/custom/session',
          tokenEndpoint: '/custom/token',
          csrfTokenHeaderName: 'CUSTOM-CSRF',
        },
        jwtConfig: {
          jwksCacheMaxSize: 50,
          jwksCacheTtl: 7200000,
        },
        protectedApis: ['/api/custom(.*)'],
        protectedPages: ['/dashboard(.*)'],
      };

      const result = normalizeMiddlewareConfig(customConfig);

      expect(result.authStrategies).toEqual([AuthStrategy.SESSION, AuthStrategy.JWT]);
      expect(result.protectedApis).toEqual(['/api/custom(.*)']);
      expect(result.protectedPages).toEqual(['/dashboard(.*)']);
      expect(result.sessionConfig.sessionEndpoint).toBe('/custom/session');
      expect(result.sessionConfig.tokenEndpoint).toBe('/custom/token');
      expect(result.sessionConfig.csrfTokenHeaderName).toBe('CUSTOM-CSRF');
      expect(result.jwtConfig.jwksCacheMaxSize).toBe(50);
      expect(result.jwtConfig.jwksCacheTtl).toBe(7200000);
    });

    it('should preserve sessionOptions unchanged', () => {
      const sessionOptions: SessionOptions = {
        secrets: 'test-secret-must-be-at-least-32-characters-long',
        cookieName: 'custom-session',
        maxAge: 7200,
      };

      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions,
        },
      };

      const result = normalizeMiddlewareConfig(config);

      expect(result.sessionConfig.sessionOptions).toBe(sessionOptions);
    });

    it('should preserve onPageUnauthenticated callback', () => {
      const callback = jest.fn();
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        onPageUnauthenticated: callback,
      };

      const result = normalizeMiddlewareConfig(config);

      expect(result.onPageUnauthenticated).toBe(callback);
    });

    it('should handle CSRF enabled in sessionOptions', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret-must-be-at-least-32-characters-long',
            enableCsrfProtection: true, // ← Now in sessionOptions
          },
        },
      };

      const result = normalizeMiddlewareConfig(config);

      // CSRF is enabled via sessionOptions, not sessionConfig
      expect(result.sessionConfig.sessionOptions?.enableCsrfProtection).toBe(true);
    });

    it('should handle CSRF disabled in sessionOptions', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret-must-be-at-least-32-characters-long',
            enableCsrfProtection: false, // ← Explicit false
          },
        },
      };

      const result = normalizeMiddlewareConfig(config);

      expect(result.sessionConfig.sessionOptions?.enableCsrfProtection).toBe(false);
    });

    it('should handle JWT-only strategy', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.JWT],
        jwtConfig: {
          jwksCacheMaxSize: 30,
          jwksCacheTtl: 3600000,
        },
      };

      const result = normalizeMiddlewareConfig(config);

      expect(result.authStrategies).toEqual([AuthStrategy.JWT]);
      expect(result.sessionConfig.sessionOptions).toBeUndefined();
      expect(result.jwtConfig.jwksCacheMaxSize).toBe(30);
      expect(result.jwtConfig.jwksCacheTtl).toBe(3600000);
    });

    it('should set sessionOptions to undefined when SESSION strategy is not used', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.JWT],
      };

      const result = normalizeMiddlewareConfig(config);

      expect(result.sessionConfig.sessionOptions).toBeUndefined();
    });
  });

  describe('validateMiddlewareConfig', () => {
    it('should throw when authStrategies is empty', () => {
      const config: any = {
        authStrategies: [],
      };

      expect(() => {
        return normalizeMiddlewareConfig(config);
      }).toThrow('authStrategies must contain at least one AuthStrategy');
    });

    it('should throw when authStrategies is missing', () => {
      const config: any = {};

      expect(() => {
        return normalizeMiddlewareConfig(config);
      }).toThrow('authStrategies must contain at least one AuthStrategy');
    });

    it('should throw when SESSION strategy is used without sessionConfig', () => {
      const config: any = {
        authStrategies: [AuthStrategy.SESSION],
      };

      expect(() => {
        return normalizeMiddlewareConfig(config);
      }).toThrow('sessionConfig is required when using AuthStrategy.SESSION');
    });

    it('should throw when SESSION strategy is used without sessionOptions', () => {
      const config: any = {
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {},
      };

      expect(() => {
        return normalizeMiddlewareConfig(config);
      }).toThrow('sessionConfig.sessionOptions is required when using AuthStrategy.SESSION');
    });

    it('should not throw when JWT strategy is used without sessionConfig', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [AuthStrategy.JWT],
      };

      expect(() => {
        return normalizeMiddlewareConfig(config);
      }).not.toThrow();
    });
  });

  describe('createRouteMatcher', () => {
    it('should match exact paths', () => {
      const matcher = createRouteMatcher(['/api/users', '/settings']);

      expect(matcher('/api/users')).toBe(true);
      expect(matcher('/settings')).toBe(true);
      expect(matcher('/api/posts')).toBe(false);
    });

    it('should match wildcard patterns', () => {
      const matcher = createRouteMatcher(['/dashboard(.*)']);

      expect(matcher('/dashboard')).toBe(true);
      expect(matcher('/dashboard/profile')).toBe(true);
      expect(matcher('/dashboard/settings/security')).toBe(true);
      expect(matcher('/home')).toBe(false);
    });

    it('should match named parameters', () => {
      const matcher = createRouteMatcher(['/api/users/:id', '/posts/:slug/comments']);

      expect(matcher('/api/users/123')).toBe(true);
      expect(matcher('/api/users/abc')).toBe(true);
      expect(matcher('/posts/my-post/comments')).toBe(true);
      expect(matcher('/api/users')).toBe(false);
      expect(matcher('/api/users/123/extra')).toBe(false);
    });

    it('should match regex patterns', () => {
      const matcher = createRouteMatcher(['/api/(?!auth/(login|callback|logout)).*']);

      expect(matcher('/api/users')).toBe(true);
      expect(matcher('/api/posts')).toBe(true);
      expect(matcher('/api/auth/profile')).toBe(true);
      expect(matcher('/api/auth/login')).toBe(false);
      expect(matcher('/api/auth/callback')).toBe(false);
      expect(matcher('/api/auth/logout')).toBe(false);
    });

    it('should return false for empty pattern array', () => {
      const matcher = createRouteMatcher([]);

      expect(matcher('/any/path')).toBe(false);
    });

    it('should match multiple patterns', () => {
      const matcher = createRouteMatcher(['/dashboard(.*)', '/settings', '/api/users/:id']);

      expect(matcher('/dashboard')).toBe(true);
      expect(matcher('/dashboard/profile')).toBe(true);
      expect(matcher('/settings')).toBe(true);
      expect(matcher('/api/users/123')).toBe(true);
      expect(matcher('/home')).toBe(false);
    });

    it('should handle patterns with multiple named parameters', () => {
      const matcher = createRouteMatcher(['/api/:version/users/:id']);

      expect(matcher('/api/v1/users/123')).toBe(true);
      expect(matcher('/api/v2/users/abc')).toBe(true);
      expect(matcher('/api/users/123')).toBe(false);
    });
  });

  describe('isProtectedApi', () => {
    const sessionConfig = normalizeMiddlewareConfig({
      authStrategies: [AuthStrategy.SESSION],
      sessionConfig: {
        sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
      },
    });

    it('should protect session endpoint when using SESSION strategy', () => {
      expect(isProtectedApi('/api/auth/session', sessionConfig)).toBe(true);
    });

    it('should protect token endpoint when using SESSION strategy', () => {
      expect(isProtectedApi('/api/auth/token', sessionConfig)).toBe(true);
    });

    it('should NOT protect session endpoint when using JWT-only strategy', () => {
      const jwtOnlyConfig = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.JWT],
      });

      expect(isProtectedApi('/api/auth/session', jwtOnlyConfig)).toBe(false);
      expect(isProtectedApi('/api/auth/token', jwtOnlyConfig)).toBe(false);
    });

    it('should protect session endpoint when SESSION is one of multiple strategies', () => {
      const multiStrategyConfig = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.JWT, AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      expect(isProtectedApi('/api/auth/session', multiStrategyConfig)).toBe(true);
      expect(isProtectedApi('/api/auth/token', multiStrategyConfig)).toBe(true);
    });

    it('should not protect auth login, callback, and logout endpoints', () => {
      expect(isProtectedApi('/api/auth/login', sessionConfig)).toBe(false);
      expect(isProtectedApi('/api/auth/callback', sessionConfig)).toBe(false);
      expect(isProtectedApi('/api/auth/logout', sessionConfig)).toBe(false);
    });

    it('should not protect non-API routes', () => {
      expect(isProtectedApi('/dashboard', sessionConfig)).toBe(false);
      expect(isProtectedApi('/home', sessionConfig)).toBe(false);
    });

    it('should work with custom protectedApis patterns', () => {
      const customConfig = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedApis: ['/api/admin(.*)'],
      });

      expect(isProtectedApi('/api/admin/users', customConfig)).toBe(true);
      expect(isProtectedApi('/api/users', customConfig)).toBe(false);
      // Session and token endpoints are still protected
      expect(isProtectedApi('/api/auth/session', customConfig)).toBe(true);
    });

    it('should work with custom session endpoint', () => {
      const customConfig = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
          sessionEndpoint: '/custom/session',
        },
      });

      // Custom endpoint should be protected
      expect(isProtectedApi('/custom/session', customConfig)).toBe(true);
      // Default endpoint not protected anymore
      expect(isProtectedApi('/api/auth/session', customConfig)).toBe(false);
    });

    it('should protect API routes when explicitly configured in protectedApis', () => {
      const customConfig = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedApis: ['/api/v1/.*'],
      });

      expect(isProtectedApi('/api/v1/users', customConfig)).toBe(true);
      expect(isProtectedApi('/api/v1/posts', customConfig)).toBe(true);
      expect(isProtectedApi('/api/v2/users', customConfig)).toBe(false);
      // Session and token still protected
      expect(isProtectedApi('/api/auth/session', customConfig)).toBe(true);
      expect(isProtectedApi('/api/auth/token', customConfig)).toBe(true);
    });
  });

  describe('isProtectedPage', () => {
    it('should return false when no protected pages configured', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const request1 = new NextRequest('https://example.com/dashboard');
      const request2 = new NextRequest('https://example.com/settings');

      expect(isProtectedPage(request1, config)).toBe(false);
      expect(isProtectedPage(request2, config)).toBe(false);
    });

    it('should match protected page patterns', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedPages: ['/dashboard(.*)', '/settings'],
      });

      const request1 = new NextRequest('https://example.com/dashboard');
      const request2 = new NextRequest('https://example.com/dashboard/profile');
      const request3 = new NextRequest('https://example.com/settings');
      const request4 = new NextRequest('https://example.com/home');

      expect(isProtectedPage(request1, config)).toBe(true);
      expect(isProtectedPage(request2, config)).toBe(true);
      expect(isProtectedPage(request3, config)).toBe(true);
      expect(isProtectedPage(request4, config)).toBe(false);
    });

    it('should support wildcard patterns', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedPages: ['/admin(.*)'],
      });

      const request1 = new NextRequest('https://example.com/admin');
      const request2 = new NextRequest('https://example.com/admin/users');
      const request3 = new NextRequest('https://example.com/admin/settings/security');
      const request4 = new NextRequest('https://example.com/dashboard');

      expect(isProtectedPage(request1, config)).toBe(true);
      expect(isProtectedPage(request2, config)).toBe(true);
      expect(isProtectedPage(request3, config)).toBe(true);
      expect(isProtectedPage(request4, config)).toBe(false);
    });

    it('should support multiple patterns', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedPages: ['/dashboard(.*)', '/settings', '/profile'],
      });

      const request1 = new NextRequest('https://example.com/dashboard');
      const request2 = new NextRequest('https://example.com/settings');
      const request3 = new NextRequest('https://example.com/profile');
      const request4 = new NextRequest('https://example.com/home');

      expect(isProtectedPage(request1, config)).toBe(true);
      expect(isProtectedPage(request2, config)).toBe(true);
      expect(isProtectedPage(request3, config)).toBe(true);
      expect(isProtectedPage(request4, config)).toBe(false);
    });

    describe('Server Action Bypass', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        protectedPages: ['/dashboard(.*)'],
      });

      it('should NOT protect Server Actions (POST with next-action header)', () => {
        const request = new NextRequest('https://example.com/dashboard', {
          method: 'POST',
          headers: { 'next-action': 'abc123' },
        });

        expect(isProtectedPage(request, config)).toBe(false);
      });

      it('should protect regular POST to protected pages without next-action header', () => {
        const request = new NextRequest('https://example.com/dashboard', {
          method: 'POST',
        });

        expect(isProtectedPage(request, config)).toBe(true);
      });

      it('should protect GET requests even with next-action header', () => {
        const request = new NextRequest('https://example.com/dashboard', {
          method: 'GET',
          headers: { 'next-action': 'abc123' },
        });

        expect(isProtectedPage(request, config)).toBe(true);
      });

      it('should require BOTH POST method AND next-action header for bypass', () => {
        // POST without next-action
        const request1 = new NextRequest('https://example.com/dashboard', {
          method: 'POST',
        });
        expect(isProtectedPage(request1, config)).toBe(true);

        // GET with next-action
        const request2 = new NextRequest('https://example.com/dashboard', {
          method: 'GET',
          headers: { 'next-action': 'abc123' },
        });
        expect(isProtectedPage(request2, config)).toBe(true);

        // POST with next-action (bypass)
        const request3 = new NextRequest('https://example.com/dashboard', {
          method: 'POST',
          headers: { 'next-action': 'abc123' },
        });
        expect(isProtectedPage(request3, config)).toBe(false);
      });

      it('should allow Server Actions on deeply nested routes', () => {
        const request = new NextRequest('https://example.com/dashboard/settings/profile', {
          method: 'POST',
          headers: { 'next-action': 'updateProfile' },
        });

        expect(isProtectedPage(request, config)).toBe(false);
      });

      it('should protect other HTTP methods with next-action header', () => {
        const methods = ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

        methods.forEach((method) => {
          const request = new NextRequest('https://example.com/dashboard', {
            method,
            headers: { 'next-action': 'abc123' },
          });
          expect(isProtectedPage(request, config)).toBe(true);
        });
      });
    });
  });

  describe('isValidCsrf', () => {
    let mockRequest: NextRequest;

    beforeEach(() => {
      mockRequest = new NextRequest('https://example.com/api/test');
    });

    it('should return false when csrfToken is undefined', () => {
      expect(isValidCsrf(mockRequest, undefined, 'X-CSRF-TOKEN')).toBe(false);
    });

    it('should return false when csrfToken is empty string', () => {
      expect(isValidCsrf(mockRequest, '', 'X-CSRF-TOKEN')).toBe(false);
    });

    it('should return false when header is missing', () => {
      expect(isValidCsrf(mockRequest, 'test-token', 'X-CSRF-TOKEN')).toBe(false);
    });

    it('should return false when tokens do not match', () => {
      mockRequest.headers.set('X-CSRF-TOKEN', 'wrong-token');

      expect(isValidCsrf(mockRequest, 'test-token', 'X-CSRF-TOKEN')).toBe(false);
    });

    it('should return true when tokens match', () => {
      mockRequest.headers.set('X-CSRF-TOKEN', 'test-token');

      expect(isValidCsrf(mockRequest, 'test-token', 'X-CSRF-TOKEN')).toBe(true);
    });

    it('should work with custom header name', () => {
      mockRequest.headers.set('CUSTOM-CSRF', 'test-token');

      expect(isValidCsrf(mockRequest, 'test-token', 'CUSTOM-CSRF')).toBe(true);
    });

    it('should be case-sensitive for token comparison', () => {
      mockRequest.headers.set('X-CSRF-TOKEN', 'Test-Token');

      expect(isValidCsrf(mockRequest, 'test-token', 'X-CSRF-TOKEN')).toBe(false);
      expect(isValidCsrf(mockRequest, 'Test-Token', 'X-CSRF-TOKEN')).toBe(true);
    });
  });

  describe('resolveOnPageUnauthenticated', () => {
    let mockRequest: NextRequest;

    beforeEach(() => {
      mockRequest = new NextRequest('https://example.com/dashboard/profile');
    });

    it('should return custom handler if provided in config', () => {
      const customHandler = jest.fn();
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
        onPageUnauthenticated: customHandler,
      });

      const result = resolveOnPageUnauthenticated(config, 'https://example.com/api/auth/login');

      expect(result).toBe(customHandler);
    });

    it('should create default handler that redirects to login with return_url', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const onPageUnauthenticated = resolveOnPageUnauthenticated(config, 'https://example.com/api/auth/login');
      const response = await onPageUnauthenticated(mockRequest);

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(302);

      const location = response.headers.get('location');
      expect(location).toContain('/api/auth/login');
      expect(location).toContain('return_url=https%3A%2F%2Fexample.com%2Fdashboard%2Fprofile');
    });

    it('should handle tenant subdomain placeholders in loginUrl', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const onPageUnauthenticated = resolveOnPageUnauthenticated(
        config,
        'https://{tenant_domain}.app.com/api/auth/login'
      );
      const response = await onPageUnauthenticated(mockRequest);

      const location = response.headers.get('location');
      expect(location).toContain('/api/auth/login');
      expect(location).not.toContain('{tenant_domain}');
    });

    it('should preserve current domain when creating redirect URL', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const customRequest = new NextRequest('https://tenant1.myapp.com/settings');
      const onPageUnauthenticated = resolveOnPageUnauthenticated(config, 'https://example.com/auth/login');
      const response = await onPageUnauthenticated(customRequest);

      const location = response.headers.get('location');
      expect(location).toContain('tenant1.myapp.com');
      expect(location).toContain('/auth/login');
    });

    it('should encode return_url properly', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const requestWithQueryParams = new NextRequest('https://example.com/dashboard?foo=bar&baz=qux');
      const onPageUnauthenticated = resolveOnPageUnauthenticated(config, 'https://example.com/api/auth/login');
      const response = await onPageUnauthenticated(requestWithQueryParams);

      const location = response.headers.get('location');
      expect(location).toContain('return_url=https%3A%2F%2Fexample.com%2Fdashboard%3Ffoo%3Dbar%26baz%3Dqux');
    });

    it('should work with different login paths', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const onPageUnauthenticated1 = resolveOnPageUnauthenticated(config, 'https://example.com/login');
      const response1 = await onPageUnauthenticated1(mockRequest);
      expect(response1.headers.get('location')).toContain('/login?');

      const onPageUnauthenticated2 = resolveOnPageUnauthenticated(config, 'https://example.com/auth/v2/login');
      const response2 = await onPageUnauthenticated2(mockRequest);
      expect(response2.headers.get('location')).toContain('/auth/v2/login?');
    });

    it('should handle root path requests', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const rootRequest = new NextRequest('https://example.com/');
      const onPageUnauthenticated = resolveOnPageUnauthenticated(config, 'https://example.com/api/auth/login');
      const response = await onPageUnauthenticated(rootRequest);

      const location = response.headers.get('location');
      expect(location).toContain('return_url=https%3A%2F%2Fexample.com%2F');
    });

    it('should use fallback path when loginUrl is malformed', async () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      const onPageUnauthenticated = resolveOnPageUnauthenticated(config, 'not-a-valid-url');
      const response = await onPageUnauthenticated(mockRequest);

      const location = response.headers.get('location');
      expect(location).toContain('/api/auth/login');
      expect(location).toContain('return_url=https%3A%2F%2Fexample.com%2Fdashboard%2Fprofile');
    });

    it('should throw when loginUrl is empty string', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      expect(() => {
        return resolveOnPageUnauthenticated(config, '');
      }).toThrow(TypeError);
      expect(() => {
        return resolveOnPageUnauthenticated(config, '');
      }).toThrow('Must provide a valid login URL');
    });

    it('should throw when loginUrl is whitespace only', () => {
      const config = normalizeMiddlewareConfig({
        authStrategies: [AuthStrategy.SESSION],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret-must-be-at-least-32-characters-long' },
        },
      });

      expect(() => {
        return resolveOnPageUnauthenticated(config, '   ');
      }).toThrow(TypeError);
      expect(() => {
        return resolveOnPageUnauthenticated(config, '   ');
      }).toThrow('Must provide a valid login URL');
    });
  });

  describe('copyResponseHeaders', () => {
    it('should copy all headers from source to target', () => {
      const source = new Response(null, {
        headers: {
          'x-custom-header': 'custom-value',
          'content-type': 'application/json',
        },
      });

      const target = NextResponse.next();
      const result = copyResponseHeaders(source, target);

      expect(result.headers.get('x-custom-header')).toBe('custom-value');
      expect(result.headers.get('content-type')).toBe('application/json');
    });

    it('should copy Set-Cookie headers', () => {
      const source = new Response(null, {
        headers: {
          'set-cookie': 'session=abc123; Path=/; HttpOnly',
        },
      });

      const target = NextResponse.next();
      const result = copyResponseHeaders(source, target);

      expect(result.headers.get('set-cookie')).toBe('session=abc123; Path=/; HttpOnly');
    });

    it('should handle multiple Set-Cookie headers using append', () => {
      const source = new Response(null);
      source.headers.append('set-cookie', 'session=abc; Path=/');
      source.headers.append('set-cookie', 'csrf=xyz; Path=/');

      const target = NextResponse.next();
      const result = copyResponseHeaders(source, target);

      const cookies = result.headers.get('set-cookie');
      expect(cookies).toContain('session=abc');
      expect(cookies).toContain('csrf=xyz');
    });

    it('should return the same NextResponse instance', () => {
      const source = new Response(null);
      const target = NextResponse.next();

      const result = copyResponseHeaders(source, target);

      expect(result).toBe(target);
    });

    it('should preserve existing headers in target', () => {
      const source = new Response(null, {
        headers: { 'x-new-header': 'new-value' },
      });

      const target = NextResponse.next();
      target.headers.set('x-existing-header', 'existing-value');

      const result = copyResponseHeaders(source, target);

      expect(result.headers.get('x-existing-header')).toBe('existing-value');
      expect(result.headers.get('x-new-header')).toBe('new-value');
    });

    it('should handle empty headers', () => {
      const source = new Response(null);
      const target = NextResponse.next();

      const result = copyResponseHeaders(source, target);

      expect(result).toBe(target);
    });

    it('should append headers when duplicates exist', () => {
      const source = new Response(null, {
        headers: { 'x-custom': 'value2' },
      });

      const target = NextResponse.next();
      target.headers.set('x-custom', 'value1');

      const result = copyResponseHeaders(source, target);

      const headerValue = result.headers.get('x-custom');
      expect(headerValue).toContain('value1');
      expect(headerValue).toContain('value2');
    });

    it('should filter out x-middleware-next header', () => {
      const source = new Response(null, {
        headers: {
          'x-middleware-next': '1',
          'x-custom-header': 'custom-value',
        },
      });

      const target = NextResponse.next();

      // Store initial x-middleware-next value (NextResponse.next() may set it)
      const initialMiddlewareNext = target.headers.get('x-middleware-next');

      const result = copyResponseHeaders(source, target);

      // x-middleware-next from source should NOT be copied/appended
      // The value should be unchanged from what NextResponse.next() set
      expect(result.headers.get('x-middleware-next')).toBe(initialMiddlewareNext);
      // Other headers should be copied
      expect(result.headers.get('x-custom-header')).toBe('custom-value');
    });

    it('should filter x-middleware-next regardless of case', () => {
      const source = new Response(null);
      source.headers.set('X-MIDDLEWARE-NEXT', '1');
      source.headers.set('x-custom', 'value');

      const target = NextResponse.next();

      // Store initial x-middleware-next value
      const initialMiddlewareNext = target.headers.get('x-middleware-next');

      const result = copyResponseHeaders(source, target);

      // x-middleware-next from source should NOT be copied/appended
      expect(result.headers.get('x-middleware-next')).toBe(initialMiddlewareNext);
      // Other headers should still be copied
      expect(result.headers.get('x-custom')).toBe('value');
    });
  });
});
