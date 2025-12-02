import { NextRequest, NextResponse } from 'next/server';

import { AuthMiddlewareConfig, AuthStrategy, NormalizedMiddlewareConfig, UnauthenticatedPageHandler } from '../types';

const DEFAULT_CSRF_HEADER_NAME: string = 'X-CSRF-TOKEN';
const DEFAULT_PROTECTED_APIS: string[] = [];
const DEFAULT_PROTECTED_PAGES: string[] = [];
const DEFAULT_LOGIN_ENDPOINT: string = '/api/auth/login';
const DEFAULT_SESSION_ENDPOINT: string = '/api/auth/session';
const DEFAULT_TOKEN_ENDPOINT: string = '/api/auth/token';

const VALID_AUTH_STRATEGIES = new Set<AuthStrategy>(['SESSION', 'JWT']);

// Skip x-middleware-next - internal Next.js routing signal
const X_MIDDLEWARE_NEXT_HEADER: string = 'x-middleware-next';

/**
 * Validates auth middleware configuration.
 *
 * @param config - User-provided middleware configuration
 * @throws {TypeError} If authStrategies is empty
 * @throws {TypeError} If authStrategies contains invalid values
 * @throws {TypeError} If authStrategies contains duplicates
 * @throws {TypeError} If authStrategies contains too many strategies
 * @throws {TypeError} If SESSION strategy is used but sessionConfig or sessionOptions are missing
 */
function validateMiddlewareConfig(config: AuthMiddlewareConfig): void {
  // Validate authStrategies is not empty
  if (!config.authStrategies || config.authStrategies.length === 0) {
    throw new TypeError('authStrategies must contain at least one strategy');
  }

  // Validate in one pass: no invalid values, no duplicates
  const seen = new Set<AuthStrategy>();
  const invalidStrategies: string[] = [];

  config.authStrategies.forEach((strategy) => {
    // Check for invalid strategy
    if (!VALID_AUTH_STRATEGIES.has(strategy as AuthStrategy)) {
      invalidStrategies.push(strategy);
      return; // Skip to next iteration
    }

    // Check for duplicate
    if (seen.has(strategy)) {
      throw new TypeError(`authStrategies contains duplicate strategy: '${strategy}'`);
    }

    seen.add(strategy);
  });

  // Report all invalid strategies at once
  if (invalidStrategies.length > 0) {
    throw new TypeError(
      `Invalid auth strategies: '${invalidStrategies.join("', '")}'. Valid strategies are: 'SESSION', 'JWT'`
    );
  }

  // Validate sessionConfig is provided if SESSION strategy is used
  if (config.authStrategies.includes('SESSION')) {
    if (!config.sessionConfig) {
      throw new TypeError('sessionConfig is required when using SESSION strategy');
    }

    if (!config.sessionConfig?.sessionOptions) {
      throw new TypeError('sessionConfig.sessionOptions is required when using SESSION strategy');
    }
  }
}

/**
 * Normalizes middleware configuration by applying default values for optional fields.
 *
 * @param config - User-provided middleware configuration with nested strategy configs
 * @returns Normalized configuration with all strategy configs in nested objects and defaults applied
 * @throws {TypeError} If configuration validation fails
 *
 * @example
 * ```typescript
 * const normalized = normalizeMiddlewareConfig({
 *   authStrategies: ['SESSION'],
 *   sessionConfig: {
 *     sessionOptions: { secrets: 'my-secret', enableCsrfProtection: true },
 *   },
 *   protectedPages: ['/dashboard'],
 * });
 * // Returns config with sessionConfig and jwtConfig objects, all defaults applied
 * ```
 */
export function normalizeMiddlewareConfig(config: AuthMiddlewareConfig): NormalizedMiddlewareConfig {
  // Validate config first
  validateMiddlewareConfig(config);

  return {
    authStrategies: config.authStrategies,
    protectedApis: config.protectedApis || DEFAULT_PROTECTED_APIS,
    protectedPages: config.protectedPages || DEFAULT_PROTECTED_PAGES,
    // The core middleware logic will handle applying a default "onPageUnauthenticated" value if none is provided.
    onPageUnauthenticated: config.onPageUnauthenticated || undefined,
    sessionConfig: {
      sessionOptions: config.sessionConfig?.sessionOptions || undefined,
      sessionEndpoint: config.sessionConfig?.sessionEndpoint || DEFAULT_SESSION_ENDPOINT,
      tokenEndpoint: config.sessionConfig?.tokenEndpoint || DEFAULT_TOKEN_ENDPOINT,
      csrfTokenHeaderName: config.sessionConfig?.csrfTokenHeaderName || DEFAULT_CSRF_HEADER_NAME,
    },
    jwtConfig: {
      jwksCacheMaxSize: config.jwtConfig?.jwksCacheMaxSize || undefined,
      jwksCacheTtl: config.jwtConfig?.jwksCacheTtl || undefined,
    },
  };
}

/**
 * Extracts the pathname from a login URL, removing the protocol, host, and any tenant placeholders. This
 * is used to create a default redirect URL for the default for onPageUnauthenticated() middleware config.
 *
 * This handles URLs with tenant subdomains (containing `{tenant_name}` or `{tenant_domain}` placeholders)
 * by removing the placeholder and the dot separator that follows it.
 *
 * @param loginUrl - The full login URL from WristbandAuth config
 * @returns The pathname portion of the URL (e.g., '/api/auth/login'). Returns '/api/auth/login' as
 *          a fallback if URL parsing fails.
 *
 * @example
 * ```typescript
 * extractLoginPath('http://localhost/login');
 * // Returns: '/login'
 *
 * extractLoginPath('https://{tenant_domain}.app.com/api/auth/login');
 * // Returns: '/api/auth/login'
 *
 * extractLoginPath('https://{tenant_name}.app.com/login');
 * // Returns: '/login'
 *
 * extractLoginPath('https://acme.com/api/v1/login');
 * // Returns: '/api/v1/login'
 * ```
 */
function extractLoginPath(loginUrl: string): string {
  if (!loginUrl || !loginUrl.trim()) {
    throw new TypeError('Must provide a valid login URL');
  }

  try {
    // Remove tenant placeholders and the dot separator that follows them
    const normalizedUrl = loginUrl.replace(/\{tenant_domain\}\./g, '').replace(/\{tenant_name\}\./g, '');

    const url = new URL(normalizedUrl);
    return url.pathname;
  } catch (error) {
    // Fallback to relative path default in the event a parse error occurs.
    return DEFAULT_LOGIN_ENDPOINT;
  }
}

/**
 * Resolves the onPageUnauthenticated() handler, using the provided config or creating a default handler
 * that redirects to the login endpoint with a return_url query parameter.
 *
 * @param config - Normalized middleware configuration
 * @param loginUrl - The full login URL from WristbandAuth config
 * @returns The resolved onPageUnauthenticated handler function
 *
 * @example
 * ```typescript
 * // With custom handler
 * const onPageUnauthenticated = resolveOnPageUnauthenticated(config, loginUrl);
 * return await onPageUnauthenticated(req);
 *
 * // Default behavior (no custom handler provided)
 * // Redirects to: /api/auth/login?return_url=<current_location>
 * ```
 */
export function resolveOnPageUnauthenticated(
  config: NormalizedMiddlewareConfig,
  loginUrl: string
): UnauthenticatedPageHandler {
  // If user provided a custom handler, use it
  if (config.onPageUnauthenticated) {
    return config.onPageUnauthenticated;
  }

  // Otherwise, create default handler that redirects to login with return_url
  const loginPath = extractLoginPath(loginUrl);
  return (request: NextRequest) => {
    const redirectUrl = new URL(loginPath, request.url);
    redirectUrl.searchParams.set('return_url', request.url);
    return NextResponse.redirect(redirectUrl, { status: 302 });
  };
}

/**
 * Creates a route matcher function from an array of URL patterns.
 *
 * Supports:
 * - Exact path matches: `/api/users`
 * - Named parameters: `/api/users/:id` matches `/api/users/123`
 * - Wildcards: `/dashboard(.*)` matches `/dashboard`, `/dashboard/settings`, etc.
 * - Regex patterns: Any valid regex pattern
 *
 * @param patterns - Array of route patterns to match against
 * @returns Matcher function that tests if a pathname matches any pattern
 *
 * @example
 * ```typescript
 * const matcher = createRouteMatcher([
 *   '/dashboard(.*)',
 *   '/api/users/:id',
 *   '/settings'
 * ]);
 *
 * matcher('/dashboard/profile'); // true
 * matcher('/api/users/123');     // true
 * matcher('/settings');          // true
 * matcher('/home');              // false
 * ```
 */
export function createRouteMatcher(patterns: string[]): (pathname: string) => boolean {
  const regexPatterns = patterns.map((pattern) => {
    // Convert pattern to regex
    // Handle named params like :id and wildcards like (.*)
    const regexPattern = pattern
      .replace(/:[^/]+/g, '[^/]+') // :id -> [^/]+
      .replace(/\(\.\*\)/g, '.*'); // (.*) -> .*

    return new RegExp(`^${regexPattern}$`);
  });

  return (pathname: string) => {
    return regexPatterns.some((regex) => {
      return regex.test(pathname);
    });
  };
}

/**
 * Determines if a pathname is a protected API route that requires authentication.
 *
 * A route is considered protected if:
 * 1. SESSION strategy is used and it matches the Session Endpoint (`/api/auth/session` by default)
 * 2. SESSION strategy is used and it matches the Token Endpoint (`/api/auth/token` by default)
 * 3. It matches any pattern in `config.protectedApis`
 *
 * Note: Session and token endpoints are only protected when using the SESSION authentication strategy.
 * If using only JWT strategy, these endpoints will not be automatically protected.
 *
 * @param pathname - The URL pathname to check
 * @param config - Normalized middleware configuration
 * @returns True if the route requires authentication
 *
 * @example
 * ```typescript
 * // With SESSION strategy and no protectedApis configured
 * isProtectedApi('/api/users', config);        // false (not protected by default)
 * isProtectedApi('/api/auth/login', config);   // false
 * isProtectedApi('/api/auth/session', config); // true (protected when using SESSION strategy)
 * isProtectedApi('/api/auth/token', config);   // true (protected when using SESSION strategy)
 *
 * // With JWT strategy only (no SESSION strategy)
 * isProtectedApi('/api/auth/session', config); // false (not protected without SESSION strategy)
 * isProtectedApi('/api/auth/token', config);   // false (not protected without SESSION strategy)
 *
 * // With protectedApis: ['/api/v1/.*']
 * isProtectedApi('/api/v1/users', config);     // true
 * ```
 */
export function isProtectedApi(pathname: string, config: NormalizedMiddlewareConfig): boolean {
  // Only protect session and token endpoints if SESSION strategy is being used
  if (config.authStrategies.includes('SESSION')) {
    if (pathname === config.sessionConfig.sessionEndpoint || pathname === config.sessionConfig.tokenEndpoint) {
      return true;
    }
  }

  // Check against protected API patterns
  const matcher = createRouteMatcher(config.protectedApis);
  return matcher(pathname);
}

/**
 * Determines if a pathname is a protected page route that requires authentication.
 *
 * Checks if the pathname matches any pattern defined in `config.protectedPages`.
 * Unlike API routes, pages typically redirect unauthenticated users rather than
 * returning 401 status codes.
 *
 * @param pathname - The URL pathname to check
 * @param config - Normalized middleware configuration
 * @returns True if the page requires authentication
 *
 * @example
 * ```typescript
 * // With protectedPages: ['/dashboard(.*)', '/settings']
 * isProtectedPage('/dashboard', config);          // true
 * isProtectedPage('/dashboard/profile', config);  // true
 * isProtectedPage('/settings', config);           // true
 * isProtectedPage('/home', config);               // false
 * ```
 */
export function isProtectedPage(request: NextRequest, config: NormalizedMiddlewareConfig): boolean {
  const matcher = createRouteMatcher(config.protectedPages);

  const isRouteMatch = matcher(request.nextUrl.pathname);
  if (!isRouteMatch) {
    return false;
  }

  // Server Actions POST to the same route as their page but handle their own auth.
  // Skip middleware for them to avoid blocking legitimate Server Action requests.
  // Security: Requires BOTH POST method AND next-action header to prevent bypass attacks.
  const isServerAction = request.method === 'POST' && request.headers.get('next-action');
  if (isServerAction) {
    return false;
  }

  return true;
}

/**
 * Validates the CSRF token for API requests to prevent cross-site request forgery attacks.
 *
 * Compares the CSRF token stored in the session against the token provided in the
 * request header. Both must exist and match exactly for validation to pass.
 *
 * This should only be used for API routes, as page navigations don't include CSRF headers.
 *
 * @param req - The NextRequest object containing headers
 * @param csrfToken - The CSRF token stored in the session (from session.csrfToken)
 * @param csrfHeaderName - The header name to check for the token (default: 'X-CSRF-TOKEN')
 * @returns True if the CSRF token is valid, false otherwise
 *
 * @example
 * ```typescript
 * // In middleware for protected API routes
 * const isValid = isValidCsrf(req, session.csrfToken, 'X-CSRF-TOKEN');
 * if (!isValid) {
 *   return new NextResponse(null, { status: 403 });
 * }
 * ```
 */
export function isValidCsrf(req: NextRequest, csrfToken: string | undefined, csrfHeaderName: string): boolean {
  if (!csrfToken) {
    return false;
  }

  const headerValue = req.headers.get(csrfHeaderName);
  return csrfToken === headerValue;
}

/**
 * Copies all headers from a source Response to a target NextResponse.
 * This is useful for preserving headers (including Set-Cookie) when creating
 * new responses in middleware.
 *
 * IMPORTANT: Filters out the internal Next.js 'x-middleware-next' header to prevent
 * routing conflicts when copying headers to error or redirect responses.
 *
 * @param source - The source Response to copy headers from
 * @param target - The target NextResponse to copy headers to
 * @returns The target NextResponse with headers copied
 */
export function copyResponseHeaders(source: Response, target: NextResponse): NextResponse {
  source.headers.forEach((value, key) => {
    // Skip x-middleware-next - internal Next.js routing signal
    if (key.toLowerCase() === X_MIDDLEWARE_NEXT_HEADER) {
      return;
    }
    target.headers.append(key, value);
  });

  return target;
}
