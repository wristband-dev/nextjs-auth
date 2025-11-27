import { NextRequest, NextResponse } from 'next/server';
import { Session, SessionData, SessionOptions } from '@wristband/typescript-session';

/**
 * Next.js cookie store interface (duck-typed, no Next.js dependency required).
 * This matches the return type of Next.js cookies() function.
 */
export interface NextJsCookieStore {
  get(name: string): { value: string } | undefined;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  set(name: string, value: string, options?: any): void;
}

/**
 * Authentication strategy for Wristband auth.
 *
 * Available strategies:
 * - `'SESSION'` - Session-based authentication using cookies
 * - `'JWT'` - JWT bearer token authentication
 */
export type AuthStrategy = 'SESSION' | 'JWT';

/**
 * Reasons why authentication can fail in middleware or Server Actions.
 *
 * @property not_authenticated - No valid session or JWT token found
 * @property csrf_failed - CSRF token validation failed (SESSION strategy only)
 * @property token_refresh_failed - Token refresh attempt failed (SESSION strategy only)
 * @property unexpected_error - Unexpected error occurred during authentication
 */
export type AuthFailureReason = 'not_authenticated' | 'csrf_failed' | 'token_refresh_failed' | 'unexpected_error';

/**
 * Handler invoked when a protected page is accessed without valid authentication.
 *
 * @param request - The incoming request to the protected page
 * @param reason - Why authentication failed
 * @returns Response to send to the client (typically a redirect to login)
 */
export type UnauthenticatedPageHandler = (
  request: NextRequest,
  reason: AuthFailureReason
) => NextResponse | Promise<NextResponse>;

/**
 * Configuration for Wristband auth middleware.
 */
export interface AuthMiddlewareConfig {
  /**
   * Authentication strategies to use, in order of precedence.
   * At least one strategy is required.
   *
   * - ['SESSION']: Only session-based auth
   * - ['JWT']: Only JWT bearer token auth
   * - ['SESSION', 'JWT']: Try session first, fallback to JWT
   * - ['JWT', 'SESSION']: Try JWT first, fallback to session
   *
   * @example
   * ```typescript
   * authStrategies: [SESSION, JWT]
   * ```
   */
  authStrategies: AuthStrategy[];

  /**
   * Configuration specific to SESSION authentication strategy.
   * Required if SESSION is included in authStrategies.
   */
  sessionConfig?: {
    /**
     * Session configuration options including secrets and cookie settings.
     *
     * NOTE: If you set `enableCsrfProtection` to true in these options, it will also automatically enable
     * CSRF token validation for all requests to protected API routes.
     *
     * @example
     * ```typescript
     * sessionOptions: {
     *   secrets: process.env.SESSION_SECRET!,
     *   cookieName: 'my-session',
     *   maxAge: 24 * 60 * 60 * 1000, // 24 hours
     * }
     * ```
     */
    sessionOptions: SessionOptions;
    /**
     * CSRF token header name (only used if `sessionOptions.enableCsrfProtection` is true).
     * Default: 'X-CSRF-TOKEN'
     */
    csrfTokenHeaderName?: string;
    /**
     * Path to the Session Endpoint that should be protected when using SESSION strategy.
     * Default: '/api/auth/session'
     */
    sessionEndpoint?: string;
    /**
     * Path to the Token Endpoint that should be protected when using SESSION strategy.
     * Default: '/api/auth/token'
     */
    tokenEndpoint?: string;
  };

  /**
   * Configuration specific to JWT strategy.
   * Optional (all settings rely on @wristband/typescript-jwt SDK defaults).
   */
  jwtConfig?: {
    /**
     * Maximum number of JWKs to cache.
     * Default: 20
     */
    jwksCacheMaxSize?: number;
    /**
     * Time-to-live for cached JWKs in milliseconds.
     * Default: Infinite (until evicted due to LRU cache eviction)
     */
    jwksCacheTtl?: number;
  };

  /**
   * Page routes that require authentication (e.g., ['/settings(.*)', '/dashboard(.*)'])
   * Supports static paths and regex patterns
   * Optional - defaults to empty array (no pages protected)
   * Default: []
   */
  protectedPages?: string[];

  /**
   * API routes that require authentication (e.g., ['/api/v1(.*)'])
   * Optional - defaults to empty array (only Session and Token Endpoints protected when using SESSION strategy)
   * Default: []
   */
  protectedApis?: string[];

  /**
   * Callback invoked when a protected page is accessed without valid authentication.
   *
   * Use this to customize the response when authentication fails. By default, users are
   * redirected to the login URL (as defined in your WristbandAuth config) with a `return_url`
   * parameter so they can be redirected back after logging in.
   *
   * @param request - The incoming request to the protected page
   * @param reason - Why authentication failed
   *
   * @example
   * ```typescript
   * onPageUnauthenticated: (request, reason) => {
   *   const loginUrl = new URL('/login', request.url);
   *   loginUrl.searchParams.set('return_url', request.url);
   *
   *   // Optionally pass the error reason
   *   if (reason === 'csrf_failed') {
   *     loginUrl.searchParams.set('error', 'invalid_request');
   *   }
   *
   *   return NextResponse.redirect(loginUrl);
   * }
   * ```
   */
  onPageUnauthenticated?: UnauthenticatedPageHandler;
}

/**
 * Session type for Server Actions - allows data mutations but requires saveSessionWithCookies()
 * or destroySessionWithCookies() to persist.
 *
 * @template T - Session data type extending SessionData
 * @internal
 */
export type MutableSession<T extends SessionData> = RestrictedSession<T>;

/**
 * Session type for Server Components - read-only with SERVER_COMPONENT_SESSION marker for runtime protection.
 *
 * @template T - Session data type extending SessionData
 * @internal
 */
export type ReadOnlySession<T extends SessionData> = RestrictedSession<T> & ServerComponentSessionMarker;

/**
 * Result of a Server Action authentication check.
 *
 * A discriminated union that provides type-safe access to the user's session when authenticated,
 * or a failure reason when authentication fails.
 *
 * @template T - Session data type extending SessionData
 *
 * @example
 * ```typescript
 * // Success case - session is guaranteed to exist
 * const result = await requireAuth(cookieStore);
 * if (result.authenticated) {
 *   console.log(result.session.userId); // ✅ TypeScript knows session exists
 *   // result.reason is never (compile error if accessed)
 * }
 *
 * // Failure case - reason explains why
 * if (!result.authenticated) {
 *   console.log(result.reason); // 'not_authenticated' | 'token_refresh_failed' | 'unexpected_error'
 *   // result.session is never (compile error if accessed)
 *   return { message: 'Please log in', authError: true };
 * }
 * ```
 */
export type ServerActionAuthResult<T extends SessionData = SessionData> =
  | { authenticated: true; session: MutableSession<T>; reason?: never }
  | { authenticated: false; session?: never; reason: AuthFailureReason };

// ====================================================== //
// ================== INTERNAL TYPES ==================== //
// ====================================================== //

/**
 * Normalized middleware configuration with all defaults applied.
 * This is the internal configuration format used by the middleware after
 * processing the user-provided AuthMiddlewareConfig.
 *
 * @internal
 */
export interface NormalizedMiddlewareConfig {
  /** Authentication strategies to use, in order of precedence */
  authStrategies: AuthStrategy[];
  /** Session authentication strategy configuration */
  sessionConfig: {
    /** Session options - only defined when SESSION strategy is used */
    sessionOptions?: SessionOptions;
    /** CSRF token header name (default: 'X-CSRF-TOKEN') */
    csrfTokenHeaderName: string;
    /** Session endpoint path (default: '/api/auth/session') */
    sessionEndpoint: string;
    /** Token endpoint path (default: '/api/auth/token') */
    tokenEndpoint: string;
  };
  /** JWT authentication strategy configuration */
  jwtConfig: {
    /** Maximum JWKs to cache - uses library default (20) when undefined */
    jwksCacheMaxSize?: number;
    /** JWK cache TTL in ms - uses library default of infinite when undefined */
    jwksCacheTtl?: number;
  };
  /** Page route patterns requiring authentication */
  protectedPages: string[];
  /** API route patterns requiring authentication */
  protectedApis: string[];
  /** Callback for handling unauthenticated page requests. */
  onPageUnauthenticated?: UnauthenticatedPageHandler;
}

/**
 * Describes the outcome of running a single authentication strategy.
 *
 * A discriminated union that captures whether authentication succeeded or failed,
 * and provides specific failure reasons to enable proper error handling and HTTP
 * status code selection.
 *
 * @template T - The application-defined session data shape.
 */
export type AuthStrategyResult<T extends SessionData> =
  | {
      /** Authentication succeeded */
      authenticated: true;
      /** The resolved session (only present for SESSION strategy) */
      session?: Session<T> & T;
      /** The strategy that produced successful authentication */
      usedStrategy: AuthStrategy;
      /** Never present on success */
      reason?: never;
    }
  | {
      /** Authentication failed */
      authenticated: false;
      /** Never present on failure */
      session?: never;
      /** Never present on failure */
      usedStrategy?: never;
      /** Why authentication failed */
      reason: AuthFailureReason;
    };

/**
 * Symbol used to mark sessions from Server Components as read-only.
 * This marker enables runtime protection in saveSessionWithCookies() and destroySessionWithCookies().
 *
 * @internal
 */
export const SERVER_COMPONENT_SESSION = Symbol('SERVER_COMPONENT_SESSION');

/**
 * Interface for objects marked with the SERVER_COMPONENT_SESSION symbol.
 * Used for type-safe runtime detection of read-only Server Component sessions.
 *
 * @internal
 */
export interface ServerComponentSessionMarker {
  [SERVER_COMPONENT_SESSION]: true;
}

/**
 * Session type with persistence methods removed.
 * Used internally to construct MutableSession and ReadOnlySession types.
 * @internal
 */
type RestrictedSession<T extends SessionData> = Omit<
  Session<T> & T,
  | 'save'
  | 'destroy'
  | 'saveToResponse'
  | 'destroyToResponse'
  | 'fromCallback'
  | 'enableDeferredMode'
  | 'flush'
  | 'flushSync'
>;
