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
 * Authentication strategy enum for Wristband auth.
 */
export enum AuthStrategy {
  /**
   * Session-based authentication using cookies
   */
  SESSION = 'SESSION',
  /**
   * JWT bearer token authentication
   */
  JWT = 'JWT',
}

/**
 * Configuration for Wristband auth middleware.
 */
export interface AuthMiddlewareConfig {
  /**
   * Authentication strategies to use, in order of precedence.
   * At least one strategy is required.
   *
   * - [AuthStrategy.SESSION]: Only session-based auth
   * - [AuthStrategy.JWT]: Only JWT bearer token auth
   * - [AuthStrategy.SESSION, AuthStrategy.JWT]: Try session first, fallback to JWT
   * - [AuthStrategy.JWT, AuthStrategy.SESSION]: Try JWT first, fallback to session
   *
   * @example
   * ```typescript
   * authStrategies: [AuthStrategy.SESSION, AuthStrategy.JWT]
   * ```
   */
  authStrategies: AuthStrategy[];

  /**
   * Configuration specific to SESSION authentication strategy.
   * REQUIRED if AuthStrategy.SESSION is included in authStrategies.
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
   * Callback when a protected page request is unauthenticated.
   * Use this to redirect to login or handle however you want.
   * Default: A function that automatically redirects unauthenticated users to the login URL
   *          as defined in your config for WristbandAuth.
   */
  onPageUnauthenticated?: (req: NextRequest) => NextResponse | Promise<NextResponse>;
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
 *   // result.reason is undefined
 * }
 *
 * // Failure case - reason explains why
 * if (!result.authenticated) {
 *   console.log(result.reason); // 'not_authenticated' | 'token_refresh_failed' | 'error'
 *   // result.session is null
 *   return { message: 'Please log in', authError: true };
 * }
 * ```
 *
 * @property {boolean} authenticated - Whether authentication succeeded
 * @property {MutableSession<T> | null} session - The authenticated session (only present when authenticated is true)
 * @property {'not_authenticated' | 'token_refresh_failed' | 'unexpected_error'} [reason] - Why authentication failed
 *      (only present when authenticated is false)
 */
export type ServerActionAuthResult<T extends SessionData = SessionData> =
  | { authenticated: true; session: MutableSession<T>; reason?: never }
  | { authenticated: false; session: null; reason: 'not_authenticated' | 'token_refresh_failed' | 'unexpected_error' };

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
  onPageUnauthenticated?: (req: NextRequest) => NextResponse | Promise<NextResponse>;
}

/**
 * Describes the outcome of running a single authentication strategy.
 *
 * This captures whether authentication succeeded, the resolved session
 * when successful, which strategy produced the result, and whether the
 * attempt failed due to CSRF validation. Callers can use this structure
 * to orchestrate sequential fallback across multiple strategies.
 *
 * @template T - The application-defined session data shape.
 */
export type AuthStrategyResult<T extends SessionData> = {
  /** Whether the strategy successfully authenticated the request */
  success: boolean;

  /** The resolved session when authentication succeeds. Only present for the SESSION strategy */
  session?: Session<T> & T;

  /** The strategy that produced a successful authentication (if any). */
  usedStrategy?: AuthStrategy;

  /** Indicates CSRF failure for CSRF-enforcing strategies. */
  csrfFailed?: boolean;
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
