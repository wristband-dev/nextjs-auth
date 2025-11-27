import type { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionData, SessionOptions } from '@wristband/typescript-session';

import type {
  AuthMiddlewareConfig,
  CallbackResult,
  LoginConfig,
  LogoutConfig,
  NextJsCookieStore,
  ServerActionAuthResult,
  TokenData,
} from '../types';

/**
 * WristbandAuth is a utility interface providing methods for seamless interaction with Wristband for authenticating
 * application users. It can handle the following:
 * - Initiate a login request by redirecting to Wristband.
 * - Receive callback requests from Wristband to complete a login request.
 * - Retrive all necessary JWT tokens and userinfo to start an application session.
 * - Logout a user from the application by revoking refresh tokens and redirecting to Wristband.
 * - Checking for expired access tokens and refreshing them automatically, if necessary.
 */
export interface WristbandAuth {
  /**
   * App Router authentication handlers for Next.js 13+ App Router.
   * Provides login, callback, logout, and response creation methods that work with Next.js App Router APIs.
   */
  appRouter: {
    /**
     * Initiates a login request by redirecting to Wristband. An authorization request is constructed
     * for the user attempting to login in order to start the Authorization Code flow.
     *
     * Your request can contain Wristband-specific query parameters:
     * - login_hint: A hint to Wristband about user's preferred login identifier. This can be appended as a query
     * parameter in the redirect request to the Authorize URL.
     * - return_url: The location of where to send users after authenticating.
     * - tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to, if applicable. Should be
     * used as the domain of the authorize URL when present.
     * - tenant_domain: The domain name of the tenant the user belongs to. Should be used in the tenant vanity domain of
     * the authorize URL when not utilizing tenant subdomains nor tenant custom domains.
     *
     * @param {NextRequest} request The request object.
     * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<NextResponse>} A Promise with the NextResponse that is peforming the URL redirect to Wristband.
     */
    login: (request: NextRequest, loginConfig?: LoginConfig) => Promise<NextResponse>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * Your request can contain Wristband-specific query parameters:
     * - code: The authorization code to use for exchanging for an access token.
     * - error: An error code indicating that some an issue occurred during the login process.
     * - error_description: A plaintext description giving more detail around the issue that occurred during the login
     * process.
     * - state: The state value that was originally sent to the Authorize URL.
     * - tenant_custom_domain: If the tenant has a tenant custom domain defined, then this query parameter will be part
     * of the incoming request to the Callback Endpoint. n the event a redirect to the Login Endpoint is required, then
     * this should be appended as a query parameter when redirecting to the Login Endpoint.
     * - tenant_domain: The domain name of the tenant the user belongs to. In the event a redirect to the Login Endpoint
     * is required and neither tenant subdomains nor tenant custom domains are not being utilized, then this should be
     * appended as a query parameter when redirecting to the Login Endpoint.
     *
     * @param {Request} request The request object.
     * @returns {Promise<CallbackResult>} A Promise containing the result of what happened during callback execution
     * as well as any accompanying data.
     * @throws {WristbandError} If an error occurs during the callback handling.
     */
    callback: (request: NextRequest) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and redirects them to the Wristband logout endpoint to destroy
     * their authenticated session in Wristband.
     *
     * @param {NextRequest} request The request object.
     * @param {LogoutConfig} [config] Additional configuration for logging out the user.
     * @returns {Promise<NextResponse>} A Promise with the NextResponse that is peforming the URL redirect to Wristband.
     * @throws {Error} If an error occurs during the logout process.
     */
    logout: (request: NextRequest, logoutConfig?: LogoutConfig) => Promise<NextResponse>;

    /**
     * Constructs the redirect response to your application and cleans up the login state.
     *
     * @param {NextRequest} request The request object.
     * @param {string} redirectUrl The location for your application that you want to send users to.
     * @returns {NextResponse} The NextResponse that is peforming the URL redirect to your desired application URL.
     */
    createCallbackResponse: (request: NextRequest, redirectUrl: string) => Promise<NextResponse>;

    /**
     * Creates a configured Server Action authentication helper.
     *
     * Factory function that returns a reusable authentication helper for Server Actions.
     * Configure once with session options, then use the returned function in multiple Server Actions
     * to validate authentication, refresh tokens, and retrieve session data.
     *
     * **Note:** Server Actions have built-in CSRF protection via Origin/Host header comparison,
     * so CSRF token validation is not performed.
     *
     * @param config - Configuration object
     * @param config.sessionOptions - Session configuration options (secrets, cookie settings, etc.)
     * @returns A function that checks authentication and returns a result
     *
     * @example
     * ```typescript
     * // Create a configured auth helper (once per app)
     * const requireServerActionAuth = wristbandAuth.appRouter.createServerActionAuth({
     *   sessionOptions: {
     *     secrets: process.env.SESSION_SECRET!,
     *     cookieName: 'my-session',
     *     maxAge: 24 * 60 * 60
     *   }
     * });
     *
     * // Use in Server Actions
     * 'use server'
     * import { cookies } from 'next/headers';
     *
     * export async function updateProfile(formData: FormData) {
     *   const cookieStore = await cookies();
     *   const { authenticated, session, reason } = await requireServerActionAuth(cookieStore);
     *
     *   if (!authenticated) {
     *     return { message: 'Not authenticated', authError: true };
     *   }
     *
     *   // Session is validated and tokens are refreshed automatically
     *   const userId = session.userId;
     *   // ... update profile
     * }
     * ```
     *
     * @see {@link ServerActionAuthResult} for the return type details
     */
    createServerActionAuth: <T extends SessionData = SessionData>(config: {
      sessionOptions: SessionOptions;
    }) => (cookieStore: NextJsCookieStore) => Promise<ServerActionAuthResult<T>>;
  };

  /**
   * Pages Router authentication handlers for Next.js Pages Router (API routes and getServerSideProps).
   * Provides login, callback, and logout methods that work with Next.js Pages Router APIs.
   */
  pagesRouter: {
    /**
     * Initiates a login request by redirecting to Wristband. An authorization request is constructed
     * for the user attempting to login in order to start the Authorization Code flow.
     *
     * Your request can contain Wristband-specific query parameters:
     * - login_hint: A hint to Wristband about user's preferred login identifier. This can be appended as a query
     * parameter in the redirect request to the Authorize URL.
     * - return_url: The location of where to send users after authenticating.
     * - tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to, if applicable. Should be
     * used as the domain of the authorize URL when present.
     * - tenant_domain: The domain name of the tenant the user belongs to. Should be used in the tenant vanity domain of
     * the authorize URL when not utilizing tenant subdomains nor tenant custom domains.
     *
     * @param {Request} request The request object.
     * @param {Response} response The response object.
     * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<string>} A Promise with the Wristband authorize URL that your app should redirect to.
     */
    login: (request: NextApiRequest, response: NextApiResponse, loginConfig?: LoginConfig) => Promise<string>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * Your request can contain Wristband-specific query parameters:
     * - code: The authorization code to use for exchanging for an access token.
     * - error: An error code indicating that some an issue occurred during the login process.
     * - error_description: A plaintext description giving more detail around the issue that occurred during the login
     * process.
     * - state: The state value that was originally sent to the Authorize URL.
     * - tenant_custom_domain: If the tenant has a tenant custom domain defined, then this query parameter will be part
     * of the incoming request to the Callback Endpoint. n the event a redirect to the Login Endpoint is required, then
     * this should be appended as a query parameter when redirecting to the Login Endpoint.
     * - tenant_domain: The domain name of the tenant the user belongs to. In the event a redirect to the Login Endpoint
     * is required and neither tenant subdomains nor tenant custom domains are not being utilized, then this should be
     * appended as a query parameter when redirecting to the Login Endpoint.
     *
     * @param {Request} request The request object.
     * @param {Response} response The response object.
     * @param {CallbackConfig} [config] Additional configuration for handling auth callbacks from Wristband.
     * @returns {Promise<CallbackResult>} A Promise containing the result of what happened during callback execution
     * as well as any accompanying data.
     * @throws {WristbandError} If an error occurs during the callback handling.
     */
    callback: (request: NextApiRequest, response: NextApiResponse) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and returns a redirect URL to the Wristband logout endpoint, where
     * their authenticated session in Wristband gets destroy.
     *
     * @param {Request} request The request object.
     * @param {Response} response The response object.
     * @param {LogoutConfig} [config] Additional configuration for logging out the user.
     * @returns {Promise<string>} A Promise with the Wristband logout URL that your app should redirect to.
     */
    logout: (request: NextApiRequest, response: NextApiResponse, logoutConfig?: LogoutConfig) => Promise<string>;
  };

  /**
   * Checks if the user's access token is expired and refreshed the token, if necessary. Works for both
   * Pages and App Router.
   *
   * @param {string} refreshToken The refresh token.
   * @param {number} expiresAt Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} A Promise with the data from the token endpoint if the token was refreshed.
   * Otherwise, a Promise with null value is returned.
   * @throws {Error} If an error occurs during the token refresh process.
   */
  refreshTokenIfExpired: (refreshToken: string, expiresAt: number) => Promise<TokenData | null>;

  /**
   * Creates a Next.js middleware function that handles authentication and session management
   * for protected routes in your application. Works for both Pages and App Router.
   *
   * This middleware:
   * - Checks if routes require authentication based on your configuration
   * - Validates user sessions for protected routes
   * - Optionally enforces CSRF token protection for API routes (if enabled)
   * - Automatically refreshes expired access tokens (if refresh tokens are in your session data)
   * - Handles unauthenticated requests appropriately (401 for APIs, your own custom handler for pages)
   * - Preserves headers and cookies from previous middleware when chained
   *
   * @template T - Session data type extending SessionData
   * @param config - Configuration for the authentication middleware
   * @param config.authStrategies - Authentication strategies to use (SESSION, JWT, or both)
   * @param config.sessionConfig - Session strategy configuration (required if using SESSION)
   * @param config.sessionConfig.sessionOptions - Session options including secrets and cookie settings
   * @param config.sessionConfig.csrfTokenHeaderName - Header name for CSRF token (default: 'X-CSRF-TOKEN')
   * @param config.sessionConfig.sessionEndpoint - Path to session endpoint (default: '/api/auth/session')
   * @param config.sessionConfig.tokenEndpoint - Path to token endpoint (default: '/api/auth/token')
   * @param config.jwtConfig - JWT strategy configuration (optional)
   * @param config.jwtConfig.jwksCacheMaxSize - Maximum number of JWKs to cache (default: 20)
   * @param config.jwtConfig.jwksCacheTtl - Cache TTL in milliseconds (default: 3600000)
   * @param config.protectedPages - Array of page route patterns requiring authentication (supports regex)
   * @param config.protectedApis - Array of API route patterns requiring authentication (default: empty array)
   * @param config.onPageUnauthenticated - Callback to handle unauthenticated page requests (e.g., redirect to login)
   * @returns A Next.js middleware function that accepts an optional response parameter for middleware chaining
   *
   * @example
   * ```typescript
   * // Basic usage - wristband.ts
   * import { createWristbandAuth } from '@wristband/nextjs-auth';
   *
   * const wristbandAuth = createWristbandAuth({ ... });
   *
   * export const requireWristbandSession = wristbandAuth.createMiddlewareAuth({
   *   sessionOptions: { secrets: process.env.SESSION_SECRET!, enableCsrfProtection: true },
   *   protectedPages: ['/dashboard(.*)', '/settings(.*)'],
   *   protectedApis: ['/api/users/.*', '/api/admin/.*'],
   *   onPageUnauthenticated: (request) => {
   *     const loginUrl = new URL('/api/auth/login', request.url);
   *     loginUrl.searchParams.set('return_url', request.nextUrl.pathname);
   *     return NextResponse.redirect(loginUrl);
   *   }
   * });
   *
   * // middleware.ts
   * import { requireWristbandSession } from '@/wristband';
   *
   * export async function middleware(request: NextRequest) {
   *   return await requireWristbandSession(request);
   * }
   *
   * export const config = {
   *   matcher: ['/((?!_next|fonts|[\\w-]+\\.\\w+).*)']
   * };
   * ```
   *
   * @example
   * ```typescript
   * // Chaining with other middleware - preserves headers/cookies
   * import { requireWristbandSession } from '@/wristband';
   * import { customMiddleware01, customMiddleware02 } from '@/lib/custom-middleware';
   *
   * export async function middleware(request: NextRequest) {
   *   // First middleware sets some headers
   *   const customResponse = await customMiddleware01(request);
   *
   *   // Wristband middleware preserves those headers
   *   const wristbandResponse = await requireWristbandSession(request, customResponse);
   *
   *   // You can pass the Wristband response to other middlewares that suppport chaining.
   *   return await customMiddleware02(request, wristbandResponse);
   * }
   * ```
   *
   * @example
   * ```typescript
   * // With custom session data type
   * interface MySessionData extends SessionData {
   *   theme: string;
   *   roles: string[];
   * }
   *
   * export const requireWristbandSession = wristbandAuth.createMiddlewareAuth<MySessionData>({
   *   sessionOptions: { secrets: process.env.SESSION_SECRET! },
   *   protectedPages: ['/dashboard(.*)'],
   *   onPageUnauthenticated: (request) => NextResponse.redirect(new URL('/login', request.url))
   * });
   * ```
   */
  // eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
  createMiddlewareAuth: <T extends SessionData = SessionData>(
    config: AuthMiddlewareConfig
  ) => (request: NextRequest, previousResponse?: NextResponse) => Promise<NextResponse>;
}
