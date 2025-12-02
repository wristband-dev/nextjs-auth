import { getSession as getWristbandSession, Session, SessionData, SessionOptions } from '@wristband/typescript-session';

import { WristbandError } from '../error';
import {
  MutableSession,
  NextJsCookieStore,
  ReadOnlySession,
  SERVER_COMPONENT_SESSION,
  ServerComponentSessionMarker,
} from '../types';

const DEFAULT_SESSION_COOKIE_NAME: string = 'session';
const REQUEST_PLACEHOLDER_URL: string = 'https://placeholder.url';
const SESSION_READ_ONLY_ERROR: string = 'SESSION_READ_ONLY'; // For Server Component session errors

// ======================================
//  INTERNAL FUNCTIONS
// ======================================

/**
 * Internal helper to get session from Next.js cookies() API.
 *
 * Extracts the session cookie and creates a Web Request to pass to the
 * underlying typescript-session SDK. Not exported - users should use
 * getReadOnlySessionFromCookies() or getMutableSessionFromCookies().
 *
 * For App Router Server Actions and Server Components only.
 *
 * @internal
 * @template T - Session data type extending SessionData
 * @param cookieStore - The result of `await cookies()` from 'next/headers'
 * @param options - Session configuration options
 * @returns Promise resolving to a full session instance
 */
async function getSessionFromCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  options: SessionOptions
): Promise<Session<T> & T> {
  const cookieName = options.cookieName || DEFAULT_SESSION_COOKIE_NAME;
  const cookieValue = cookieStore.get(cookieName)?.value;

  const request = new Request(REQUEST_PLACEHOLDER_URL, {
    headers: { cookie: cookieValue ? `${cookieName}=${cookieValue}` : '' },
  });

  return getWristbandSession<T>(request, options);
}

/**
 * Type guard to check if a session is from a Server Component.
 *
 * Checks for the invisible SERVER_COMPONENT_SESSION symbol marker
 * that is added by getReadOnlySessionFromCookies().
 *
 * @internal
 * @param session - The session object to check
 * @returns True if the session is from a Server Component
 */
function isServerComponentSession(session: unknown): session is ServerComponentSessionMarker {
  return Boolean(session && typeof session === 'object' && (session as any)[SERVER_COMPONENT_SESSION]);
}

// ======================================
//  PUBLIC API
// ======================================

/**
 * Get a read-only session from Next.js cookies() API.
 *
 * **For App Router Server Components only** - when you need to READ session data.
 * Cannot modify or save. For modifying sessions in Server Actions, use getMutableSessionFromCookies().
 *
 * For route handlers or middleware/proxy, use getSession() instead.
 * For Pages Router, use getPagesRouterSession() instead.
 *
 * **IMPORTANT:** Using `cookies()` automatically makes your Server Component dynamic (no static caching).
 * The route will execute fresh on every request, ensuring session data is always current.
 *
 * @template T - Session data type extending SessionData
 * @param cookieStore - The result of `await cookies()` from 'next/headers'
 * @param options - Session configuration options
 * @returns Promise resolving to a read-only session with runtime protection against mutations
 *
 * @example
 * ```typescript
 * // ✅ Server Component - reading session data
 * import { cookies } from 'next/headers';
 * import { getReadOnlySessionFromCookies } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export default async function ProfilePage() {
 *   const cookieStore = await cookies();
 *   const session = await getReadOnlySessionFromCookies(cookieStore, sessionOptions);
 *   return <div>User: {session.userId}</div>;
 * }
 *
 * // ❌ These will throw TypeScript errors:
 * // session.set('theme', 'dark');
 * // await session.save();
 * ```
 * @see {@link getMutableSessionFromCookies} For Server Actions that need to modify sessions
 * @see {@link getSessionFromRequest} For App Router route handlers and middleware/proxy
 * @see {@link getPagesRouterSession} For Pages Router
 */
export async function getReadOnlySessionFromCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  options: SessionOptions
): Promise<ReadOnlySession<T>> {
  const session = await getSessionFromCookies<T>(cookieStore, options);

  // Add invisible marker for runtime detection
  Object.defineProperty(session, SERVER_COMPONENT_SESSION, { value: true, enumerable: false, writable: false });
  return session as unknown as ReadOnlySession<T>;
}

/**
 * Get a mutable session from Next.js cookies() API.
 *
 * **For App Router Server Actions only** - when you need to MODIFY session data.
 * Can call set()/delete(), but must use saveSessionWithCookies() to persist changes
 * or destroySessionWithCookies() to destroy the session.
 *
 * For route handlers or middleware/proxy, use getSession() instead.
 * For Pages Router, use getPagesRouterSession() instead.
 *
 * **Cache Behavior:** Server Actions automatically trigger a router refresh when cookies are modified,
 * so the UI will update to reflect session changes without manual revalidation. If you have cached
 * data that depends on session values, you can optionally call `revalidatePath()` or `revalidateTag()`.
 *
 * @template T - Session data type extending SessionData
 * @param cookieStore - The result of `await cookies()` from 'next/headers'
 * @param options - Session configuration options
 * @returns Promise resolving to a mutable session that can be modified and saved
 * @throws {WristbandError} If an invalid session method is invoked.
 *
 * @example
 * ```typescript
 * // Server Action - modifying session data
 * 'use server'
 * import { cookies } from 'next/headers';
 * import {
 *   getMutableSessionFromCookies,
 *   saveSessionWithCookies
 * } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export async function updateUserPreferences(theme: string, language: string) {
 *   const cookieStore = await cookies();
 *   const session = await getMutableSessionFromCookies(cookieStore, sessionOptions);
 *
 *   // ✅ Modify session data
 *   session.set('theme', theme);
 *   session.set('language', language);
 *
 *   // ✅ Persist changes
 *   await saveSessionWithCookies(cookieStore, session);
 *
 *   // Optional: revalidate cached data if you have OTHER data that depends on session
 *   // revalidatePath('/settings'); <- Next.js function
 *
 *   // ❌ These will throw TypeScript errors:
 *   // await session.save(); -> Use saveSessionWithCookies(cookieStore, session) instead
 *   // session.destroy();    -> Use destroySessionWithCookies(cookieStore, session) instead
 * }
 * ```
 *
 * @see {@link saveSessionWithCookies} To persist session changes
 * @see {@link destroySessionWithCookies} To destroy the session
 * @see {@link getReadOnlySessionFromCookies} For Server Components (read-only)
 */
export async function getMutableSessionFromCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  options: SessionOptions
): Promise<MutableSession<T>> {
  const session = await getSessionFromCookies<T>(cookieStore, options);
  return session as MutableSession<T>;
}

/**
 * Save session changes to Next.js cookies API.
 *
 * **For App Router Server Actions only.**
 * Encrypts and saves session data to cookies using Next.js `cookies()` API.
 *
 * For App Router route handlers and middleware/proxy, use session.saveToResponse() instead.
 * For Pages Router route handlers, use session.save().
 *
 * **Cache Behavior:** Modifying cookies automatically invalidates Next.js Router Cache
 * and triggers a re-render of the current route, so UI updates reflect session changes
 * without manual revalidation.
 *
 * @template T - Session data type extending SessionData
 * @param cookieStore - The result of await cookies() from 'next/headers'
 * @param session - The session instance to save
 * @returns Promise that resolves when cookies are set
 * @throws {WristbandError} If session is from a Server Component (read-only)
 *
 * @example
 * ```typescript
 * // app/actions.ts
 * 'use server'
 * import { cookies } from 'next/headers';
 * import {
 *   getMutableSessionFromCookies,
 *   saveSessionWithCookies
 * } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export async function updateTheme(theme: string) {
 *   const cookieStore = await cookies();
 *   const session = await getMutableSessionFromCookies(cookieStore, sessionOptions);
 *
 *   session.set('theme', theme);
 *   await saveSessionWithCookies(cookieStore, session);
 *
 *   // UI automatically updates - no manual revalidation needed.
 * }
 * ```
 *
 * @see {@link getMutableSessionFromCookies} To get a mutable session
 * @see {@link destroySessionWithCookies} To destroy the session instead
 */
export async function saveSessionWithCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  session: MutableSession<T>
): Promise<void> {
  if (isServerComponentSession(session)) {
    throw new WristbandError(
      SESSION_READ_ONLY_ERROR,
      'Cannot save a Server Component session. Server Components are read-only. ' +
        'Use getMutableSessionFromCookies() in Server Actions instead.'
    );
  }

  const cookieData = await session.getCookieDataForSave();
  cookieData.forEach(({ name, value, options }) => {
    cookieStore.set(name, value, options);
  });
}

/**
 * Destroy session using Next.js cookies API.
 *
 * **For App Router Server Actions only.**
 * Clears session cookies using Next.js `cookies()` API.
 *
 * For App Router route handlers and middleware/proxy, use session.destroyToResponse() instead.
 * For Pages Router route handlers, use session.destroy().
 *
 * **Cache Behavior:** Deleting cookies automatically invalidates Next.js Router Cache
 * and triggers a re-render of the current route.
 *
 * @template T - Session data type extending SessionData
 * @param cookieStore - The result of `await cookies()` from 'next/headers'
 * @param session - The session instance to destroy
 * @throws {WristbandError} If session is from a Server Component (read-only)
 *
 * @example
 * ```typescript
 * 'use server'
 * import { cookies } from 'next/headers';
 * import { getMutableSessionFromCookies, destroySessionWithCookies } from '@wristband/nextjs-auth';
 * import { redirect } from 'next/navigation';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export async function logout() {
 *   const cookieStore = await cookies();
 *   const session = await getMutableSessionFromCookies(cookieStore, sessionOptions);
 *
 *   destroySessionWithCookies(cookieStore, session);
 *   redirect('/login');
 * }
 * ```
 *
 * @see {@link getMutableSessionFromCookies} To get a mutable session
 * @see {@link saveSessionWithCookies} To save session changes instead
 */
export function destroySessionWithCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  session: MutableSession<T>
): void {
  if (isServerComponentSession(session)) {
    throw new WristbandError(
      SESSION_READ_ONLY_ERROR,
      'Cannot destroy a Server Component session. Server Components are read-only. ' +
        'Use getMutableSessionFromCookies() in Server Actions instead.'
    );
  }

  const cookieData = session.getCookieDataForDestroy();
  cookieData.forEach(({ name, value, options }) => {
    cookieStore.set(name, value, options);
  });
}
