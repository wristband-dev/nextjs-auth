import { NextRequest } from 'next/server';
import { getSession as getWristbandSession, Session, SessionData, SessionOptions } from '@wristband/typescript-session';

/**
 * Get session from NextRequest.
 *
 * **For Next.js middleware/proxy and App Router route handlers.**
 * Returns a full session with all methods available (save, destroy, saveToResponse, etc.)
 *
 * For Pages Router route handlers and getServerSideProps, use getPagesRouterSession().
 * For Server Components (read-only), use getReadOnlySessionFromCookies().
 * For Server Actions (mutable), use getMutableSessionFromCookies().
 *
 * @template T - Session data type extending SessionData
 * @param request - Next.js NextRequest object
 * @param options - Session configuration options
 * @returns Promise resolving to a full session instance with all methods
 *
 * @example
 * ```typescript
 * // In middleware/proxy
 * import { NextRequest, NextResponse } from 'next/server';
 * import { getSessionFromRequest } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export async function middleware(request: NextRequest) {
 *   const session = await getSessionFromRequest(request, sessionOptions);
 *
 *   if (!session.accessToken) {
 *     return NextResponse.redirect(new URL('/login', request.url));
 *   }
 *
 *   return NextResponse.next();
 * }
 *
 * // In App Router route handler
 * import { NextRequest, NextResponse } from 'next/server';
 * import { getSessionFromRequest } from '@wristband/nextjs-auth';
 *
 * export async function POST(request: NextRequest) {
 *   const session = await getSessionFromRequest(request, sessionOptions);
 *   session.set('theme', theme);
 *   return await session.saveToResponse(NextResponse.json({ ok: true }));
 * }
 * ```
 *
 * @see {@link getReadOnlySessionFromCookies} For Server Components (read-only)
 * @see {@link getMutableSessionFromCookies} For Server Actions (mutable)
 * @see {@link getPagesRouterSession} For Pages Router
 */
export async function getSessionFromRequest<T extends SessionData = SessionData>(
  request: NextRequest,
  options: SessionOptions
): Promise<Session<T> & T> {
  // Build cookie string from cookies API to include any modifications made via cookies.set().
  const cookies = request.cookies.getAll();
  const cookieHeader = cookies
    .map((c) => {
      return `${c.name}=${c.value}`;
    })
    .join('; ');

  // Create standard Request with current cookie state
  const standardRequest = new Request(request.url, {
    headers: { cookie: cookieHeader },
  });

  return getWristbandSession<T>(standardRequest, options);
}
