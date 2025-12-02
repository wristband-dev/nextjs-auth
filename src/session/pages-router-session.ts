import * as http from 'http';
import { getSession, Session, SessionData, SessionOptions } from '@wristband/typescript-session';

/**
 * Get session from Node.js request/response objects.
 *
 * **For Pages Router route handlers and getServerSideProps() only.**
 * Returns a full session with all methods available (save, destroy, etc.)
 *
 * For middleware/proxy or App Router route handlers, use getSessionFromRequest().
 * For Server Components (read-only), use getReadOnlySessionFromCookies().
 * For Server Actions (mutable), use getMutableSessionFromCookies().
 *
 * @template T - Session data type extending SessionData
 * @param req - Node.js IncomingMessage from Pages Router
 * @param res - Node.js ServerResponse from Pages Router
 * @param options - Session configuration options
 * @returns Promise resolving to a full session instance with all methods
 *
 * @example
 * ```typescript
 * // In API route (pages/api/profile.ts)
 * import { NextApiRequest, NextApiResponse } from 'next';
 * import { getPagesRouterSession } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export default async function handler(req: NextApiRequest, res: NextApiResponse) {
 *   const session = await getPagesRouterSession(req, res, sessionOptions);
 *
 *   if (!session.isAuthenticated) {
 *     return res.status(401).json({ error: 'Unauthorized' });
 *   }
 *
 *   return res.json({ userId: session.userId });
 * }
 *
 * // In getServerSideProps
 * import { GetServerSideProps } from 'next';
 * import { getPagesRouterSession } from '@wristband/nextjs-auth';
 *
 * const sessionOptions = {
 *   secrets: process.env.SESSION_SECRET!,
 *   cookieName: 'my-session'
 * };
 *
 * export const getServerSideProps: GetServerSideProps = async ({ req, res }) => {
 *   const session = await getPagesRouterSession(req, res, sessionOptions);
 *
 *   if (!session.isAuthenticated) {
 *     return {
 *       redirect: { destination: '/login', permanent: false },
 *     };
 *   }
 *
 *   return { props: { userId: session.userId } };
 * };
 * ```
 *
 * @see {@link getSessionFromRequest} For middleware/proxy and App Router route handlers
 * @see {@link getReadOnlySessionFromCookies} For Server Components (read-only)
 * @see {@link getMutableSessionFromCookies} For Server Actions (mutable)
 */
export function getPagesRouterSession<T extends SessionData = SessionData>(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: SessionOptions
): Promise<Session<T> & T> {
  return getSession<T>(req, res, options);
}
