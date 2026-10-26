import type { NextResponse } from 'next/server';
import type { CallbackData, CallbackFailureReason, NodeCallbackResult } from '@wristband/typescript-auth';

// Login, callback, logout, and token types are shared with @wristband/typescript-auth, which implements those flows.
export type {
  AuthConfig,
  CallbackData,
  CallbackFailureReason,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  TokenData,
  UserInfo,
  UserInfoRole,
} from '@wristband/typescript-auth';

/**
 * Represents the result of the Pages Router callback execution after authentication. It can contain the set of
 * callback data necessary for creating an authenticated session.
 *
 * This is a discriminated union type based on the `type` field:
 * - When `type` is `'completed'`, `callbackData` is present and `redirectUrl` is never present
 * - When `type` is `'redirect_required'`, `redirectUrl` is present and `callbackData` is never present
 *
 * Same as `NodeCallbackResult` from `@wristband/typescript-auth`, which handles the Pages Router callback.
 */
export type PagesRouterCallbackResult = NodeCallbackResult;

/**
 * Represents the result of the App Router callback execution after authentication. It can contain the set of
 * callback data necessary for creating an authenticated session, and it always contains a redirect response
 * with the login state cookie already cleared.
 *
 * This is a discriminated union type based on the `type` field:
 * - When `type` is `'completed'`, `callbackData` is present and `response` redirects to the URL returned by the
 *   application's redirect URL resolver
 * - When `type` is `'redirect_required'`, `reason` is present, `callbackData` is never present, and `response`
 *   redirects to the Login Endpoint
 */
export type AppRouterCallbackResult =
  | {
      /** The callback data received after authentication */
      callbackData: CallbackData;
      /** Never present when type is completed */
      reason?: never;
      /** The redirect response to the URL returned by the application's redirect URL resolver */
      response: NextResponse;
      /** Indicates successful completion with callback data */
      type: 'completed';
    }
  | {
      /** Never present when type is redirect_required */
      callbackData?: never;
      /** Why the redirect is required */
      reason: CallbackFailureReason;
      /** The redirect response to the Login Endpoint */
      response: NextResponse;
      /** Indicates a redirect is required */
      type: 'redirect_required';
    };
