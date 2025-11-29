<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> •
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Wristband Multi-Tenant Authentication SDK for Next.js

[![npm package](https://img.shields.io/badge/npm%20i-nextjs--auth-brightgreen)](https://www.npmjs.com/package/@wristband/nextjs-auth)
[![version number](https://img.shields.io/github/v/release/wristband-dev/nextjs-auth?color=green&label=version)](https://github.com/wristband-dev/nextjs-auth/releases)
[![License](https://img.shields.io/github/license/wristband-dev/nextjs-auth)](https://github.com/wristband-dev/nextjs-auth/blob/main/LICENSE.md)
[![Actions Status](https://github.com/wristband-dev/nextjs-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/nextjs-auth/actions)

Enterprise-ready authentication for multi-tenant [Next.js applications](https://nextjs.org/) using OAuth 2.1 and OpenID Connect standards. It works for both the Next.js App Router and Pages Router.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Encrypted cookie-based sessions with optional CSRF token protection
- **Token handling** - Automatic access token refresh and validation
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

<br>

---

<br>

## Table of Contents

- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the Auth SDK](#1-initialize-the-auth-sdk)
  - [2) Set Up Session Management](#2-set-up-session-management)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Session Endpoint](#session-endpoint)
    - [Token Endpoint (Optional)](#token-endpoint-optional)
  - [4) Protect Your Pages, Actions, and APIs](#4-protect-your-pages-actions-and-apis)
    - [Set Up Authentication Middleware](#set-up-authentication-middleware)
    - [Protect Server Actions (App Router Only)](#protect-server-actions-app-router-only)
    - [Manual Session Access (Optional)](#manual-session-access-optional)
  - [5) Pass Your Access Token to Downstream APIs](#5-pass-your-access-token-to-downstream-apis)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
  - [Auth Config Options](#auth-config-options)
  - [createWristbandAuth()](#createwristbandauth)
- [Auth API](#auth-api)
  - [login()](#login)
  - [callback()](#callback)
  - [createCallbackResponse() (App Router)](#createcallbackresponse-app-router)
  - [logout()](#logout)
  - [refreshTokenIfExpired()](#refreshtokenifexpired)
- [Session Management](#session-management)
  - [Session Configuration](#session-configuration)
  - [The Session Object](#the-session-object)
  - [Session Helper Functions](#session-helper-functions)
    - [getSessionFromRequest()](#getsessionfromrequest)
    - [getPagesRouterSession()](#getpagesroutersession)
    - [getReadOnlySessionFromCookies()](#getreadonlysessionfromcookies)
    - [getMutableSessionFromCookies()](#getmutablesessionfromcookies)
    - [saveSessionWithCookies()](#savesessionwithcookies)
    - [destroySessionWithCookies()](#destroysessionwithcookies)
  - [Session Access Patterns](#session-access-patterns)
  - [Session API](#session-api)
    - [session.fromCallback()](#sessionfromcallbackcallbackdata-customfields)
    - [session.save()](#sessionsave)
    - [session.saveToResponse()](#sessionsavetoresponseresponse)
    - [session.destroy()](#sessiondestroy)
    - [session.destroyToResponse()](#sessiondestroytoresponseresponse)
    - [session.getSessionResponse()](#sessiongetsessionresponsemetadata)
    - [session.getTokenResponse()](#sessiongettokenresponse)
  - [CSRF Protection](#csrf-protection)
- [Authentication Middleware](#authentication-middleware)
  - [createMiddlewareAuth()](#createmiddlewareauth)
    - [SESSION Strategy](#session-strategy)
    - [JWT Strategy](#jwt-strategy)
    - [Middleware Chaining](#middleware-chaining) 
  - [createServerActionAuth()](#createserveractionauth)
- [Related Wristband SDKs](#related-wristband-sdks)
- [Wristband Multi-Tenant Next.js Demo Apps](#wristband-multi-tenant-nextjs-demo-apps)
- [Questions](#questions)

<br>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 4.x](migration/v4/README.md)
- [Instructions for migrating to Version 3.x](migration/v3/README.md)
- [Instructions for migrating to Version 2.x](migration/v2/README.md)

<br>

## Prerequisites

> **⚡ Try Our Next.js Quickstart!**
>
> For the fastest way to get started with Next.js authentication, follow our [Quick Start Guide](https://docs.wristband.dev/docs/auth-quick-start). It walks you through setting up a working Next.js app with Wristband authentication in minutes. Refer back to this README for comprehensive documentation and advanced usage patterns.

Before installing, ensure you have:

- [Node.js](https://nodejs.org/en) >= 20.0.0
- [Next.js](https://nextjs.org/) >= 14.0.0
- Your preferred package manager (npm >= 9.6.0, yarn, pnpm, etc.)

<br>

## Installation

```bash
# With npm
npm install @wristband/nextjs-auth

# Or with yarn
yarn add @wristband/nextjs-auth

# Or with pnpm
pnpm add @wristband/nextjs-auth
```

<br>

## Usage

### 1) Initialize the Auth SDK

First, create an instance of `WristbandAuth` in your Next.js directory structure in any location of your choice (i.e. `src/wristband.ts`). Then, you can export this instance and use it across your project. When creating an instance, you provide all necessary configurations for your application to correlate with how you've set it up in the Wristband Dashboard.

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/nextjs-auth';

/**
 * Wristband authentication instance for handling login, callback, and logout flows.
 */ 
export const wristbandAuth = createWristbandAuth({
  clientId: "replace-me-with-your-client-id",
  clientSecret: "replace-me-with-your-client-secret",
  wristbandApplicationVanityDomain: "replace-me-with-your-vanity-domain",
});
```

> **💡 Disabling Secure Cookies in Local Development**
>
> By default, `WristbandAuth` creates secure cookies (for tracking login state), meaning they are only sent over HTTPS connections. Most browsers make an exception for localhost and allow secure cookies to be sent over HTTP (e.g., http://localhost). However, some browsers, such as Safari, enforce stricter rules and never send secure cookies over HTTP, even for localhost. If you need to disable the secure cookies for local development, set `dangerouslyDisableSecureCookies: true`. However, be sure to **re-enable secure cookies before deploying to production**.

<br>

### 2) Set Up Session Management

Wristband provides encrypted cookie-based session management built directly into this SDK, powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). Add basic session configuration to enable the auth endpoints (Login, Callback, etc.) in the next steps.

#### App Router

```typescript
// src/wristband.ts (continued - add to existing file)
import { NextRequest } from 'next/server';
import { getSessionFromRequest, SessionOptions } from '@wristband/nextjs-auth';

// ...

/**
 * Session configuration for authentication.
 * 
 * IMPORTANT: Use a strong 32+ character secret in production and set secure: true
 */
const sessionOptions: SessionOptions = {
  secrets: 'dummyval-b5c1-463a-812c-0d8db87c0ec5',  // 32+ character secret
  maxAge: 3600, // 1 hour in seconds
  secure: process.env.NODE_ENV === 'production',  // Must be true in Production
};

/**
 * Retrieves the session from a NextRequest.
 * 
 * Use in:
 * - App Router API Route Handlers
 * - Middleware/proxy functions
 */
export function getRequestSession(request: NextRequest) {
  return getSessionFromRequest(request, sessionOptions);
}
```

#### Pages Router

```typescript
// src/wristband.ts (continued - add to existing file)
import * as http from 'http';
import { getPagesRouterSession, SessionOptions } from '@wristband/nextjs-auth';

// ...

/**
 * Session configuration for authentication.
 * 
 * IMPORTANT: Use a strong 32+ character secret in production and set secure: true
 */
const sessionOptions: SessionOptions = {
  secrets: 'dummyval-b5c1-463a-812c-0d8db87c0ec5',  // 32+ character secret
  maxAge: 3600, // 1 hour in seconds
  secure: process.env.NODE_ENV === 'production',  // Must be true in Production
};

/**
 * Retrieves session from Pages Router API routes and SSR functions.
 * 
 * Use in:
 * - Pages Router API Route Handlers
 * - getServerSideProps()
 */
export function getSession(req: http.IncomingMessage, res: http.ServerResponse) {
  return getPagesRouterSession(req, res, sessionOptions);
}
```

<br>

### 3) Add Auth Endpoints

There are **four core API endpoints** your Next.js server should expose to facilitate authentication workflows in Wristband:

- Login Endpoint
- Callback Endpoint
- Logout Endpoint
- Session Endpoint

You'll need to add these endpoints to your Next.js API routes. There's also one additional endpoint you can implement depending on your authentication needs:

- Token Endpoint (optional)

<br>

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

##### App Router

```typescript
// src/app/api/auth/login/route.ts
import type { NextRequest } from 'next/server';
import { wristbandAuth } from '../../../../wristband';

// Login Endpoint at "/api/auth/login" (route can be wherever you prefer)
export async function GET(req: NextRequest) {
  return await wristbandAuth.appRouter.login(req);
}
```

##### Pages Router

```typescript
// src/pages/api/auth/login.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { wristbandAuth } from '../../../wristband';

// Login Endpoint at "/api/auth/login" (route can be wherever you prefer)
export default async function loginEndpoint(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  const authorizeUrl = await wristbandAuth.pagesRouter.login(req, res);
  res.redirect(authorizeUrl);
}
```

<br>

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

##### App Router

```typescript
// src/app/api/auth/callback/route.ts
import { NextRequest } from 'next/server';
import { getRequestSession, wristbandAuth } from '../../../../wristband';

// Callback Endpoint at "/api/auth/callback" (route can be wherever you prefer)
export async function GET(req: NextRequest) {
  const callbackResult = await wristbandAuth.appRouter.callback(req);
  const { callbackData, redirectUrl, type } = callbackResult;

  if (type === 'redirect_required') {
    return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
  }
  
  // Set authentication data into the session
  const session = await getRequestSession(req);
  session.fromCallback(callbackData);

  // Create the response that will send the user back to your application.
  const appUrl = callbackData.returnUrl || `<your_app_home_url>`;
  const callbackResponse = await wristbandAuth.appRouter.createCallbackResponse(req, appUrl);

  // Save session headers to the response; then redirect to your app.
  return await session.saveToResponse(callbackResponse);
}
```

##### Pages Router

```typescript
// src/pages/api/auth/callback.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession, wristbandAuth } from '../../../wristband';

// Callback Endpoint at "/api/auth/callback" (route can be wherever you prefer)
export default async function callbackEndpoint(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  const callbackResult = await wristbandAuth.pagesRouter.callback(req, res);
  const { callbackData, redirectUrl, type } = callbackResult;

  if (type === 'redirect_required') {
    res.redirect(redirectUrl);
    return;
  }

  // Save authentication data in the session
  const session = await getSession(req, res);
  session.fromCallback(callbackData);
  await session.save();

  // Send the user back to the application.
  res.redirect(callbackData.returnUrl || `<your_app_home_url>`);
}
```

<br>

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

##### App Router

```typescript
// src/app/api/auth/logout/route.ts
import type { NextRequest } from 'next/server';
import { getRequestSession, wristbandAuth } from '../../../../wristband';

// Logout Endpoint at "/api/auth/logout" (route can be wherever you prefer)
export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);

  // Create the logout redirect response
  const logoutResponse = await wristbandAuth.appRouter.logout(req, {
    refreshToken: session.refreshToken,
    tenantCustomDomain: session.tenantCustomDomain,
    tenantName: session.tenantName,
  });

  // Always destroy session before redirecting.
  return await session.destroyToResponse(logoutResponse);
});
```

##### Pages Router

```typescript
// src/pages/api/auth/logout.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession, wristbandAuth } from '../../../wristband';

// Logout Endpoint at "/api/auth/logout" (route can be wherever you prefer)
export default async function logoutEndpoint(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  // Create the logout redirect URL
  const session = await getSession(req, res);
  const logoutUrl = await wristbandAuth.pagesRouter.logout(req, res, {
    refreshToken: session.refreshToken,
    tenantCustomDomain: session.tenantCustomDomain,
    tenantName: session.tenantName,
  });

  // Always destroy session before redirecting.
  session.destroy();
  res.redirect(logoutUrl);
});
```

<br>

#### Session Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Create a protected session endpoint that uses `session.getSessionResponse()` to return the session response format expected by Wristband's frontend SDKs. The response type will always have a `userId` and a `tenantId` in it. You can include any additional data for your frontend by customizing the `metadata` parameter (optional), which requires JSON-serializable values. **The response must not be cached**.

> **⚠️ Important:**
> This endpoint must be protected with authentication middleware, which is shown in [Section 4](#4-protect-your-pages-actions-and-apis).

##### App Router

```typescript
// src/app/api/auth/session/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../../wristband';

// Session Endpoint at "/api/auth/session" (route can be wherever you prefer)
export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  const sessionResponse = session.getSessionResponse({ foo: 'bar' });
  return NextResponse.json(sessionResponse, {
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
});
```

##### Page Router

```typescript
// src/pages/api/auth/session.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../../wristband';

// Session Endpoint at "/api/auth/session" (route can be wherever you prefer)
export default async function sessionEndpoint(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  const session = await getSession(req, res);
  const sessionResponse = session.getSessionResponse({ foo: 'bar' });
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.status(200).json(sessionResponse);
}
```

##### Response Type

The Session Endpoint returns the `SessionResponse` type to your frontend:

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar",
    // Any other optional data you provide...
  }
}
```

<br>

#### Token Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time without exposing it in the session cookie or in browser storage.

Create a protected token endpoint that uses `session.getTokenResponse()` to return the token data expected by Wristband's frontend SDKs. **The response must not be cached**.

> **⚠️ Important:**
> This endpoint must be protected with authentication middleware, which is shown in [Section 4](#4-protect-your-pages-actions-and-apis).

##### App Router

```typescript
// src/app/api/auth/token/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../../wristband';

// Token Endpoint at "/api/auth/token" (route can be wherever you prefer)
export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  const tokenResponse = session.getTokenResponse();
  return NextResponse.json(tokenResponse, {
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
});
```

##### Page Router

```typescript
// src/pages/api/auth/token.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../../wristband';

// Token Endpoint at "/api/auth/token" (route can be wherever you prefer)
export default async function tokenEndpoint(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  const session = await getSession(req, res);
  const tokenResponse = session.getTokenResponse();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.status(200).json(tokenResponse);
}
```

##### Response Type

The Token Endpoint returns the `TokenResponse` type to your frontend:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:

```typescript
const tokenResponse = await fetch('/api/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https://<your-wristband-app-vanity-domain>/api/v1/users/123', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

<br>

### 4) Protect Your Pages, Actions, and APIs

Once your auth endpoints are set up, protect your application routes with authentication middleware and add session helpers for accessing session data in different contexts.

#### Set Up Authentication Middleware

In Next.js, middleware (or proxy in Next.js 16+) is the ideal place to centralize authentication checks and token refresh for most scenarios. The authentication middleware works with both App Router and Pages Router, but has important differences in what it protects:

**What middleware protects:**
- ✅ **API Routes** (App and Pages Router) - All routes matching `protectedApis` patterns
- ✅ **Session & Token Endpoints** - `/api/auth/session` and `/api/auth/token` are automatically protected when using `SESSION` strategy (customizable via `sessionConfig.sessionEndpoint` and `sessionConfig.tokenEndpoint` config)
- ✅ **Pages** (Pages Router) - Server-rendered pages matching `protectedPages` patterns
- ✅ **Server Components that are pages** (App Router) - Page components matching `protectedPages` patterns

**What middleware does NOT protect:**
- ❌ **Server Actions** (App Router) - Must use `createServerActionAuth()` for manual checks
- ❌ **Server Components that are not pages** (App Router) - Server Components render during the RSC phase before middleware runs. Thus, only Server Components that are pages (route segments) are protected because they trigger a full page request that passes through middleware first.
- ❌ **Client Components** (App Router) - Client Components render in the browser after the initial page load. Authentication is enforced on the initial page request via middleware, but subsequent client-side auth state management should use Wristband's [@wristband/react-client-auth](https://github.com/wristband-dev/react-client-auth) frontend SDK.

Add middleware configuration to your `wristband.ts` file:

```typescript
// src/wristband.ts (continued - add to existing file)

// ...

/**
 * Authentication middleware that protects routes in Next.js middleware.
 * 
 * Automatically handles:
 * - Session validation for protected routes
 * - Token refresh when access tokens expire
 * - 401 responses for unauthenticated API requests
 * - Login redirects for unauthenticated page requests
 */
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: { sessionOptions },
  protectedApis: ['/api/v1(.*)'],  // Regex patterns for protected API routes
  protectedPages: ['/', '/dashboard', '/settings(.*)'],  // Regex patterns for protected pages
});
```

Now create the middleware or proxy file (depending on your version of Next.js) at the root of your `src` directory (or project root if not using `src`).

**Next.js 16+**:

```typescript
// src/proxy.ts
import { NextRequest } from 'next/server';
import { requireMiddlewareAuth } from './wristband';

export async function proxy(req: NextRequest) {
  return await requireMiddlewareAuth(req);
}

export const config = {
  /*
   * Match all paths except for:
   * 1. /_next (Next.js internals)
   * 2. /fonts (inside /public)
   * 3. /examples (inside /public)
   * 4. all root files inside /public (e.g. /favicon.ico)
   */
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

**Next.js 15 and earlier**:

```typescript
// src/middleware.ts
import { NextRequest } from 'next/server';
import { requireMiddlewareAuth } from './wristband';

export async function middleware(req: NextRequest) {
  return await requireMiddlewareAuth(req);
}

export const config = {
  /*
   * Match all paths except for:
   * 1. /_next (Next.js internals)
   * 2. /fonts (inside /public)
   * 3. /examples (inside /public)
   * 4. all root files inside /public (e.g. /favicon.ico)
   */
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

The middleware automatically:

- ✅ **Validates authentication** - Checks each auth strategy in order until one succeeds
- ✅ **Refreshes expired tokens** - When using `SESSION` strategy AND when `refreshToken` and `expiresAt` are present in session
- ✅ **Extends session expiration** - Rolling session window on each authenticated request (`SESSION` strategy only)
- ✅ **Returns 401 for API Routes** - Unauthenticated requests to protected API routes
- ✅ **Redirects pages to login** - Unauthenticated requests to protected pages (customizable via `onPageUnauthenticated`)
- ✅ **Auto-protects auth endpoints** - Session and Token Endpoints protected by default (`SESSION` strategy only)
- ✅ **Auto-bypasses Server Actions** - Server Action routes skip middleware protection (must manually check auth)

<br>

#### Protect Server Actions (App Router Only)

Server Actions are **not protected by middleware** because they execute as POST requests to internal Next.js endpoints that bypass the middleware/proxy layer. Add the Server Action auth helper to your Wristband file:

```typescript
// src/wristband.ts (continued - add to existing file)

// ...

/**
 * Authentication helper for Server Actions.
 * 
 * Server Actions bypass Next.js middleware, so they must perform their own auth checks.
 * This helper validates the session and automatically refreshes expired tokens.
 */
export const requireServerActionAuth = wristbandAuth.appRouter.createServerActionAuth({
  sessionOptions,
});
```

Here's an example of how to use it in your Server Actions:

```typescript
// src/app/actions/my-action.ts
'use server';

import { cookies } from 'next/headers';
import { requireServerActionAuth } from './wristband';

export async function updateUserProfile(formData: FormData) {
  // The helper function will return you the current session if authentication succeeds.
  const cookieStore = await cookies();
  const { authenticated, reason, session } = await requireServerActionAuth(cookieStore);
  
  // Check authentication result
  if (!authenticated) {
    return { error: 'Unauthorized', reason };
  }

  // Access the authenticated session
  const { userId } = session;

  // ...your business logic here...

  return { success: true };
}
```

<br>

#### Manual Session Access (Optional)

In most cases, middleware and `createServerActionAuth()` handle all authentication needs. For advanced use cases where you need direct session access for custom logic, conditional rendering, or fine-grained session mutations, you can manually retrieve session data in the following contexts:

- **API Route Handlers** (App Router & Pages Router)
- **Server Components** (App Router) - Read-only access
- **Server Actions** (App Router) - For advanced session mutations beyond `createServerActionAuth()`
- **`getServerSideProps()`** (Pages Router)

##### App Router: Server Components (Read-Only)

Be aware that Server Components cannot modify sessions (read-only) because they render during the RSC (React Server Components) phase where response headers and cookies cannot be set. If you need to read session data in a Server Component, add this helper:

```typescript
// src/wristband.ts (continued - add to existing file)
import { getReadOnlySessionFromCookies, NextJsCookieStore } from '@wristband/nextjs-auth';

// ...

/**
 * Retrieves read-only session for Server Components.
 */
export function getServerComponentSession(cookieStore: NextJsCookieStore) {
  return getReadOnlySessionFromCookies(cookieStore, sessionOptions);
}
```

Here's an example of how to use it in your Server Components:

```typescript
// src/app/dashboard/page.tsx
import { cookies } from 'next/headers';
import { getServerComponentSession } from '../../wristband';

export default async function DashboardPage() {
  const cookieStore = await cookies();
  const session = await getServerComponentSession(cookieStore);
  const { isAuthenticated, userId } = session;

  if (!isAuthenticated) {
    return <div>Please log in.</div>;
  }

  return <div>Welcome, {userId}</div>;
}
```

##### App Router: Server Actions (Advanced)

For advanced use cases where you need direct session manipulation without using `createServerActionAuth()`, add these helpers:

```typescript
// src/wristband.ts (continued - add to existing file)
import {
  getMutableSessionFromCookies,
  saveSessionWithCookies,
  destroySessionWithCookies,
  MutableSession,
} from '@wristband/nextjs-auth';

// ...

/**
 * Retrieves mutable session for Server Actions.
 * Call saveServerActionSession() after modifying to persist changes.
 */
export async function getServerActionSession(cookies: NextJsCookieStore) {
  return await getMutableSessionFromCookies(cookies, sessionOptions);
}

/**
 * Saves modified session data back to cookies (Server Actions only).
 */
export async function saveServerActionSession(cookies: NextJsCookieStore, session: MutableSession) {
  await saveSessionWithCookies(cookies, session);
}

/**
 * Destroys session and clears cookies (Server Actions only).
 */
export function destroyServerActionSession(cookies: NextJsCookieStore, session: MutableSession) {
  destroySessionWithCookies(cookies, session);
}
```

Here's an example of how to use it in your Server Actions:

```typescript
// src/app/actions/my-action.ts
'use server';

import { cookies } from 'next/headers';
import {
  destroyServerActionSession,
  getServerActionSession, 
  saveServerActionSession
} from '../../wristband';

export async function customAction() {
  // Get session (without performing auth check)
  const cookieStore = await cookies();
  const session = await getServerActionSession(cookieStore);

  // Manually peform auth check
  if (!session.isAuthenticated) {
    // Destroy session
    destroyServerActionSession(cookieStore, session);
    return { error: 'Unauthorized' };
  }

  // Modify session and save changes
  session.customField = 'value';
  await saveServerActionSession(cookieStore, session);

  return { success: true };
}
```

##### App Router: API Routes

API routes for the App Router can use the `getRequestSession()` helper already defined in [Section 2](#2-set-up-session-management):

```typescript
// src/app/api/orders/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);

  if (!session.isAuthenticated) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return NextResponse.json({ orders: [], userId: session.userId });
}
```

##### Pages Router: API Routes and getServerSideProps()

API routes for the Pages Router can use the `getSession()` helper already defined in [Section 2](#2-set-up-session-management):

**API Route:**

```typescript
// src/pages/api/profile.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../wristband';

export default async function apiRouteHandler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);

  if (!session.isAuthenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return res.json({ userId: session.userId });
}
```

**SSR:**

```typescript
// pages/dashboard.tsx
import type { GetServerSideProps } from 'next';
import { getSession } from '../wristband';

export const getServerSideProps: GetServerSideProps = async (context) => {
  const session = await getSession(context.req, context.res);

  if (!session.isAuthenticated) {
    return {
      redirect: { destination: '/api/auth/login', permanent: false },
    };
  }

  return {
    props: { userId: session.userId },
  };
};

export default function Dashboard({ userId }: { userId: string }) {
  return <div>Welcome, {userId}</div>;
}
```

<br>

### 5) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```bash
Authorization: Bearer <access_token_value>
```

For example, if you were using attempting to fetch user data from Wristband in an API route, you would pass the access token from your application session into the `Authorization` header as follows:

```typescript
const session = await getRequestSession(req);
const { accessToken, userId } = session;

const userResponse = await fetch(`https://yourapp-yourcompany.us.wristband.dev/api/v1/users/${userId}`, {
  method: 'GET',
  headers: { Authorization: `Bearer ${accessToken}` },
});

if (userResponse.status === 401) {
  redirect('/api/auth/login');
  return null;
}

const user = await userResponse.json();

console.log(user); // Output -> { id: 123, ... }
```

#### Using Access Tokens from the Frontend

For scenarios where your frontend needs to make direct API calls with the user's access token, use the [Token Endpoint](#token-endpoint-optional) to securely retrieve the current access token.

<br>

## Wristband Auth Configuration Options

The `createWristbandAuth()` function is used to instatiate the Wristband SDK.  It takes an `AuthConfig` type as an argument.

### Auth Config Options

`AuthConfig` contains the full set of options for integrating Wristband auth, including required, optional, and auto-configured values.

| AuthConfig Field | Type | Required | Auto-Configurable | Description |
| ---------------- | ---- | -------- | ----------------- | ----------- |
| autoConfigureEnabled | boolean | No | _N/A_ | Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown. |
| clientId | string | Yes | No | The ID of the Wristband client. |
| clientSecret | string | Yes | No | The client's secret. |
| customApplicationLoginPageUrl | string | No | Yes | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerouslyDisableSecureCookies | boolean | No | No | USE WITH CAUTION: If set to `true`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `false`. |
| isApplicationCustomDomainActive | boolean | No | Yes | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config.  Defaults to `false`. |
| loginStateSecret | string | No | No | A 32 character (or longer) secret used for encryption and decryption of login state cookies. If not provided, it will default to using the client secret. For enhanced security, it is recommended to provide a value that is unique from the client secret. You can run `openssl rand -base64 32` to create a secret from your CLI. |
| loginUrl | string | Yes | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` placeholder. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parseTenantFromRootDomain | string | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirectUri | string | Yes | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` placeholder. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | string[] | No | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `[openid, offline_access, email]`. |
| tokenExpirationBuffer | number | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| wristbandApplicationVanityDomain | string | Yes | No | The vanity domain of the Wristband application. |

<br>

### `createWristbandAuth()`

```ts
function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {}
```

This function creates an instance of `WristbandAuth` using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. `login`, `callback`, etc.). Set `autoConfigureEnabled` to `false` disable to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

>  **⚠️ Auto-Configuration in Edge Runtimes**
> 
> While auto-configuration works well in Node.js runtime environments, **manual configuration is strongly recommended when using Next.js Edge Runtime** (Edge API Routes, Middleware, and Edge-rendered pages) due to the following limitations:
>
> - **Cold start latency**: Auto-configuration requires an API call to the Wristband SDK Configuration Endpoint on every cold start, which can impact response times for authentication flows in Edge Runtime.
> - **No persistent memory**: Edge Runtime instances don't maintain in-memory caches between requests, causing the SDK to refetch configuration data on every invocation
>
> For production Next.js applications using Edge Runtime, you can set `autoConfigureEnabled: false` and provide all required configuration values manually. This is especially critical for authentication middleware that runs on every protected route.

**Minimal config with auto-configure (default behavior)**
```ts
const auth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io"
});
```

**Manual override with partial auto-configure for some fields**
```ts
const auth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
  loginUrl: "https://yourapp.io/auth/login", // Manually override "loginUrl"
  // "redirectUri" will be auto-configured
});
```

**Auto-configure disabled**
```ts
const auth = createWristbandAuth({
  autoConfigureEnabled: false,
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.custom.com",
  // Must manually configure non-auto-configurable fields
  isApplicationCustomDomainActive: true,
  loginUrl: "https://{tenant_domain}.custom.com/auth/login",
  redirectUri: "https://{tenant_domain}.custom.com/auth/callback",
  parseTenantFromRootDomain: "custom.com",
});
```

<br>

## Auth API

### login()

```ts
/* *** App Router *** */
// Definition
login: (req: NextRequest, loginConfig?: LoginConfig) => Promise<NextResponse>;
// Usage
return await wristbandAuth.appRouter.login(req);

/* *** Pages Router *** */
// Definition
login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig) => Promise<string>;
// Usage
const authorizeUrl = await wristbandAuth.pagesRouter.login(req, res);
res.redirect(authorizeUrl);
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your Next.js Login Endpoint, there are two ways to accomplish getting the `tenantName` information: passing a query parameter or using tenant subdomains.

The `login()` function can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| customState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| defaultTenantName | string | No | An optional default tenant name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| defaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| returnUrl | string | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if subdomains are enabled and the subdomain is present.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is detected.
4. `defaultTenantCustomDomain` in LoginConfig: Used if none of the above are present.
5. `defaultTenantDomain` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/api/auth/login?tenant_domain=customer01
```

Your AuthConfig would look like the following when creating an SDK instance without any subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://yourapp.io/auth/login",
  redirectUri: "https://yourapp.io/auth/callback",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Next.js Login Endpoint. The SDK will parse the tenant subdomain from the URL in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.io/api/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  parseTenantFromRootDomain: "yourapp.io",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that the `login()` function cannot find a tenant name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant name via a `LoginConfig` object. For example:

```ts
await wristbandAuth.pagesRouter.login(req, res, { defaultTenantName: 'default' });
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `login()` function cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```ts
await wristbandAuth.appRouter.login(req, { defaultTenantCustomDomain: 'mytenant.com' });
```

The default tenant custom domain takes precedence over all other possible domains else when present except when the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object. For example:

```ts
await wristbandAuth.appRouter.login(req, { customState: { test: 'abc' } });
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `customState` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `customState` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your Next.js Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/api/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.

Given that your frontend will redirect users to your Login Endpoint, you can either include it in your Login Config or pass a `return_url` query parameter when redirecting to your Login Endpoint. The URL will be available to you upon completion of the Callback Endpoint. The Login Config takes precedence over the query parameter in the event a value is provided for both.

**Passing a return URL in the Login Config**
```ts
const loginUrl = await wristbandAuth.pagesRouter.login(req, res, {
  returnUrl: 'https://customer01.yourapp.io/settings/profile',
});
res.redirect(loginUrl);
```

**Passing a return URL as a query parameter**
```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and you can choose to send users to that return URL (if necessary) after the SDK's `callback()` funciton is done executing.

<br>

### callback()

```ts
/* *** App Router *** */
// Definition
callback: (req: NextRequest) => Promise<CallbackResult>;
createCallbackResponse: (req: NextRequest, redirectUrl: string) => NextResponse;

// Usage
const callbackResult = await wristbandAuth.appRouter.callback(req);
return await wristbandAuth.appRouter.createCallbackResponse(req, appUrl);

/* *** Pages Router *** */
// Definition
callback: (req: NextApiRequest, res: NextApiResponse) => Promise<CallbackResult>;

// Usage
const callbackResult = await wristbandAuth.pagesRouter.callback(req, res);
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Next.js Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/api/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback function is a `CallbackResult` object containing the result of what happened during callback execution as well as any accompanying data.

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callbackData | CallbackData or `undefined` | The callback data received after authentication (`completed` result only). |
| reason | CallbackFailureReason or `undefined` | The reason why the callback did not complete successfully (`'redirect_required'` only). |
| redirectUrl | string or `undefined` | The URL that the user should redirected to (`redirect_required` only). |
| type | CallbackResultType | String literal representing the end result of callback execution.<br><br> Possible values: `completed` or `redirect_required`. |

<br>

The `CallbackResultType` can be one of the following string literal values:

| CallbackResultType | Description |
| ------------------ | ----------- |
| `completed` | Indicates that the callback is successfully completed and data is available for creating a session. |
| `redirect_required` | Indicates that a redirect is required, generally to a login route or page. |

<br>

When the callback returns a `'redirect_required'` result, the `reason` field indicates why the callback failed:

| CallbackFailureReason | Description |
| --------------------- | ----------- |
| `'missing_login_state'` | Login state cookie was not found (cookie expired or bookmarked callback URL). |
| `'invalid_login_state'` | Login state validation failed (security check to prevent CSRF attacks). |
| `'login_required'` | Wristband returned a login_required error (session expired or max_age elapsed). |
| `'invalid_grant'` | Authorization code was invalid, expired, or already used. |

<br>

When the callback returns a `completed` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:

| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| customState | JSON or `undefined` | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expiresAt | number | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| expiresIn | number | The duration from the current time until the access token is expired (in seconds). The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| returnUrl | string or `undefined` | The URL to return to after authentication is completed. |
| tenantCustomDomain | string | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantName | string | The name of the tenant the user belongs to. |
| userinfo | JSON | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |

The `UserInfo` type is defined as follows:

| UserInfo Field | Type | Always Returned | Description |
| -------------- | ---- | --------------- | ----------- |
| userId | string | Yes | ID of the user (mapped from "sub" claim). |
| tenantId | string | Yes | ID of the tenant that the user belongs to (mapped from "tnt_id" claim). |
| applicationId | string | Yes | ID of the application that the user belongs to (mapped from "app_id" claim). |
| identityProviderName | string | Yes | Name of the identity provider (mapped from "idp_name" claim). |
| fullName | string or `undefined` | No | End-User's full name in displayable form (mapped from "name" claim; requires `profile` scope). |
| givenName | string or `undefined` | No | Given name(s) or first name(s) of the End-User (requires `profile` scope). |
| familyName | string or `undefined` | No | Surname(s) or last name(s) of the End-User (requires `profile` scope). |
| middleName | string or `undefined` | No | Middle name(s) of the End-User (requires `profile` scope). |
| nickname | string or `undefined` | No | Casual name of the End-User (requires `profile` scope). |
| displayName | string or `undefined` | No | Shorthand name by which the End-User wishes to be referred (requires `profile` scope). |
| pictureUrl | string or `undefined` | No | URL of the End-User's profile picture (requires `profile` scope). |
| email | string or `undefined` | No | End-User's preferred email address (requires `email` scope). |
| emailVerified | boolean or `undefined` | No | True if the End-User's email address has been verified (requires `email` scope). |
| gender | string or `undefined` | No | End-User's gender (requires `profile` scope). |
| birthdate | string or `undefined` | No | End-User's birthday in YYYY-MM-DD format (requires `profile` scope). |
| timeZone | string or `undefined` | No | End-User's time zone (requires `profile` scope). |
| locale | string or `undefined` | No | End-User's locale as BCP47 language tag, e.g., "en-US" (requires `profile` scope). |
| phoneNumber | string or `undefined` | No | End-User's telephone number in E.164 format (requires `phone` scope). |
| phoneNumberVerified | boolean or `undefined` | No | True if the End-User's phone number has been verified (requires `phone` scope). |
| updatedAt | number or `undefined` | No | Time the End-User's information was last updated as Unix timestamp (requires `profile` scope). |
| roles | `UserInfoRole[]` or `undefined` | No | The roles assigned to the user (requires `roles` scope). |
| customClaims | `Record<string, any>` or `undefined` | No | Object containing any configured custom claims. |

The `UserInfoRole` type is defined as follows:

| UserInfoRole Field | Type | Description |
| ------------------ | ---- | ----------- |
| id | string | Globally unique ID of the role. |
| name | string | The role name (e.g., "app:app-name:admin"). |
| displayName | string | The human-readable display name for the role. |

<br>

#### Redirect Responses

There are certain scenarios where instead of callback data being returned by the SDK, a redirect URL is returned instead.  The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Tenant-Level Login Page URL.

In these events, the your application should redirect the user to that location.

#### Error Parameters

Certain edge cases are possible where Wristband encounters an error during the processing of an auth request. These are the following query parameters that are sent for those cases to your Callback Endpoint:

| Query Parameter | Description |
| --------------- | ----------- |
| error | Indicates an error that occurred during the Login Workflow. |
| error_description | A human-readable description or explanation of the error to help diagnose and resolve issues more effectively. |

```sh
GET https://customer01.yourapp.io/api/auth/callback?state=f983yr893hf89ewn0idjw8e9f&error=login_required&error_description=User%20must%20re-authenticate%20because%20the%20specified%20max_age%20value%20has%20elapsed
```

The error types that get automatically resolved in the SDK are:

| Error | Description |
| ----- | ----------- |
| login_required | Indicates that the user needs to log in to continue. This error can occur in scenarios where the user's session has expired, the user is not currently authenticated, or Wristband requires the user to explicitly log in again for security reasons. |

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.

<br>

### createCallbackResponse() (App Router)

```typescript
/* *** App Router *** */
// Definition
createCallbackResponse: (req: NextRequest, redirectUrl: string) => Promise<NextResponse>;

// Usage
const appUrl = callbackData.returnUrl || `https://yourapp.io/home`;
return await wristbandAuth.appRouter.createCallbackResponse(req, appUrl);
```

When using the App Router, there is a second callback-related function called `createCallbackResponse()` you must use to create the appropriate redirect response to your application's destination URL while ensuring the proper response headers are set.

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | NextRequest | Yes | The Next.js request object. |
| redirectUrl | string | Yes | The URL to redirect the user to after authentication completes. |

```typescript
// App Router: Callback endpoint
import { NextRequest } from 'next/server';
import { getRequestSession, wristbandAuth } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const callbackResult = await wristbandAuth.appRouter.callback(req);
  const { callbackData, redirectUrl, type } = callbackResult;

  // Handle redirect required scenario
  if (type === 'redirect_required') {
    return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
  }
  
  // Handle successful authentication
  const session = await getRequestSession(req);
  session.fromCallback(callbackData);

  // Create callback response with your app's destination URL
  const appUrl = callbackData.returnUrl || '/dashboard';
  const callbackResponse = await wristbandAuth.appRouter.createCallbackResponse(req, appUrl);
  
  // Save session and return response
  return await session.saveToResponse(callbackResponse);
}
```

<br>

### logout()

```ts
/* *** App Router *** */
// Definition
logout: (req: NextRequest, logoutConfig?: LogoutConfig) => Promise<NextResponse>;
// Usage
return await wristbandAuth.appRouter.logout(req, { refreshToken: '98yht308hf902hc90wh09' });

/* *** Pages Router *** */
// Definition
logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig) => Promise<string>;
// Usage
const logoutUrl = await wristbandAuth.pagesRouter.logout(req, res, { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

When users of your application are ready to log out and/or their application session expires, your frontend should redirect the user to your Next.js Logout Endpoint.

```sh
GET https://customer01.yourapp.io/api/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` function.  This function can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| redirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed.  |
| refreshToken | string | No | The refresh token to revoke. |
| state | string | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| tenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantName | string | No | The name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. `tenantName` in LogoutConfig: This takes the next priority if `tenantCustomDomain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenantCustomDomain` or `tenantName`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parseTenantFromRootDomain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` function, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domains

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you will need to explicitly pass it into the LogoutConfig:

```ts
// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, { refreshToken: '98yht308hf902hc90wh09', tenantName: 'customer01' });

// App Router
await wristbandAuth.appRouter.logout(req, { refreshToken: '98yht308hf902hc90wh09', tenantName: 'customer01' });
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to your Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_domain=customer01"
//
// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, { refreshToken: '98yht308hf902hc90wh09' });

// App Router
await wristbandAuth.appRouter.logout(req, { refreshToken: '98yht308hf902hc90wh09' });
```

If your application uses tenant subdomains, then passing the `tenantName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parseTenantFromRootDomain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```ts
const logoutConfig = {
  refreshToken: '98yht308hf902hc90wh09',
  tenantCustomDomain: 'mytenant.com'
};

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, logoutConfig);

// App Router
await wristbandAuth.appRouter.logout(req, logoutConfig);
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to your Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
//
const logoutConfig = {
  refreshToken: '98yht308hf902hc90wh09',
};

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, logoutConfig);

// App Router
await wristbandAuth.appRouter.logout(req, logoutConfig);
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

#### Preserving State After Logout

The `state` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```ts
const logoutConfig = {
  refreshToken: '98yht308hf902hc90wh09',
  state: 'user_initiated_logout',
  tenantName: 'customer01'
};

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, logoutConfig);

// App Router
await wristbandAuth.appRouter.logout(req, logoutConfig);
```

The state value gets appended as a query parameter to the Wristband Logout Endpoint URL:

```sh
https://customer01.auth.yourapp.io/api/v1/logout?client_id=123&state=user_initiated_logout
```

After logout completes, Wristband will redirect to your configured redirect URL (either your Login Endpoint by default, or a custom logout redirect URL if configured) with the `state` parameter included:

```sh
https://yourapp.io/auth/login?tenant_domain=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```ts
const logoutConfig = {
  redirectUrl: 'https://custom-logout.com',
  refreshToken: '98yht308hf902hc90wh09',
  tenantName: 'customer01'
};

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, logoutConfig);

// App Router
await wristbandAuth.appRouter.logout(req, logoutConfig);
```

<br>

### refreshTokenIfExpired()

```ts
// Definition (App Router & Pages Router)
refreshTokenIfExpired: (refreshToken: string, expiresAt: number) => Promise<TokenData | null>;

// Usage (App Router & Pages Router)
const tokenData = await wristbandAuth.refreshTokenIfExpired('98yht308hf902hc90wh09', 1710707503788);
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expiresAt | number | Yes | Unix timestamp in milliseconds at which the token expires. |
| refreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refreshTokenIfExpired()` functions finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expiresAt | number | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| expiresIn | number | The duration from the current time until the access token is expired (in seconds). The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

## Session Management

This SDK provides encrypted cookie-based session management powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). Sessions are automatically created and managed through the SDK's auth endpoints and middleware, with session data encrypted using AES-256-GCM before being stored in cookies.

Sessions in Next.js work differently depending on the context:

- **Middleware & API Routes** - Full read/write access. Changes are persisted by calling `session.saveToResponse()` which adds session cookies to the response headers.
- **Server Components (non-page)** - Read-only access (cannot modify, save, or destroy sessions because response headers cannot be set during the RSC rendering phase).
- **Server Actions** - Full read/write access. Changes are persisted by calling `saveSessionWithCookies()` which uses Next.js's `cookies()` API to set session cookies.
- **Pages Router** - Full read/write access. Changes are persisted by calling `session.save()` which automatically sets cookies on the response object managed by Next.js.

The following sections provide comprehensive documentation on session configuration, authentication middleware, helper functions, and session methods.

<br>

### Session Configuration

Session behavior is configured when you create your session helper functions in your Wristband configuration file (typically `src/wristband.ts`). The configuration is shared across all session contexts (middleware, API routes, Server Components, Server Actions).

```typescript
// src/wristband.ts
import { SessionOptions } from '@wristband/nextjs-auth';

const sessionOptions: SessionOptions = {
  // Session cookie configs
  cookieName: 'session',
  secrets: 'your-secret-key-min-32-chars',
  domain: 'app.example.com',
  maxAge: 3600,
  path: '/',
  sameSite: 'lax',
  secure: true,

  // Optional CSRF token protection configs
  enableCsrfProtection: true,
  csrfCookieName: 'CSRF-TOKEN',
  csrfCookieDomain: '.example.com',
};
```

#### Configuration Options

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| secrets | string or string[] | Yes | N/A | Secret key(s) for session encryption (minimum 32 characters). Can be a single string or array of strings for key rotation. Run `openssl rand -base64 32` to generate a secret. |
| cookieName | string | No | `session` | Name of the session cookie. |
| maxAge | number | No | 3600 (1 hour) | Cookie expiration time in seconds. |
| secure | boolean | No | `true` | Require HTTPS for cookies. **Must be `true` in production.** Set to `false` only for local development without HTTPS. |
| sameSite | `lax` \| `strict` \| `none` | No | `lax` | Cookie SameSite attribute. |
| path | string | No | `/` | Cookie path. |
| domain | string | No | `undefined` | Domain for the session cookie. When undefined, the cookie is only sent to the current domain. |
| enableCsrfProtection | boolean | No | `false` | When enabled, a CSRF token is automatically generated after authentication (via  `session.save()` and other save functions) and is stored in the session. A separate CSRF cookie is also set in addition to the session cookie. If using `createMiddlewareAuth()`, that will also automatically enable CSRF token validaiton for protected API requests when using the `SESSION` strategy. |
| csrfCookieName | string | No | `CSRF-TOKEN` | Name of the CSRF cookie (only used when `enableCsrfProtection` is `true`). |
| csrfCookieDomain | string | No | `undefined` | Domain for the CSRF cookie. Defaults to the `domain` value if not specified. |

For complete details on session configuration options, see the [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session#sessionoptions) documentation.

<br>

### The Session Object

Once session management is configured, you can access session data through the session object returned by the various session helper functions. The session contains both authentication data (populated after login) and any custom fields you define. The session data is typed using the `SessionData` interface from [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session?tab=readme-ov-file#typescript-support). You can access session data using both dictionary-style access (`session['key']`) and attribute-style access (`session.key`).

#### Understanding Session State

Sessions start empty. All base session fields are initially `undefined` because the session begins with no data. Session fields are only populated when you either:

- Call `session.fromCallback(callbackData)` after successful authentication (automatically sets all auth-related fields)
- Manually set fields and call `session.save()` (or any other save function) to persist them

This means before authentication, fields like `userId`, `accessToken`, etc. will be `undefined`.

#### Base Session Fields

These fields are automatically populated when you call `session.fromCallback()` after successful Wristband authentication:

| SessionData Field | Type | Description |
| ----------------- | ---- | ----------- |
| isAuthenticated | boolean or `undefined` | Whether the user is authenticated (set to `true` by `fromCallback()`). |
| accessToken | string or `undefined` | JWT access token for making authenticated API calls to Wristband and other services. |
| expiresAt | number or `undefined` | Token expiration timestamp (milliseconds since Unix epoch). Accounts for `tokenExpirationBuffer` from SDK config. |
| userId | string or `undefined` | Unique identifier for the authenticated user. |
| tenantId | string or `undefined` | Unique identifier for the tenant that the user belongs to. |
| tenantName | string or `undefined` | Name of the tenant that the user belongs to. |
| identityProviderName | string or `undefined` | Name of the identity provider that the user belongs to. |
| csrfToken | string or `undefined` | CSRF token for request validation. Automatically generated and stored when the session is saved (via `session.save()`, `session.saveToResponse()`, or `saveSessionWithCookies()`) if CSRF protection is enabled in `SessionOptions`. |
| refreshToken | string or `undefined` | Refresh token for obtaining new access tokens when they expire. Only present if `offline_access` scope was requested during authentication. |
| tenantCustomDomain | string or `undefined` | Custom domain for the tenant, if configured. Only present if a tenant custom domain was used during authentication. |

#### Extending SessionData with Custom Fields

You can extend the `SessionData` interface to add type-safe custom fields to your session:

```typescript
// src/types/session.ts
import { SessionData } from '@wristband/nextjs-auth';

/**
 * Custom session data type for this application.
 * Extends the base SessionData from the Wristband SDK with app-specific fields.
 */
export interface MySessionData extends SessionData {
  theme?: string;
  preferences?: {
    notifications: boolean;
    language: string;
  };
  lastActivity?: number;
}
```

Then use the generic type parameter when creating your session helpers. For example:

```typescript
// src/wristband.ts
import { getSessionFromRequest, SessionOptions } from '@wristband/nextjs-auth';
import { MySessionData } from './types/session';

const sessionOptions: SessionOptions = { secrets: 'your-secret-key-min-32-chars' };

export function getRequestSession(request: NextRequest) {
  // Add your custom type with generics on the Wristband SDK's session functions.
  return getSessionFromRequest<MySessionData>(request, sessionOptions);
}
```

Now your session will have full type safety for both base and custom fields:

```typescript
// src/app/api/settings/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../wristband';

export async function POST(req: NextRequest) {
  const session = await getRequestSession(req);
  
  session.theme = 'dark';    // ✅ Type-safe
  session.preferences = {    // ✅ Type-safe
    notifications: true,     // ✅ Type-safe
    language: 'en',          // ✅ Type-safe
  };
  
  return await session.saveToResponse(
    NextResponse.json({ success: true })
  );
}
```

<br>

### Session Helper Functions

The SDK provides context-specific helper functions for accessing sessions in different Next.js environments. These functions handle the underlying complexity of Next.js's various request/response patterns and return session objects appropriate for each context.

<br>

#### getSessionFromRequest()

Retrieves a session from a `NextRequest` object. Use this in App Router middleware, API route handlers, and other contexts where you have access to a `NextRequest`.

**Compatible Contexts:**

- App Router (API Routes)
- Middleware/Proxy

**Signature:**

```typescript
function getSessionFromRequest<T extends SessionData = SessionData>(
  request: NextRequest,
  options: SessionOptions
): Promise<Session<T> & T>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | `NextRequest` | Yes | The Next.js request object. |
| options | `SessionOptions` | Yes | [Session configuration](#session-configuration) options. |

**Usage:**

```typescript
// src/wristband.ts
import { NextRequest } from 'next/server';
import { getSessionFromRequest, SessionOptions } from '@wristband/nextjs-auth';

const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  secure: process.env.NODE_ENV === 'production',
};

export function getRequestSession(request: NextRequest) {
  return getSessionFromRequest(request, sessionOptions);
}
```
```typescript
// src/app/api/orders/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../wristband';

export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  
  if (!session.isAuthenticated) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  return NextResponse.json({ userId: session.userId });
}
```

<br>

#### getPagesRouterSession()

Retrieves a session from Pages Router's Node.js request and response objects. Use this in Pages Router API routes and `getServerSideProps()`.

**Compatible Contexts:**

- Pages Router

**Signature:**

```typescript
function getPagesRouterSession<T extends SessionData = SessionData>(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: SessionOptions
): Promise<Session<T> & T>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| req | `http.IncomingMessage` | Yes | Node.js incoming message (Pages Router request). |
| res | `http.ServerResponse` | Yes | Node.js server response (Pages Router response). |
| options | `SessionOptions` | Yes | [Session configuration](#session-configuration) options. |

**Usage:**

```typescript
// src/wristband.ts
import * as http from 'http';
import { getPagesRouterSession, SessionOptions } from '@wristband/nextjs-auth';

const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  secure: process.env.NODE_ENV === 'production',
};

export function getSession(req: http.IncomingMessage, res: http.ServerResponse) {
  return getPagesRouterSession(req, res, sessionOptions);
}
```
```typescript
// src/pages/api/profile.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../wristband';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  
  if (!session.isAuthenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  return res.json({ userId: session.userId });
}
```

<br>

#### getReadOnlySessionFromCookies()

Retrieves a read-only session from Next.js `cookies()` API. Use this in App Router Server Components where sessions cannot be modified because response headers cannot be set during the React Server Components (RSC) rendering phase.

**Compatible Contexts:**

- App Router (Server Components)

**Signature:**

```typescript
function getReadOnlySessionFromCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  options: SessionOptions
): Promise<ReadonlySession<T> & T>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| cookieStore | `NextJsCookieStore` | Yes | The result of `await cookies()` from `next/headers`. |
| options | `SessionOptions` | Yes | [Session configuration](#session-configuration) options. |

**Usage:**

```typescript
// src/wristband.ts
import { getReadOnlySessionFromCookies, NextJsCookieStore, SessionOptions } from '@wristband/nextjs-auth';

const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  secure: process.env.NODE_ENV === 'production',
};

export function getServerComponentSession(cookieStore: NextJsCookieStore) {
  return getReadOnlySessionFromCookies(cookieStore, sessionOptions);
}
```
```typescript
// src/app/dashboard/page.tsx
import { cookies } from 'next/headers';
import { getServerComponentSession } from '../../wristband';

export default async function DashboardPage() {
  const session = await getServerComponentSession(await cookies());
  
  if (!session.isAuthenticated) {
    return <div>Please log in.</div>;
  }
  
  return <div>Welcome, {session.userId}</div>;
}
```

> [!WARNING]
> Read-only sessions cannot call `save()`, `destroy()`, `saveToResponse()`, or `destroyToResponse()`. Attempting to do so will throw an error. Use `getMutableSessionFromCookies()` in Server Actions if you need to modify the session.

<br>

#### getMutableSessionFromCookies()

Retrieves a mutable session from Next.js `cookies()` API. Use this in App Router Server Actions where you need to modify session data. Unlike `getReadOnlySessionFromCookies()`, this returns a session that can be modified and saved using `saveSessionWithCookies()`.

**Compatible Contexts:**

- App Router (Server Actions)

**Signature:**

```typescript
function getMutableSessionFromCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  options: SessionOptions
): Promise<MutableSession<T> & T>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| cookieStore | `NextJsCookieStore` | Yes | The result of `await cookies()` from `next/headers`. |
| options | `SessionOptions` | Yes | [Session configuration](#session-configuration) options. |

**Usage:**

```typescript
// src/wristband.ts
import { getMutableSessionFromCookies, NextJsCookieStore, SessionOptions } from '@wristband/nextjs-auth';

const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  secure: process.env.NODE_ENV === 'production',
};

export async function getServerActionSession(cookieStore: NextJsCookieStore) {
  return await getMutableSessionFromCookies(cookieStore, sessionOptions);
}
```
```typescript
// src/app/actions/update-theme.ts
'use server';

import { cookies } from 'next/headers';
import { getServerActionSession, saveServerActionSession } from '../../wristband';

export async function updateTheme(theme: string) {
  const cookieStore = await cookies();
  const session = await getServerActionSession(cookieStore);
  
  if (!session.isAuthenticated) {
    return { error: 'Unauthorized' };
  }
  
  session.theme = theme;
  await saveServerActionSession(cookieStore, session);
  
  return { success: true };
}
```

<br>

#### saveSessionWithCookies()

Saves a mutable session by setting cookies using Next.js `cookies()` API. Use this in Server Actions after modifying session data retrieved via `getMutableSessionFromCookies()`.

**Compatible Contexts:**

- App Router (Server Actions)

**Signature:**

```typescript
function saveSessionWithCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  session: MutableSession<T> & T
): Promise<void>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| cookieStore | `NextJsCookieStore` | Yes | The result of `await cookies()` from `next/headers`. |
| session | `MutableSession<T> & T` | Yes | The mutable session to save. |

**Usage:**

```typescript
// src/wristband.ts
import { saveSessionWithCookies, MutableSession, NextJsCookieStore } from '@wristband/nextjs-auth';

export async function saveServerActionSession(
  cookieStore: NextJsCookieStore,
  session: MutableSession
) {
  await saveSessionWithCookies(cookieStore, session);
}
```
```typescript
// src/app/actions/update-preferences.ts
'use server';

import { cookies } from 'next/headers';
import { getServerActionSession, saveServerActionSession } from '../../wristband';

export async function updatePreferences(preferences: any) {
  const cookieStore = await cookies();
  const session = await getServerActionSession(cookieStore);
  
  session.preferences = preferences;
  await saveServerActionSession(cookieStore, session);
  
  return { success: true };
}
```

> [!NOTE]
> This function automatically handles Next.js caching behavior. Setting cookies invalidates the Next.js Router Cache and triggers a re-render of the current route.

<br>

#### destroySessionWithCookies()

Destroys a session and clears all session cookies using Next.js `cookies()` API. Use this in Server Actions when you need to manually destroy a session (e.g., custom logout flows).

**Compatible Contexts:**

- App Router (Server Actions)

**Signature:**

```typescript
function destroySessionWithCookies<T extends SessionData = SessionData>(
  cookieStore: NextJsCookieStore,
  session: MutableSession<T> & T
): void
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| cookieStore | `NextJsCookieStore` | Yes | The result of `await cookies()` from `next/headers`. |
| session | `MutableSession<T> & T` | Yes | The mutable session to destroy. |

**Usage:**

```typescript
// src/wristband.ts
import { destroySessionWithCookies, MutableSession, NextJsCookieStore } from '@wristband/nextjs-auth';

export function destroyServerActionSession(
  cookieStore: NextJsCookieStore,
  session: MutableSession
) {
  destroySessionWithCookies(cookieStore, session);
}
```
```typescript
// src/app/actions/custom-logout.ts
'use server';

import { cookies } from 'next/headers';
import { getServerActionSession, destroyServerActionSession } from '../../wristband';
import { redirect } from 'next/navigation';

export async function customLogout() {
  const cookieStore = await cookies();
  const session = await getServerActionSession(cookieStore);
  
  destroyServerActionSession(cookieStore, session);
  redirect('/login');
}
```

> [!NOTE]
> This function automatically handles Next.js caching behavior. Deleting cookies invalidates the Next.js Router Cache and triggers a re-render of the current route.

<br>

### Session Access Patterns

Sessions behave like plain JavaScript objects, supporting both dot notation (`session.userId`) and bracket notation (`session['userId']`) for getting, setting, checking, and deleting values.

#### Reading Values
```typescript
// Dot notation
const userId = session.userId;
const theme = session.theme;

// Bracket notation
const userId = session['userId'];
const theme = session['theme'];

// With optional chaining
const notifications = session.preferences?.notifications;
```

#### Setting Values
```typescript
// Dot notation
session.userId = '123';
session.theme = 'dark';

// Bracket notation
session['userId'] = '123';
session['theme'] = 'dark';

// Nested objects
session.preferences = {
  notifications: true,
  language: 'en'
};
```

#### Checking Existence
```typescript
// Using 'in' operator
if ('theme' in session) {
  console.log('Theme is set:', session.theme);
}

// Checking for undefined
if (session.userId !== undefined) {
  console.log('User ID:', session.userId);
}

// Optional chaining with nullish coalescing
const theme = session.theme ?? 'light';
```

#### Deleting Values
```typescript
// Delete operator
delete session.theme;
delete session['preferences'];

// Verify deletion
console.log('theme' in session); // false
```

#### Iterating Over Session Data
```typescript
// Get all keys
const keys = Object.keys(session);

// Iterate over entries
for (const [key, value] of Object.entries(session)) {
  console.log(`${key}: ${value}`);
}
```

#### Additional Session Methods

For more session operations, see the [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session#core-methods-all-runtimes) documentation which provides additional methods like:

- `session.get(key)` - Get a value with optional default
- `session.set(key, value)` - Set a value
- `session.delete(key)` - Delete a value
- `session.has(key)` - Check if key exists
- `session.clear()` - Clear all session data
- `session.toJSON()` - Get session as plain object

#### Limitations

**JSON Serialization:** All values stored in the session must be JSON-serializable. Attempting to store non-serializable values (functions, class instances, objects with circular references) will result in errors when the session is encrypted and saved.

**Size Limit:** Sessions are limited to 4KB total, including encryption overhead and cookie attributes. This limit is enforced by browsers per [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265). If your session exceeds this limit, an error will be thrown when attempting to save.

**Read-Only in Server Components:** Server Components cannot modify sessions because they render during the RSC phase where response headers cannot be set. Use `getReadOnlySessionFromCookies()` for reading session data and `getMutableSessionFromCookies()` in Server Actions for modifications.

<br>

### Session API

The session object provides several methods for managing sessions and authentication data. These include lifecycle methods for persisting and destroying sessions, as well as Wristband-specific methods for creating sessions from callback data and generating responses for frontend SDKs.

<br>

#### session.fromCallback()

Create a session from Wristband callback data after successful authentication. This is a convenience method that automatically extracts a core subset of user and tenant info from the authentication callback data.

**Compatible Context:**

- App Router
- Pages Router

**Signature:**

```typescript
session.fromCallback(callbackData: CallbackData, customFields?: Record<string, any>): void
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| callbackData | `CallbackData` | Yes | The callback data from `wristbandAuth.callback()`. An error is thrown if `callbackData` is null or `callbackData.userinfo` is missing. |
| customFields | `Record<string, any>` | No | Additional custom fields to store in the session. Must be JSON-serializable. |

**Usage:**

```typescript
// App Router: Callback endpoint
import { NextRequest } from 'next/server';
import { getRequestSession, wristbandAuth } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const callbackResult = await wristbandAuth.appRouter.callback(req);
  const { callbackData, redirectUrl, type } = callbackResult;

  if (type === 'redirect_required') {
    return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
  }
  
  const session = await getRequestSession(req);
  
  // Basic usage
  session.fromCallback(callbackData);
  
  // With custom fields
  session.fromCallback(callbackData, {
    loginTime: Date.now(),
    loginIp: req.ip
  });

  const appUrl = callbackData.returnUrl || '/';
  const callbackResponse = await wristbandAuth.appRouter.createCallbackResponse(req, appUrl);
  
  return await session.saveToResponse(callbackResponse);
}
```

**Fields Automatically Set:**

The following fields are automatically populated from the callback data:

- `isAuthenticated` (always set to `true`)
- `accessToken`
- `expiresAt`
- `userId` (from `callbackData.userinfo.userId`)
- `tenantId` (from `callbackData.userinfo.tenantId`)
- `tenantName`
- `identityProviderName` (from `callbackData.userinfo.identityProviderName`)
- `refreshToken` (only if `offline_access` scope was requested)
- `tenantCustomDomain` (only if a tenant custom domain was used)

<br>

#### session.save()

Saves the session by setting the session cookie (and CSRF cookie if enabled). Refreshes cookie expiration (rolling sessions) and persists any session modifications. If CSRF protection is enabled and no CSRF token exists yet, this also generates and stores a CSRF token in both the session (`csrfToken` field) and a separate CSRF cookie. Use this method in Pages Router contexts where the response object is managed by Next.js.

**Compatible Context:**

- Pages Router

**Signature:**

```typescript
session.save(): Promise<void>
```

**Usage:**
```typescript
// Pages Router: API route
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../wristband';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  
  session.theme = req.body.theme;
  session.lastActivity = Date.now();
  
  await session.save();
  
  res.json({ success: true });
}
```

<br>

#### session.saveToResponse()

Saves the session by adding session and CSRF cookie headers to a Next.js response object. Refreshes cookie expiration (rolling sessions) and persists any session modifications. Generates a CSRF token if CSRF protection is enabled and no token exists yet. Use this method in App Router contexts (route handlers, middleware/proxy) where you need to manually manage response headers. Returns the same response object with cookie headers added.

**Compatible Context:**

- App Router
- Middleware/Proxy

**Signature:**

```typescript
session.saveToResponse(response: NextResponse): Promise<NextResponse>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| response | `NextResponse` | Yes | The Next.js response object to add session cookies to. |

**Returns:**

The same `NextResponse` object with session cookie headers added.

**Usage:**

```typescript
// App Router: Route handler
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../wristband';

export async function POST(req: NextRequest) {
  const session = await getRequestSession(req);
  const { theme } = await req.json();
  
  session.theme = theme;
  
  return await session.saveToResponse(
    NextResponse.json({ success: true })
  );
}
```

<br>

#### session.destroy()

Delete the session data and clear all cookies (both session and CSRF). Use this method in Pages Router contexts where the response object is managed by Next.js.

**Compatible Context:**

- Pages Router

**Signature:**

```typescript
session.destroy(): void
```

**Usage:**

```typescript
// Pages Router: Logout endpoint
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession, wristbandAuth } from '../../../wristband';

export default async function logoutEndpoint(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  const { refreshToken, tenantName } = session;
  
  // Destroy session
  session.destroy();
  
  const logoutUrl = await wristbandAuth.pagesRouter.logout(req, res, {
    refreshToken,
    tenantName,
  });
  
  res.redirect(logoutUrl);
}
```

<br>

#### session.destroyToResponse()

Destroys the session data and clears all cookies (both session and CSRF) by setting the appropriate headers on a Next.js response object. Use this method in App Router contexts (route handlers, middleware/proxy) where you need to manually manage response headers.

**Compatible Context:**

- App Router
- Middleware/Proxy

**Signature:**

```typescript
session.destroyToResponse(response: NextResponse): Promise<NextResponse>
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| response | `NextResponse` | Yes | The Next.js response object to add session deletion headers to. |

**Returns:**

The same `NextResponse` object with cookie deletion headers added.

**Usage:**

```typescript
// App Router: Logout endpoint
import type { NextRequest } from 'next/server';
import { getRequestSession, wristbandAuth } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  const { refreshToken, tenantName } = session;
  
  const logoutResponse = await wristbandAuth.appRouter.logout(req, {
    refreshToken,
    tenantName,
  });
  
  return await session.destroyToResponse(logoutResponse);
}
```

<br>

#### session.getSessionResponse()

Create a `SessionResponse` for Wristband frontend SDKs. This method is typically used in your Session Endpoint. An error is thrown if `tenantId` or `userId` are missing from the session.

**Compatible Context:**

- App Router
- Pages Router

**Signature:**

```typescript
session.getSessionResponse(metadata?: Record<string, any>): SessionResponse
```

**Parameters:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| metadata | `Record<string, any>` | No | Custom metadata to include in the response. Must be JSON-serializable. |

**Returns:**

A `SessionResponse` object.

**SessionResponse Type:**

| Field | Type | Description |
| ----- | ---- | ----------- |
| userId | string | The ID of the authenticated user. |
| tenantId | string | The ID of the tenant that the user belongs to. |
| metadata | `Record<string, any>` | Custom metadata provided. Defaults to empty object if none provided. |

**Usage:**

```typescript
// App Router: Session Endpoint
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  
  const sessionResponse = session.getSessionResponse({
    theme: session.theme,
    name: session.fullName
  });
  
  return NextResponse.json(sessionResponse, {
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
}
```
```typescript
// Pages Router: Session Endpoint
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../../wristband';

export default async function sessionEndpoint(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  
  const sessionResponse = session.getSessionResponse({
    theme: session.theme
  });
  
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.status(200).json(sessionResponse);
}
```

> [!NOTE]
> Ensure the Session Endpoint is protected with authentication middleware using the `SESSION` strategy!

<br>

#### session.getTokenResponse()

Create a TokenResponse for Wristband frontend SDKs. This method is typically used in your Token Endpoint. An error is thrown if `accessToken` or `expiresAt` are missing from the session.

**Compatible Context:**

- App Router
- Pages Router

**Signature:**
```typescript
session.getTokenResponse(): TokenResponse
```

**Returns:**

A `TokenResponse` object.

**TokenResponse Type:**

| Field | Type | Description |
| ----- | ---- | ----------- |
| accessToken | string | The access token for making authenticated API calls. |
| expiresAt | number | Token expiration timestamp (milliseconds since Unix epoch). Accounts for `tokenExpirationBuffer` from `WristbandAuth` SDK config. |

**Usage:**

```typescript
// App Router: Token endpoint
import { NextRequest, NextResponse } from 'next/server';
import { getRequestSession } from '../../../../wristband';

export async function GET(req: NextRequest) {
  const session = await getRequestSession(req);
  const tokenResponse = session.getTokenResponse();
  
  return NextResponse.json(tokenResponse, {
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
}
```
```typescript
// Pages Router: Token endpoint
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '../../../wristband';

export default async function tokenEndpoint(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  const tokenResponse = session.getTokenResponse();
  
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.status(200).json(tokenResponse);
}
```

> [!NOTE]
> Ensure the Token Endpoint is protected with authentication middleware using the `SESSION` strategy!

<br>

### CSRF Protection

CSRF (Cross-Site Request Forgery) protection helps prevent unauthorized actions by validating that requests originate from your application's frontend. When enabled, the SDK implements the [Synchronizer Token Pattern](https://docs.wristband.dev/docs/csrf-protection-for-backend-servers) using a dual-cookie approach.

When CSRF protection is enabled in your `SessionOptions` and a session is saved, the SDK:

1. **Generates a CSRF token** - A cryptographically secure random token is created
2. **Stores the token in two places:**
   - **Session cookie** (encrypted, HttpOnly) - Contains the CSRF token as part of the encrypted session data
   - **CSRF cookie** (unencrypted, readable by JavaScript) - Contains the same CSRF token in plaintext

This dual-cookie approach ensures:
- The session cookie proves the user is authenticated (server-side validation)
- The CSRF cookie must be read by your frontend and sent in request headers (client-side participation)
- An attacker cannot forge requests because they cannot read cookies from your domain due to the browser's Same-Origin Policy

#### Enabling CSRF Protection

To enable CSRF protection, configure it in your session options and use the `SESSION` strategy in your [Authentication Middleware](#authentication-middleware):

```typescript
// src/wristband.ts
import { SessionOptions } from '@wristband/nextjs-auth';

// 1. Enable CSRF in session configuration
const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  enableCsrfProtection: true,  // Enable CSRF token generation
};

// 2. Enable CSRF validation in middleware
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: {
    sessionOptions,  // Enable CSRF token validation
    csrfTokenHeaderName: 'x-csrf-token',  // Header name to read token from
  },
  protectedApis: ['/api/v1(.*)'],
  protectedPages: ['/', '/dashboard'],
});
```

#### Frontend Implementation

Your frontend must read the CSRF token from the CSRF cookie and include it in request headers for all state-changing operations (POST, PUT, DELETE, PATCH):

```typescript
// Read CSRF token from cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('CSRF-TOKEN='))
  ?.split('=')[1];

// Include in requests
fetch('/api/protected-endpoint', {
  method: 'POST',
  headers: {
    'X-CSRF-TOKEN': csrfToken,
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({ data: 'example' })
});
```

When you use the `createMiddlewareAuth()` middleware with `enableCsrfProtection: true`, CSRF token validation happens automatically on every request to a protected API route. When a request hits a protected route:

1. Middleware extracts the CSRF token from the request header (default: `x-csrf-token`)
2. Compares it with the CSRF token stored in the session
3. If they match, the request proceeds
4. If they don't match or the header is missing, an HTTP 403 response is returned

> [!NOTE]
> CSRF validation is primarily for state-changing operations (POST, PUT, DELETE). GET requests can rely on `createMiddlewareAuth()` for authentication without concern, though CSRF token validation still occurs if the token is present in the request.

#### Cross-Subdomain CSRF Cookies

If your frontend and backend are on different subdomains (e.g., `app.example.com` and `api.example.com`), you need to configure the CSRF cookie domain to allow cross-subdomain access:

```typescript
const sessionOptions: SessionOptions = {
  secrets: 'your-secret-key-min-32-chars',
  enableCsrfProtection: true,
  csrfCookieDomain: '.example.com',  // Leading dot allows all subdomains
};
```

> [!NOTE]
> The session cookie should remain scoped to your backend domain for security. Only the CSRF cookie needs cross-subdomain access since it's read by JavaScript in the browser.

<br>

## Authentication Middleware

The SDK provides two authentication functions for protecting routes and validating sessions in different Next.js contexts:

- **`createMiddlewareAuth()`** - For protecting routes in Next.js middleware/proxy (supports multiple auth strategies)
- **`createServerActionAuth()`** - For protecting Server Actions (session-only authentication)

Both functions are created using your `WristbandAuth` instance and automatically handle authentication checks, token refresh, and more.

<br>

### createMiddlewareAuth()

The `createMiddlewareAuth()` factory function creates middleware for protecting routes in Next.js middleware (or proxy in Next.js 16+). This middleware supports multiple authentication strategies and automatically handles session validation, token refresh, and optional CSRF token protection. You can use this same middleware function for both App Router and Pages Router.

**Usage:**

First, you configure and create an instance of the middleware in your Wristband file:

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/nextjs-auth';

export const wristbandAuth = createWristbandAuth({
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  wristbandApplicationVanityDomain: 'app-mystartup.us.wristband.dev',
});

// Advanced Example (All Options)
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  // Try JWT validation first (access token), fallback to SESSION validation (session cookie)
  authStrategies: ['JWT', 'SESSION'],
  
  // Session configuration (required when using SESSION strategy)
  sessionConfig: {
    // Session options as expected by the @wristband/typescript-session SDK
    sessionOptions: {
      cookieName: 'session',                 // Session cookie name
      secrets: process.env.SESSION_SECRET!,  // Min 32 chars, keep secret
      maxAge: 3600,                          // 1 hour in seconds
      domain: '.example.com',                // Cookie domain (undefined = current domain only)
      path: '/',                             // Cookie path
      secure: true,                          // HTTPS only (must be true in prod)
      sameSite: 'lax',                       // Cookie cross-site policy (strict, lax, or none)
      enableCsrfProtection: true,            // Generate and validate CSRF tokens for API requests
      csrfCookieName: 'CSRF-TOKEN',          // CSRF cookie name (if CSRF enabled)
      csrfCookieDomain: '.example.com',      // CSRF cookie domain (if CSRF enabled; defaults to domain)
    },
    sessionEndpoint: '/api/v1/session',      // Custom Session Endpoint location
    tokenEndpoint: '/api/v1/token',          // Custom Token Endpoint location
    csrfTokenHeaderName: 'x-custom-csrf',    // Custom CSRF header name (if CSRF enabled)
  },
  
  // JWT configuration (optional; values used only with JWT strategy)
  jwtConfig: {
    jwksCacheMaxSize: 25,   // Cache up to 25 JWKs before eviction
    jwksCacheTtl: 3600000,  // 1 hour cache TTL
  },
  
  // Protect all /api/v1/* and /api/v2/* routes
  protectedApis: ['/api/v1(.*)', '/api/v2(.*)'],
  
  // Protect home, dashboard, and all settings pages
  protectedPages: ['/', '/dashboard', '/settings(.*)'],
  
  // Custom redirect logic for unauthenticated page requests
  onPageUnauthenticated: (req: NextRequest) => {
    const loginUrl = new URL('/login', req.url);
    loginUrl.searchParams.set('returnUrl', req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  },
});
```

Then you can use it accordingly in your middleware/proxy file:

```typescript
// src/proxy.ts (or src/middleware.ts in Next.js 15 and below)
import { NextRequest } from 'next/server';

import { requireMiddlewareAuth } from '@/wristband';

export async function proxy(request: NextRequest) {
  return await requireMiddlewareAuth(request);
}

export const config = {
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

**Common Middleware Behavior:**

When a request matches a protected route, the middleware tries each auth strategy in sequential order until one succeeds. If all strategies fail, it returns the appropriate response:

- **Protected API routes:** Returns 401 Unauthorized
- **Protected pages:** Redirects to login (or calls custom `onPageUnauthenticated` handler)

**Common MiddlewareAuth Configuration Options:**

| MiddlewareAuth Config | Type | Required | Default | Description |
| --------------------- | ---- | -------- | ------- | ----------- |
| authStrategies | `AuthStrategy[]` | Yes | N/A | Array of authentication strategies to try in sequential order. At least one strategy is required. The middleware will attempt each strategy until one succeeds.<br><br> Available strategies: <br>- `SESSION` (cookie-based sessions)<br>- `JWT` (bearer token authentication) |
| sessionConfig | object | Required if using `SESSION` strategy | N/A | Configuration object for session-based authentication. Must be provided when `SESSION` is included in authStrategies. Contains session options, CSRF settings, and endpoint paths. |
| jwtConfig | object | No | `undefined` | Optional configuration object for JWT bearer token authentication. Contains caching settings for JSON Web Key Sets (JWKS) used to verify JWT signatures. This is only needed if you are using the `JWT` strategy and don't want to rely on default config values. |
| protectedApis | string[] | No | `[]` (no API routes protected, **except** the Session and Token Endpoints which are automatically protected when using the `SESSION` strategy) | Array of regex patterns defining which API routes require authentication. Routes matching these patterns return HTTP 401 if authentication fails. Patterns support exact paths (`'/api/users'`), wildcards (`'/api/v1(.*)'`), and named parameters (`'/api/users/:id'`). The default is an empty list meaning <br><br> Example: [`'/api/v1(.*)'`, `'/api/v2/orders/:id'`] protects all v1 APIs and specific v2 order routes.<br><br> Important: Session and Token Endpoints are automatically protected when using the `SESSION` strategy and don't need to be listed here. |
| protectedPages | string[] | No | `[]` (no pages protected) | Array of regex patterns defining which page routes require authentication. Pages matching these patterns redirect unauthenticated users to login (or call your custom handler). Patterns support exact paths (`'/dashboard'`), wildcards (`'/settings(.*)'`), and named parameters (`'/profile/:userId'`).<br><br> Example: [`'/'`, `'/dashboard'`, `'/settings(.*)'`] protects the home page, dashboard, and all settings subpages.<br><br> Note: Server Actions are automatically excluded from middleware protection - they must use `createServerActionAuth()` instead. |
| onPageUnauthenticated | `(request: NextRequest, reason: AuthFailureReason) => NextResponse \| Promise<NextResponse>` | No | A function that redirects to your Login Endpoint. | Custom handler for unauthenticated requests to protected pages. Receives the `NextRequest` and an `AuthFailureReason` indicating why authentication failed (`not_authenticated`, `csrf_failed`, `token_refresh_failed`, or `unexpected_error`). Must return a `NextResponse` or a Promise that resolves to a `NextResponse`.<br><br> Example use cases: Display error messages for `unexpected_error`, different redirects based on failure type, etc. See examples below for custom implementations. |

The middleware supports two authentication strategies that can be used independently or combined:

- `SESSION`
- `JWT`

<br>

#### SESSION Strategy

The `SESSION` strategy validates authentication using encrypted session cookies. This is the most common strategy for traditional web applications. The middleware performs these steps for protected routes:

1. **Validates session cookie** - Checks for valid encrypted session (`session.isAuthenticated === true`)
2. **Auto-protects auth endpoints** - Session and Token Endpoints are always automatically protected
3. **Refreshes expired tokens** - Automatically refreshes access tokens if both `refreshToken` and `expiresAt` exist in session and the access token is expired
4. **Validates CSRF tokens (optional)** - Checks CSRF token in request header if `enableCsrfProtection` is `true` (API routes only, not pages)
5. **Extends session expiration** - Updates session cookie `maxAge` on each request (rolling sessions)
6. **Saves session changes** - Persists any token refreshes or expiration updates to session cookie

**Session Configurations:**

| SessionConfig | Type | Required | Default | Description |
| ------------- | ---- | -------- | ------- | ----------- |
| sessionOptions | `SessionOptions` | Yes | N/A | Core session configuration object. Defines encryption secrets, cookie settings, max age, and more. This is the same configuration used in your session helper functions. See [Session Configuration](#session-configuration) for all available options. Minimum required fields: `secrets` (min 32 chars) |
| sessionEndpoint | string | No | `/api/auth/session` | Path to your Session Endpoint. Automatically protected when using `SESSION` strategy. |
| tokenEndpoint | string | No | `/api/auth/token` | Path to your Token Endpoint. Automatically protected when using `SESSION` strategy |
| csrfTokenHeaderName | string | No | `X-CSRF-TOKEN` | HTTP header name containing the CSRF token. Only used when `sessionOptions.enableCsrfProtection` is `true`. If enabled, your frontend must send the CSRF token in this header to your protected API Routes. |

**Example: Basic Configuration**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: {
    sessionOptions: {
      secrets: process.env.SESSION_SECRET!,
      maxAge: 3600,
      secure: true,
      sameSite: 'strict'
    },
  },
  protectedApis: ['/api/v1(.*)'],
  protectedPages: ['/dashboard'],
});
```

**Example: CSRF Token Protection**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: {
    sessionOptions: {
      secrets: process.env.SESSION_SECRET!,
      enableCsrfProtection: true,                 // Enable CSRF token generation/validation
      csrfCookieName: 'CUSTOM-COOKIE-NAME',       // Optional
      csrfCookieDomain: 'mydomain.com',           // Optional
    },
    csrfTokenHeaderName: 'X-CUSTOM-HEADER-NAME',  // Optional
  },
  protectedApis: ['/api/v1(.*)'],   // CSRF validation applies here
  protectedPages: ['/dashboard'],   // No CSRF for page navigations
});
```

**Example: Custom Auth Endpoints**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: {
    sessionOptions: { secrets: process.env.SESSION_SECRET! },
    sessionEndpoint: '/api/v1/session',  // ← Custom session endpoint path
    tokenEndpoint: '/api/v1/token',      // ← Custom token endpoint path
  },
  protectedApis: ['/api/v1(.*)'],
  protectedPages: ['/', '/dashboard'],
});
```

#### JWT Strategy

The `JWT` strategy validates authentication using JWT bearer tokens from the `Authorization` request header. This strategy is powered by [@wristband/typescript-jwt](https://github.com/wristband-dev/typescript-jwt) and is useful for API-first applications or when your frontend stores access tokens and includes them in API requests. The middleware performs these steps for protected routes:

1. **Extracts JWT token** - Gets token from `Authorization: Bearer <token>` header
2. **Verifies signature** - Uses cached JWKS from Wristband to verify token signature
3. **Validates claims** - Checks token expiration, issuer, etc.
4. **Caches JWKs** - Stores JSON Web Keys in memory according to `jwksCacheMaxSize` and `jwksCacheTtl` settings
5. **No session management** - Stateless authentication with no cookies or token refresh

> [!NOTE]
> **JWT and Page Routes:** The `JWT` strategy is designed with API routes in mind. While it technically works for protected pages, browsers don't naturally send JWT tokens in Authorization headers during page navigation. Use `SESSION` strategy for traditional web page protection.

**JWT Configurations:**

| JwtConfig | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| jwksCacheMaxSize | number | No | 20 | Maximum number of JSON Web Keys (JWKs) to cache in memory. JWKs are public keys used to verify JWT signatures. Caching improves performance by avoiding repeated JWKS endpoint requests. Uses LRU (Least Recently Used) eviction. The default is sufficient for most cases. |
| jwksCacheTtl | number | No | `undefined` (infinite, until LRU eviction) | How long JWKs stay cached, in milliseconds, before refresh. The default is sufficient for most cases.<br><br> Example: 300000 (5 minutes) to force periodic key refresh. |

**Example: Basic Configuration**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  // `jwtConfig` is optional
  authStrategies: ['JWT'],
  protectedApis: ['/api/v1(.*)'],
});
```

**Example: Aggressive Caching (high-traffic)**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['JWT'],
  jwtConfig: {
    jwksCacheMaxSize: 50,    // Cache more keys than the default
    jwksCacheTtl: 600000,    // 10 minutes TTL
  },
  protectedApis: ['/api/v1(.*)', '/api/v2(.*)'],
});
```

#### Strategy Order

When multiple strategies are configured, they are tried in the order specified. The first strategy that successfully authenticates the request is used:

```typescript
// Try JWT first, fall back to SESSION
authStrategies: ['JWT', 'SESSION']

// Try SESSION first, fall back to JWT  
authStrategies: ['SESSION', 'JWT']
```

If all strategies fail, the request is considered unauthenticated.

#### Custom Page Authentication Handlers

When a protected page request fails authentication, you can customize the response using the `onPageUnauthenticated` handler. The handler receives both the request and a reason for the authentication failure. By default, all failure reasons redirect to your Login Endpoint.

**Failure Reasons:**

| Reason | Description | When It Occurs |
| ------ | ----------- | -------------- |
| `not_authenticated` | No valid session or JWT token found | User has no session cookie or authentication has expired |
| `csrf_failed` | CSRF token validation failed | CSRF token in request doesn't match session (`SESSION` strategy only; API routes only) |
| `token_refresh_failed` | Token refresh attempt failed | Refresh token is invalid or Wristband token refresh request failed |
| `unexpected_error` | Unexpected error during authentication | Session service crashed, JWT validator failed, or other infrastructure issues |

**Example: Custom URL Redirect**

```typescript
export const requireMiddlewareAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: { sessionOptions },
  protectedPages: ['/dashboard', '/settings'],
  
  // Custom handler
  onPageUnauthenticated: (request, reason) => {
    const customUrl = new URL('/custom-unauthenticated-url', request.url);
    loginUrl.searchParams.set('error', reason);
    return NextResponse.redirect(customUrl);
  },
});
```

**Example: Different Login Pages by Failure Type**

```typescript
onPageUnauthenticated: (request, reason) => {
  // Show error page for infrastructure issues
  if (reason === 'unexpected_error') {
    return NextResponse.redirect(new URL('/error?code=500', request.url));
  }

  // Show CSRF error page
  if (reason === 'csrf_failed') {
    return NextResponse.redirect(new URL('/error/invalid-request', request.url));
  }
  
  // Show session expired message
  if (reason === 'token_refresh_failed') {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('expired', 'true');
    loginUrl.searchParams.set('return_url', request.url);
    return NextResponse.redirect(loginUrl);
  }
  
  // Default redirect to login
  const loginUrl = new URL('/login', request.url);
  loginUrl.searchParams.set('return_url', request.url);
  return NextResponse.redirect(loginUrl);
}
```

> [!NOTE]
> The `onPageUnauthenticated` handler is only called for protected **page routes**, not API routes. API routes always return appropriate HTTP status codes (401, 403, or 500) without calling this handler.

<br>

#### Middleware Chaining

When using Next.js middleware, you may need to combine Wristband authentication with other middleware logic (logging, rate limiting, custom headers, etc.). The SDK's authentication middleware is designed to work seamlessly in middleware chains by accepting an optional `previousResponse?: NextResponse` parameter and automatically merging response headers.

**How Header Copying Works**

The authentication middleware accepts a second parameter `previousResponse?: NextResponse`. When provided:

- All headers from `previousResponse` are automatically copied to the authentication middleware's response
- This includes custom headers, cookies, and any other response modifications you've made
- The middleware handles merging intelligently - authentication cookies/headers take precedence
- **If the current route doesn't match any protected patterns, the `previousResponse` is returned as-is** - no authentication checks are performed and all headers are preserved

This design allows you to chain middleware functions without manually managing header propagation.

> [!NOTE]
> **Third-Party Middleware**: When chaining with third-party middleware libraries, be aware that they may not automatically propagate headers/cookies from previous responses. You may need to manually copy headers between middleware calls, or check the library's documentation for chaining support. The Wristband middleware will always preserve headers from any `previousResponse` you pass to it.

**Example: Basic Chaining**

```typescript
// src/middleware.ts (or proxy.ts for Next.js 16+)
import { NextRequest, NextResponse } from 'next/server';
import { requireMiddlewareAuth } from './wristband';

export async function middleware(req: NextRequest) {
  // Start with a custom response
  const customResponse = NextResponse.next();
  customResponse.headers.set('X-Custom-Header', 'my-value');
  customResponse.headers.set('X-Request-Id', crypto.randomUUID());
  
  // Pass it to auth middleware - headers are automatically preserved
  return await requireMiddlewareAuth(req, customResponse);
}

export const config = {
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

**Example: Manual Header Copying with Third-Party Middleware**

If a third-party middleware doesn't preserve headers automatically, you'll need to copy them manually:

```typescript
// src/middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { requireMiddlewareAuth } from './wristband';
import { someThirdPartyMiddleware } from 'some-library';

export async function middleware(req: NextRequest) {
  // Add custom headers
  let response = NextResponse.next();
  response.headers.set('X-Request-Id', crypto.randomUUID());
  
  // Call third-party middleware (might not preserve headers)
  const thirdPartyResponse = await someThirdPartyMiddleware(req);
  
  // Manually copy headers from our response to third-party response
  response.headers.forEach((value, key) => {
    thirdPartyResponse.headers.set(key, value);
  });
  
  // Pass to Wristband auth (automatically preserves all headers)
  return await requireMiddlewareAuth(req, thirdPartyResponse);
}

export const config = {
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

**Multiple Auth Middleware Instances**

You can create multiple `requireMiddlewareAuth` instances with different configurations and chain them together. This is useful when you want different authentication strategies or settings for different route patterns.

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/nextjs-auth';

export const wristbandAuth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

// API-focused auth: JWT first, session fallback, with CSRF
export const requireApiAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['JWT', 'SESSION'],
  sessionConfig: { 
    sessionOptions,
    enableCsrfProtection: true,
  },
  protectedApis: ['/api/v1(.*)'],
  protectedPages: [],  // Don't protect any pages
});

// Page-focused auth: Session only, no CSRF
export const requirePageAuth = wristbandAuth.createMiddlewareAuth({
  authStrategies: ['SESSION'],
  sessionConfig: { sessionOptions },
  protectedApis: [],  // Don't protect any APIs
  protectedPages: ['/', '/dashboard(.*)'],
});
```

You can chain them together with short-circuit logic. If the first auth check returns a redirect or error response (status >= 300), stop the chain and return immediately:

```typescript
// src/middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { requireApiAuth, requirePageAuth } from './wristband';

export async function middleware(req: NextRequest) {
  let response = NextResponse.next();
  
  // Add custom headers
  response.headers.set('X-Request-Id', crypto.randomUUID());
  
  // Try API auth first
  response = await requireApiAuth(req, response);
  
  // Short-circuit: if API auth returned redirect/error, don't continue
  if (response.status >= 300) {
    return response;
  }
  
  // Continue to page auth
  response = await requirePageAuth(req, response);
  
  return response;
}

export const config = {
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

There are several scenarios where multiple auth middleware instances are beneficial:

- **Different strategies per route type**: Use JWT for APIs, session for pages
- **Different CSRF settings**: Enable CSRF for APIs but not for pages
- **Different protected patterns**: Separate concerns between API and page protection
- **Different error handlers**: Custom `onPageUnauthenticated` per route group
- **Performance optimization**: Only run necessary auth checks per route type

**Advanced: Custom Middleware Composer**

Create a reusable middleware composition utility with short-circuit support:

```typescript
// src/middleware/composer.ts
import { NextRequest, NextResponse } from 'next/server';

type MiddlewareFunction = (
  req: NextRequest,
  res?: NextResponse
) => NextResponse | Promise<NextResponse>;

export function composeMiddleware(...middlewares: MiddlewareFunction[]) {
  return async (req: NextRequest): Promise<NextResponse> => {
    let response: NextResponse | undefined;
    
    for (const middleware of middlewares) {
      response = await middleware(req, response);
      
      // Short-circuit: if middleware returns redirect/error, stop chain
      if (response.status >= 300) {
        return response;
      }
    }
    
    return response!;
  };
}
```

Use it to compose your middleware:

```typescript
// src/middleware.ts
import { requireApiAuth, requirePageAuth } from './wristband';
import { composeMiddleware } from './middleware/composer';

const addSecurityHeaders = (req: NextRequest, res?: NextResponse) => {
  const response = res || NextResponse.next();
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  return response;
};

const addRequestTracking = (req: NextRequest, res?: NextResponse) => {
  const response = res || NextResponse.next();
  response.headers.set('X-Request-Id', crypto.randomUUID());
  return response;
};

const logging = async (req: NextRequest, res?: NextResponse) => {
  console.log(`${req.method} ${req.url}`);
  return res || NextResponse.next();
};

export const middleware = composeMiddleware(
  logging,
  addSecurityHeaders,
  addRequestTracking,
  requireApiAuth,    // Short-circuits on auth failure
  requirePageAuth,   // Only runs if API auth passed or didn't apply
);

export const config = {
  matcher: ['/((?!_next|fonts|examples|[\\w-]+\\.\\w+).*)'],
};
```

> [!IMPORTANT]
> **Automatic Header Preservation**: The auth middleware automatically copies all headers from `previousResponse` to its return value. You don't need to manually merge headers - just pass your response as the second parameter and the middleware handles the rest.

> [!WARNING]
> **Short-Circuit Pattern**: When chaining multiple auth middleware instances, always check `response.status >= 300` before continuing to the next middleware. This prevents unnecessary auth checks and ensures error/redirect responses are returned immediately.

> [!NOTE]
> **Performance**: Header copying is lightweight and has negligible performance impact. The middleware only copies headers when both a `previousResponse` is provided AND authentication succeeds or needs to return an error.

<br>

### createServerActionAuth()

The `createServerActionAuth()` factory function creates an authentication helper for Server Actions that validates the session and automatically refreshes expired tokens. Server Actions bypass Next.js middleware, so they require explicit authentication checks.

```typescript
// src/wristband.ts
export const requireServerActionAuth = wristbandAuth.appRouter.createServerActionAuth({
  sessionOptions,
});
```

**Configuration Options:**

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| sessionOptions | `SessionOptions` | Yes | Session configuration. Same options used in [Session Configuration](#session-configuration). |

**Usage:**
```typescript
// src/app/actions/my-action.ts
'use server';

import { cookies } from 'next/headers';
import { requireServerActionAuth } from '../../wristband';

export async function updateProfile(formData: FormData) {
  const cookieStore = await cookies();
  const { authenticated, reason, session } = await requireServerActionAuth(cookieStore);
  
  if (!authenticated) {
    return { error: 'Unauthorized', reason };
  }

  // Access authenticated session (TypeScript knows session exists here)
  const { userId } = session;
  
  // Your business logic here...
  
  return { success: true };
}
```

**Return Type:**

The helper returns a `ServerActionAuthResult` object:

| Field | Type | Description |
| ----- | ---- | ----------- |
| authenticated | boolean | Whether authentication succeeded. |
| reason | `AuthFailureReason` or `undefined` | Reason for failure if `authenticated` is `false`. Only present when authentication fails.<br><br>Possible values:<br>- `not_authenticated`: No valid session found<br>- `token_refresh_failed`: Token refresh attempt failed<br>- `unexpected_error`: Infrastructure error (session service down, etc.) |
| session | `MutableSession` or `undefined` | The authenticated session. Only present when `authenticated` is `true`. |

**What It Does:**

1. Retrieves session from the Next.js Cookies API
2. Validates authentication (`session.isAuthenticated === true`)
3. Checks token expiration (if `refreshToken` and `expiresAt` exist in the session data)
4. Automatically refreshes expired tokens and updates the session (rolling session expiration)
5. Returns authentication result

**Differences from Middleware Auth:**

Unlike `createMiddlewareAuth()`, Server Action authentication:

- ❌ Does not validate CSRF tokens (Next.js Server Actions have built-in CSRF protection via Origin/Host header comparison)
- ❌ Does not support multiple authentication strategies (session-only, since Server Actions use Next.js's internal invocation mechanism where clients don't control request headers; authentication relies on cookies/sessions rather than Authorization headers)

<br>

## Related Wristband SDKs

This SDK builds upon and integrates with other Wristband SDKs to provide a complete authentication solution:

**[@wristband/typescript-session](https://github.com/wristband-dev/typescript-session)**

This SDK leverages the Wristband TypeScript Session SDK for encrypted cookie-based session management. It provides the underlying session infrastructure including encryption, cookie handling, and session lifecycle management. Refer to that GitHub repository for more information on session configuration options and advanced usage.

**[@wristband/typescript-jwt](https://github.com/wristband-dev/typescript-jwt)**

This SDK leverages the Wristband TypeScript JWT SDK for JWT validation when using the `JWT` authentication strategy in middleware. It handles JWT signature verification, token parsing, and JWKS key management. The JWT SDK functions are also re-exported from this package, allowing you to use them directly for custom JWT validation scenarios beyond the built-in middleware strategy. Refer to that GitHub repository for more information on JWT validation configuration and options.

**[@wristband/react-client-auth](https://github.com/wristband-dev/react-auth)**

For handling client-side authentication and session management in your React frontend, check out the Wristband React Client Auth SDK. It integrates seamlessly with this backend SDK by consuming the Session and Token endpoints you create. Refer to that GitHub repository for more information on frontend authentication patterns.

<br>

## Wristband Multi-Tenant Next.js Demo Apps

You can check out the following Next.js demo apps to see the SDK in action. Refer to that GitHub repositories for more information.

- [Next.js Demo App - App Router](https://github.com/wristband-dev/nextjs-app-router-demo-app)
- [Next.js Demo App - Pages Router](https://github.com/wristband-dev/nextjs-page-router-demo-app) 

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
