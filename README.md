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

# Wristband Multi-Tenant Authentication SDK for NextJS


[![npm package](https://img.shields.io/badge/npm%20i-nextjs--auth-brightgreen)](https://www.npmjs.com/package/@wristband/nextjs-auth)
[![version number](https://img.shields.io/github/v/release/wristband-dev/nextjs-auth?color=green&label=version)](https://github.com/wristband-dev/nextjs-auth/releases)
[![License](https://img.shields.io/github/license/wristband-dev/nextjs-auth)](https://github.com/wristband-dev/nextjs-auth/blob/main/LICENSE.md)
<!-- [![Actions Status](https://github.com/wristband-dev/nextjs-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/nextjs-auth/actions) -->

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant [NextJS applications](https://nextjs.org/). It follows OAuth 2.1 and OpenID standards. It supports both CommonJS and ES Modules and includes TypeScript declaration files. It works for both the NextJS App Router as well as the Page Router.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Auth Flow Walkthrough](https://docs.wristband.dev/docs/auth-flows-and-diagrams)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Installation

```sh
npm install @wristband/nextjs-auth
```

or 

```sh
yarn add @wristband/nextjs-auth
```

## Usage

### 1) Initialize the SDK
First, create an instance of `WristbandAuth` in your NextJS directory structure in any location of your choice (i.e. `src/wristband-auth.ts`). Then, you can export this instance and use it across your project. When creating an instance, you provide all necessary configurations for your application to correlate with how you've set it up in Wristband. 

```typescript
import { createWristbandAuth } from '@wristband/nextjs-auth';

const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  rootDomain: "yourapp.io",
  useCustomDomains: true,
  useTenantSubdomains: true,
  wristbandApplicationDomain: "auth.yourapp.io",
});

export default wristbandAuth;
```

### 2) Choose Your Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies.  We are fans of <ins>[Iron Session](https://github.com/vvo/iron-session)</ins> for this reason. Examples below show what it might look like when using such a library to manage your application's session data.

First, add your session framework to your project:

```typescript
// @/src/session/iron-session.ts
import { getIronSession, IronSession, SessionOptions } from 'iron-session';

// Example: Define the type for the data you plan to store in your session
type SessionData = {
  accessToken: string;
  expiresAt: number;
  isAuthenticated: boolean;
  refreshToken?: string;
  tenantCustomDomain?: string;
  tenantDomainName: string;
  user: User;
};

// Define the configuration of the session cookie
const sessionOptions: SessionOptions = {
  cookieName: 'my-session-cookie-name',
  password: 'my-session-cookie-secret',
  cookieOptions: {
    httpOnly: true,
    maxAge: 1800,
    path: '/',
    sameSite: true,
    secure: true,
  },
};

//
// vv Exampe of functions to use elsewhere in your code. vv
//

// This is the "classic" way of getting the session.
export function getSession(
  req: http.IncomingMessage | Request,
  res: http.ServerResponse | Response
): Promise<IronSession<SessionData>> {
  return getIronSession(req, res, sessionOptions);
}

// The App Router can leverage the new `cookies()` function in NextJS.
export function getSessionAppRouter(): Promise<IronSession<SessionData>> {
  return getIronSession<SessionData>(cookies(), sessionOptions);
}

// The `cookies()` function in NextJS is not available in middleware, so both router types will rely on passing in a Response object.
export function middlewareGetSession(
  req: http.IncomingMessage | Request,
  res: http.ServerResponse | Response
): Promise<IronSession<SessionData>> {
  return getSession<SessionData>(req, res);
}
...
...
```

### 3) Add Auth Endpoints

There are <ins>three core endpoints</ins> your NextJS API routes should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your API routes live.

#### [Login Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#login-endpoint)

The goal of the Login Endpoint is to initiate an auth request by redircting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

##### App Router

```typescript
// @/src/app/api/auth/login/route.ts
import type { NextRequest } from 'next/server';
import wristbandAuth from '@/wristband-auth.ts';

export async function GET(req: NextRequest) {
  return await wristbandAuth.appRouter.login(req);
}
```

##### Page Router

```typescript
// @/src/pages/api/auth/login.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import wristbandAuth from '@/wristband-auth.ts';

export default async function handleLogin(req: NextApiRequest, res: NextApiResponse) {
    await wristbandAuth.pageRouter.login(req, res);
}
```

#### [Callback Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#callback-endpoint)

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

##### App Router

```typescript
// @/src/app/api/auth/callback/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { CallbackResultType } from '@wristband/nextjs-auth';
import wristbandAuth from '@/wristband-auth.ts';
import { getSessionAppRouter } from '@/session/iron-session';

export async function GET(req: NextRequest) {
  const callbackResult = await wristbandAuth.appRouter.callback(req);
  const { callbackData, redirectResponse, result } = callbackResult;

  if (result === CallbackResultType.REDIRECT_REQUIRED) {
    return redirectResponse;
  }
  
  const session = await getSessionAppRouter();

  // Save any necessary fields for your app session into the session cookie.
  session.isAuthenticated = true;
  session.accessToken = callbackData.accessToken;
  // Convert the "expiresIn" seconds into an expiration date with the format of milliseconds from the epoch.
  session.expiresAt = Date.now() + callbackData.expiresIn * 1000;
  session.refreshToken = callbackData.refreshToken;
  session.userId = callbackData.userinfo.sub;
  session.tenantId = callbackData.userinfo.tnt_id;
  session.identityProviderName = callbackData.userinfo.idp_name;
  session.tenantDomainName = callbackData.tenantDomainName;
  session.tenantCustomDomain = callbackData.tenantCustomDomain || undefined;
  
  await session.save();

  // Send the user back to the application.
  const appUrl = callbackData.returnUrl || `https://${callbackData.tenantDomainName}.yourapp.io/`;
  return wristbandAuth.appRouter.createCallbackResponse(req, appUrl);
}
```

##### Page Router

```typescript
// @/src/pages/api/auth/callback.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { CallbackResultType } from '@wristband/nextjs-auth';
import wristbandAuth from '@/wristband-auth.ts';
import { getSession } from '@/session/iron-session';

export default async function handleCallback(req: NextApiRequest, res: NextApiResponse) {
  const callbackResult = await wristbandAuth.pageRouter.callback(req, res);
  const { callbackData, result } = callbackResult;

  if (result === CallbackResultType.REDIRECT_REQUIRED) {
    return;
  }
  
  const session = await getSession(req, res);

  // Save any necessary fields for your app session into the session cookie.
  session.isAuthenticated = true;
  session.accessToken = callbackData.accessToken;
  // Convert the "expiresIn" seconds into an expiration date with the format of milliseconds from the epoch.
  session.expiresAt = Date.now() + callbackData.expiresIn * 1000;
  session.refreshToken = callbackData.refreshToken;
  session.userId = callbackData.userinfo.sub;
  session.tenantId = callbackData.userinfo.tnt_id;
  session.identityProviderName = callbackData.userinfo.idp_name;
  session.tenantDomainName = callbackData.tenantDomainName;
  session.tenantCustomDomain = callbackData.tenantCustomDomain || undefined;
  
  await session.save();

  // Send the user back to the application.
  const appUrl = callbackData.returnUrl || `https://${callbackData.tenantDomainName}.yourapp.io/`;
  res.redirect(appUrl);
}
```


#### [Logout Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#logout-endpoint-1)

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

##### App Router

```typescript
// @/src/app/api/auth/logout/route.ts
import type { NextRequest } from 'next/server';
import { cookies } from 'next/headers';
import { getSessionAppRouter } from '@/session/iron-session';
import wristbandAuth from '@/wristband-auth';

export async function GET(req: NextRequest) {
  const session = await getSessionAppRouter();
  const { refreshToken, tenantCustomDomain, tenantDomainName } = session;

  // Always destroy session.
  cookies().delete('my-session-cookie-name');
  session.destroy();

  return await wristbandAuth.appRouter.logout(req, { refreshToken, tenantCustomDomain, tenantDomainName });
});
```

##### Page Router

```typescript
// @/src/pages/api/auth/callback.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '@/session/iron-session';
import wristbandAuth from '@/wristband-auth';

export default async function logoutRoute(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  const { refreshToken, tenantCustomDomain, tenantDomainName } = session;

  // Always destroy session.
  res.setHeader('Set-Cookie', `my-session-cookie-name=; Max-Age=0; Path=/`);
  session.destroy();

  await wristbandAuth.pageRouter.logout(req, res, { refreshToken, tenantCustomDomain, tenantDomainName });
});
```

### 4) Guard Your Pages, Actions, and APIs / Handle Token Refresh

> [!NOTE]
> There may be applications that do not want to utilize access tokens and/or refresh tokens. If that applies to your application, then you can ignore using the `refreshTokenIfExpired()` functionality.

#### Middleware

For most cases, the NextJS middleware is an ideal place to centralize and perform auth checks as well as refresh expired tokens. The Wristband SDK will make 3 attempts to refresh the token and return the latest JWTs to your app.

```typescript
// @/src/middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { middlewareGetSession } from '@/session/iron-session';
import { wristbandAuth } from '@/wristband-auth';

const HTTP_401_STATUS = { status: 401 };
const UNAUTHORIZED = { statusText: 'Unauthorized' };

export async function middleware(req: NextRequest) {
  const res = NextResponse.next();

  // ** Replace with whatever path matching your app needs. **
  const isProtectedPage: boolean = req.nextUrl.pathname.startsWith('/dashboard');
  const isProtectedApiRoute: boolean = req.nextUrl.pathname.startsWith('/api/v1');
  
  // Simply return if the path is not meant to be protected
  if (!isProtectedPage && !isProtectedApiRoute) {
    return res;
  }

  const session = await middlewareGetSession(req, res);
  const { expiresAt, isAuthenticated, refreshToken } = session;
  const host = req.headers.get('host');
  
  // UX: Optionally set a return URL for users that do get redirected to login.
  const returnUrl = `http://${host}${req.nextUrl.pathname}`;
  // NOTE: If you are not using tenant subdomains, you'll need to append the tenant_domain query param to the loginUrl: "&tenant_domain=mytenant".
  const loginUrl = `http://${host}/api/auth/login?return_url=${returnUrl}`;

  // Send unauthenticated users to the login page.
  if (!isAuthenticated) {
    return isProtectedApiRoute ? NextResponse.json(UNAUTHORIZED, HTTP_401_STATUS) : NextResponse.redirect(loginUrl);
  }

  // Always verify the refresh token is not expired and touch the session timestamp.
  try {
    const tokenData = await wristbandAuth.refreshTokenIfExpired(refreshToken, expiresAt);
    if (tokenData) {
      // Convert the "expiresIn" seconds into an expiration date with the format of milliseconds from the epoch.
      session.expiresAt = Date.now() + tokenData.expiresIn * 1000;
      session.accessToken = tokenData.accessToken;
      session.refreshToken = tokenData.refreshToken;
    }

    // Save and/or touch the session.
    await session.save();
  } catch (error) {
    console.log(`Token refresh failed: ${error}`);
    return isProtectedApiRoute ? NextResponse.json(UNAUTHORIZED, HTTP_401_STATUS) : NextResponse.redirect(loginUrl);
  }

  return res;
};

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

There may be instances where using middleware is not feasible due to specific application requirements and design considerations. In such cases, authentication checks and token refreshes should be performed directly at the point where a user attempts to access a protected resource.

#### API Routes

You can perform auth checks in API routes, which can be useful if you need to fetch data on the server-side that depends on the user's authentication status. For example:

```typescript
// @/src/app/api/v1/hello-world/route.ts
import { NextResponse } from 'next/server';
import { getSession } from '@/session/iron-session';

export async function GET() {
  const session = await getSession();
  const { isAuthenticated } = session;

  /* WRISTBAND_TOUCHPOINT - AUTHENTICATION */
  if (!isAuthenticated) {
    return NextResponse.json({ statusText: 'Unauthorized' }, { status: 401 });
  }
  
  //
  // Call wristbandAuth.refreshTokenIfExpired(refreshToken, expiresAt), if needed
  //

  return NextResponse.json({ message: 'Hello World' });
}
```

#### Page Router: getServerSideProps() and getStaticProps()

You can perform auth checks before rendering a page on the server when using the Page Router, which can again be useful if you need to fetch data on the server-side that depends on the user's authentication status. For example:

```typescript
// @/src/pages/ssr-page.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '@/session/iron-session';
import wristbandAuth from '@/wristband-auth';

export const getServerSideProps: GetServerSideProps = async function (context: GetServerSidePropsContext) {
  const { req, res } = context;
  const session = await getSession(req, res);

  const { isAuthenticated } = session;
  if (!isAuthenticated) {
    const returnUrl = `http://${req.headers.host}${req.url}`;
    // NOTE: If you are not using tenant subdomains, you'll need to append the tenant_domain query param to the loginUrl: "&tenant_domain=mytenant".
    return {
      redirect: {
        destination: `http://${req.headers.host}/api/auth/login?return_url=${returnUrl}`,
        permanent: false,
      }
    };
  }
  
  //
  // Call wristbandAuth.refreshTokenIfExpired() and update session, if needed
  //

  return { props: { // your props } };
};
```

#### App Router: Server Components and Actions

You can perform auth checks directly in a server component or in server actions when using the App Router. For example:

```typescript
// @/src/app/my-page/page.tsx
'use server';

import { getSessionAppRouter } from '@/session/iron-session';

export default async function MyPage() {
  const session = await getSessionAppRouter();
  const { isAuthenticated } = session;

  if (!isAuthenticated) {
    // NOTE: If you are not using tenant subdomains, you'll need to append the tenant_domain query param to the loginUrl: "?tenant_domain=mytenant".
    redirect('/api/auth/login');
    return null;
  }
  
  //
  // Call wristbandAuth.refreshTokenIfExpired() and update session, if needed
  //

  const data = await getMyServerData();

  return <p>My data: {data}</p>;
}
```

### 5) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

For example, if you were using attempting to fetch user data from Wristband in an API route, you would pass the access token from your application session into the `Authorization` header as follows:

```typescript
const session = await getSession();
const { accessToken, userId } = session;

const userResponse = await fetch(`https://yourapp-yourcompany.us.wristband.dev/api/v1/users/${userId}`, {
  method: 'GET',
  headers: {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

if (userResponse.status === 401) {
  redirect('/api/auth/login');
  return null;
}

const user = await userResponse.json();

console.log(user); // Output -> { id: 123, ... }
```

## Wristband Auth Configuration Options

The `createWristbandAuth()` function is used to instatiate the Wristband SDK.  It takes an `AuthConfig` type as an argument.

```ts
function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {}
```

| AuthConfig Field | Type | Required | Description |
| ---------- | ---- | -------- | ----------- |
| clientId | string | Yes | The client ID for the application. |
| clientSecret | string | Yes | The client secret for the application. |
| customApplicationLoginPageUrl | string | No | Custom Application-Level Login Page URL (Tenant Discovery) if you are building/self-hosting that portion of the UI. By default, the SDK will use your Wristband-hosted Application-Level Login pgae URL. The SDK will redirect to either the self-hosted or Wristband-hosted URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerouslyDisableSecureCookies | boolean | No | USE WITH CAUTION: If set to true, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development (if necessary). |
| loginStateSecret | string | Yes | A secret -- 32 or more characters in length -- used for encryption and decryption of login state cookies. |
| loginUrl | string | Yes | The URL for initiating the login request. |
| redirectUri | string | Yes | The redirect URI for callback after authentication. |
| rootDomain | string | Depends | The root domain for your application. This value only needs to be specified if you use tenant subdomains in your login and redirect URLs. |
| scopes | string[] | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `[openid, offline_access, email]`. |
| useCustomDomains | boolean | No | Indicates whether custom domains are used for authentication. |
| useTenantSubdomains | boolean | No | Indicates whether tenant subdomains are used for authentication. |
| wristbandApplicationDomain | string | Yes | The vanity domain of the Wristband application. |


## API

### login()

```ts
/* *** App Router *** */
// Definition
login: (req: NextRequest, loginConfig?: LoginConfig) => Promise<NextResponse>;
// Usage
await wristbandAuth.appRouter.login(req);

/* *** Page Router *** */
// Definition
login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig) => Promise<NextApiResponse>;
// Usage
await wristbandAuth.pageRouter.login(req, res);
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your NextJS Login Endpoint, there are two ways to accomplish getting the `tenantDomainName` information: passing a query parameter or using tenant subdomains.

The `login()` function can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| customState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| defaultTenantDomainName | string | No | An optional default tenant domain name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| defaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |

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
  wristbandApplicationDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your NextJS Login Endpoint. The SDK will parse the tenant subdomain from the URL in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

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
  rootDomain: "yourapp.io",
  useTenantSubdomains: true,
  wristbandApplicationDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Default Tenant Domain Name

For certain use cases, it may be useful to specify a default tenant domain name in the event that the `login()` function cannot find a tenant domain name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant domain name via a `LoginConfig` object. For example:

```ts
await wristbandAuth.pageRouter.login(req, res, { defaultTenantDomainName: 'default' });
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
await wristbandAuth.login(req, res, { defaultTenantCustomDomain: 'mytenant.com' });
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

Wristband will redirect to your NextJS Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/api/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.  Given that your frontend will redirect users to your NextJS Login Endpoint, you can pass a `return_url` query parameter when redirecting to your Login Endpoint, and that URL will be available to you upon completion of the Callback Endpoint.

```sh
GET https://customer01.yourapp.io/api/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and you can choose to send users to that return URL (if necessary) after the SDK's `callback()` funciton is done executing.

### callback()

```ts
/* *** App Router *** */
// Definition
callback: (req: NextRequest) => Promise<AppRouterCallbackResult>;
createCallbackResponse: (req: NextRequest, redirectUrl: string) => NextResponse;

// Usage
const callbackResult = await wristbandAuth.appRouter.callback(req);
return wristbandAuth.appRouter.createCallbackResponse(req, appUrl);

/* *** Page Router *** */
// Definition
callback: (req: NextApiRequest, res: NextApiResponse) => Promise<PageRouterCallbackResult>;

// Usage
const callbackResult = await wristbandAuth.pageRouter.callback(req, res);
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your NextJS Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/api/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback function is either a `PageRouterCallbackResult` or a `AppRouterCallbackResult` object containing the result of what happened during callback execution as well as any accompanying data. The following are common fields that both objects share:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callbackData | CallbackData or `undefined` | The callback data received after authentication (`COMPLETED` result only). |
| result | CallbackResultType | Enum representing the end result of callback execution. |

<br>

The following are fields only for the `AppRouterCallbackResult`:

| AppRouterCallbackResult Field | Type | Description |
| ----------------------------- | ---- | ----------- |
| redirectResponse | NextResponse or `undefined` | The NextResponse that the user should be redirected with (`REDIRECT_REQUIRED` only). |

<br>

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType | Description |
| ------------------ | ----------- |
| COMPLETED | Indicates that the callback is successfully completed and data is available for creating a session. |
| REDIRECT_REQUIRED | Indicates that a redirect is required, generally to a login route or page. |

<br>

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:

| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| customState | JSON or `undefined` | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expiresIn | number | The durtaion from the current time until the access token is expired (in seconds). |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| returnUrl | string or `undefined` | The URL to return to after authentication is completed. |
| tenantCustomDomain | string | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantDomainName | string | The domain name of the tenant the user belongs to. |
| userinfo | JSON | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |

<br>

When using the App Router, there is a second function called `createCallbackResponse()` you must use to create the appropriate redirect response to your application's destination URL while ensuring the proper response headers are set.

```
const appUrl = callbackData.returnUrl || `https://yourapp.io/home`;
return wristbandAuth.appRouter.createCallbackResponse(req, appUrl);
```


#### Redirect Responses

There are certain scenarios where instead of callback data being returned by the SDK, a redirect response occurs during execution instead.  The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

In these events, the user will get redirected back to your NextJS Login Endpoint.

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


### logout()

```ts
/* *** App Router *** */
// Definition
logout: (req: NextRequest, logoutConfig?: LogoutConfig) => Promise<NextResponse>;
// Usage
await wristbandAuth.appRouter.logout(req, { refreshToken: '98yht308hf902hc90wh09' });

/* *** Page Router *** */
// Definition
logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig) => Promise<NextApiResponse>;
// Usage
await wristbandAuth.pageRouter.logout(req, res, { refreshToken: '98yht308hf902hc90wh09' });
```

When users of your application are ready to log out and/or their application session expires, your frontend should redirect the user to your NextJS Logout Endpoint.

```sh
GET https://customer01.yourapp.io/api/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` function.  This function can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| redirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed.  |
| refreshToken | string | No | The refresh token to revoke. |
| tenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantDomainName | string | No | The domain name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?
Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if subdomains are enabled and the subdomain is present.
3. `tenantDomain` in LogoutConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` function, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domain Names

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you will need to explicitly pass it into the LogoutConfig.

```ts
await wristbandAuth.pageRouter.logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09', tenantDomainName: 'customer01' });
```

If your application uses tenant subdomains, then passing the `tenantDomainName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you will need to explicitly pass it into the LogoutConfig.

```ts
await logout(req, res, { refreshToken: '98yht308hf902hc90wh09', tenantCustomDomain: 'mytenant.com' });
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then passing both the `tenantDomainName` and `tenantCustomDomain` fields to the LogoutConfig is necessary to ensure all use cases are handled by the SDK.

```ts
const { refreshToken, tenantCustomDomain, tenantDomainName } = session;

await logout(req, res, { refreshToken, tenantCustomDomain, tenantDomainName });
```

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```ts
const logoutConfig = {
  redirectUrl: 'https://custom-logout.com',
  refreshToken: '98yht308hf902hc90wh09',
  tenantDomainName: 'customer01'
};
await wristbandAuth.appRouter.logout(req, logoutConfig);
```

### refreshTokenIfExpired()

```ts
// Definition (App Router & Page Router)
refreshTokenIfExpired: (refreshToken: string, expiresAt: number) => Promise<TokenData | null>;

// Usage (App Router & Page Router)
const tokenData = await wristbandAuth.refreshTokenIfExpired('98yht308hf902hc90wh09', 1710707503788);
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expiresAt | number | Yes | Unix timestamp in milliseconds at which the token expires. |
| refreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refreshTokenIfExpired()` functions finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

<br>

## Wristband Multi-Tenant NextJS Demo Apps

You can check out the following NextJS demo apps to see the SDK in action. Refer to that GitHub repositories for more information.

- [NextJS Demo App - App Router](https://github.com/wristband-dev/b2b-nextjs-app-router-demo-app)
- [NextJS Demo App - Page Router](https://github.com/wristband-dev/b2b-nextjs-page-router-demo-app) 

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
