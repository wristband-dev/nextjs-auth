<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v1.0.0 to version v2.0.0
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

# Migration instruction from version v1.0.0 to version v2.0.0

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 2.x

<br>

## Table of Contents

- [SDK Configuration Property Name Change](#sdk-configuration-property-name-change)
- [Redirect Logic Moved Upstream in Page Router Auth Flows](#redirect-logic-moved-upstream-in-page-router-auth-flows)
  - [Login](#login)
  - [Logout](#logout)
- [Callback Result Refactoring](#callback-result-refactoring)

<br>

## SDK Configuration Property Name Change

When calling `createWristbandAuth` to initialize the SDK, the `wristbandApplicationDomain` property has been renamed to `wristbandApplicationVanityDomain` in order to be more explicit:

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
  // New name for app vanity domain
  - wristbandApplicationDomain: "auth.yourapp.io",
  + wristbandApplicationVanityDomain: "auth.yourapp.io",
});

export default wristbandAuth;
```

<br>

## Redirect Logic Moved Upstream in Page Router Auth Flows

Both the `login` and `logout` functions for the Page Router now return a redirect URL value instead of automatically invoking the redirect. The server code which calls `login` and `logout` is now responsible for calling `res.redirect()` with the value of the returned url. This change allows your code to customize redirect behavior, making auth flows more adaptable to different environments and use cases.

**Login**
```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import wristbandAuth from '@/wristband-auth.ts';

export default async function handleLogin(req: NextApiRequest, res: NextApiResponse) {
  // caller now does the redirect with the returned URL
  - await wristbandAuth.pageRouter.login(req, res);
  + const authorizeUrl = await wristbandAuth.pageRouter.login(req, res);
  + res.redirect(authorizeUrl);
}
```

<br>

**Logout**
```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from '@/session/iron-session';
import wristbandAuth from '@/wristband-auth';

export default async function logoutRoute(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  const { refreshToken, tenantCustomDomain, tenantDomainName } = session;

  res.setHeader('Set-Cookie', `my-session-cookie-name=; Max-Age=0; Path=/`);
  session.destroy();

  // caller now does the redirect with the returned url
  - await wristbandAuth.pageRouter.logout(req, res, { refreshToken, tenantCustomDomain, tenantDomainName });
  + const logoutUrl = await wristbandAuth.pageRouter.logout(req, res, { refreshToken, tenantCustomDomain, tenantDomainName });
  + res.redirect(logoutUrl);
});
```

<br>

## Callback Result Refactoring

There is now only one `CallbackResult` type for both App Router and Page Router. The `AppRouterCallbackResult` and `PageRouterCallbackResult` types have been removed. The `CallbackResult` that is returned from calling `callback()` has two changes:
1. The `result` property has been renamed to `type` (Typescript type is still `CallbackResultType`) in order to reduce confusion.
2. For both App Router and Page Router, when the `type` has a value of `REDIRECT_REQUIRED`, a `redirectUrl` value is returned in the `CallbackResult`. The App Router no longer returns a `redirectResponse` in the result, and the Page Router no longer automatically invokes the redirect. The server code which calls `callback` is now responsible for calling `res.redirect()` with the value of the returned url. This change allows your code to customize redirect behavior, making auth flows more adaptable to different environments and use cases.

**App Router**
```typescript
export async function GET(req: NextRequest) {
  const callbackResult = await wristbandAuth.appRouter.callback(req);
  // redirectUrl is now returned instead of the redirect being revoked by the SDK
  - const { callbackData, redirectResponse, result } = callbackResult;
  + const { callbackData, redirectUrl, type } = callbackResult;

  - if (result === CallbackResultType.REDIRECT_REQUIRED) {
  + if (type === CallbackResultType.REDIRECT_REQUIRED) {
    // caller now does the redirect with the returned URL
    - return redirectResponse;
    + return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
  }

  ...
}
```

**Page Router**
```typescript
export default async function handleCallback(req: NextApiRequest, res: NextApiResponse) {
  const callbackResult = await wristbandAuth.pageRouter.callback(req, res);
  // redirectUrl is now returned instead of the redirect being revoked by the SDK
  - const { callbackData, result } = callbackResult;
  + const { callbackData, redirectUrl, type } = callbackResult;

  - if (result === CallbackResultType.REDIRECT_REQUIRED) {
  + if (type === CallbackResultType.REDIRECT_REQUIRED) {
    // caller now does the redirect with the returned URL
    - return;
    + return res.redirect(redirectUrl);
  }

  ...
}
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
