<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v4.x to version v5.x
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

# Migration instruction from version v4.x to version v5.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 5.x

<br>

## Table of Contents

- [Minimum Node.js and npm Versions](#minimum-nodejs-and-npm-versions)
- [Tenant Domain URL Placeholder Removed](#tenant-domain-url-placeholder-removed)
- [parseTenantFromRootDomain Config Removed](#parsetenantfromrootdomain-config-removed)
- [customState and customClaims Type Changes](#customstate-and-customclaims-type-changes)
- [Return URL Validation in callback()](#return-url-validation-in-callback)
- [Login State Cookie Encryption Changes](#login-state-cookie-encryption-changes)

<br>

## Minimum Node.js and npm Versions

The minimum supported Node.js version is now 22.0.0, and the minimum npm version is now 10.5.1. Node.js 20 reached end of life on April 30, 2026.

The SDK's `package.json` now declares:

**Before (v4.x):**
```json
"engines": {
- "node": ">=20.0.0",
- "npm": ">=9.6.0"
}
```

**After (v5.x):**
```json
"engines": {
+ "node": ">=22.0.0",
+ "npm": ">=10.5.1"
}
```

**Key Changes:**
1. Upgrade your app's runtime to Node.js 22 or later (Node.js 22.0.0 ships with npm 10.5.1, so upgrading Node covers npm too)
2. Update anything still pinned to Node.js 20, such as CI workflows, Dockerfiles, `.nvmrc` files, or hosting platform settings

<br>

## Tenant Domain URL Placeholder Removed

The `{tenant_domain}` placeholder, deprecated in v4.x, has been removed. `{tenant_name}` is now the only supported tenant placeholder in `loginUrl` and `redirectUri`.

**Before (v4.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
- loginUrl: "https://{tenant_domain}.yourapp.com/api/auth/login",
- redirectUri: "https://{tenant_domain}.yourapp.com/api/auth/callback",
});
```

**After (v5.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
+ loginUrl: "https://{tenant_name}.yourapp.com/api/auth/login",
+ redirectUri: "https://{tenant_name}.yourapp.com/api/auth/callback",
});
```

<br>

## parseTenantFromRootDomain Config Removed

The `parseTenantFromRootDomain` config has been removed from `AuthConfig`. Tenant subdomain parsing is now enabled whenever `loginUrl` contains the `{tenant_name}` placeholder, and the SDK determines the root domain from `loginUrl` by removing the `{tenant_name}` subdomain.

**Before (v4.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
  loginUrl: "https://{tenant_name}.yourapp.com/api/auth/login",
  redirectUri: "https://{tenant_name}.yourapp.com/api/auth/callback",
- parseTenantFromRootDomain: "yourapp.com",
});
```

**After (v5.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
  loginUrl: "https://{tenant_name}.yourapp.com/api/auth/login",
  redirectUri: "https://{tenant_name}.yourapp.com/api/auth/callback",
});
```

**Key Changes:**
1. Remove `parseTenantFromRootDomain` from your SDK config
2. The root domain is derived from `loginUrl` (e.g. `https://{tenant_name}.yourapp.com/api/auth/login` gives a root domain of `yourapp.com`)
3. If your app relies on auto-configuration and never set `parseTenantFromRootDomain`, no change is needed

> **⚠️ Important:**
>
> The `{tenant_name}` placeholder must appear exactly once in `loginUrl` and `redirectUri`, as the leftmost part of the hostname. Either both URLs contain the placeholder or neither does.

<br>

## customState and customClaims Type Changes

`customState` (in `LoginConfig` and `CallbackData`) and `customClaims` (in `UserInfo`) are now typed as `Record<string, unknown>` instead of allowing `any` values. Runtime behavior is unchanged, and JavaScript apps are not affected.

**Reading Values:**

**Before (v4.x):**
```typescript
// App Router: wristbandAuth.appRouter.callback(request)
// Pages Router: wristbandAuth.pagesRouter.callback(req, res)
const callbackResult = await wristbandAuth.appRouter.callback(request);

if (callbackResult.type === 'completed') {
  const { customState, userinfo } = callbackResult.callbackData;
- const userId: string = customState?.userId;
- const plan: string = userinfo.customClaims?.plan;
}
```

**After (v5.x):**
```typescript
// App Router: wristbandAuth.appRouter.callback(request)
// Pages Router: wristbandAuth.pagesRouter.callback(req, res)
const callbackResult = await wristbandAuth.appRouter.callback(request);

if (callbackResult.type === 'completed') {
  const { customState, userinfo } = callbackResult.callbackData;
+ const userId = customState?.userId as string;
+ const plan = userinfo.customClaims?.plan as string;
}
```

**Passing customState to login():**

**Before (v4.x):**
```typescript
- interface MyCustomState {
-   userId: string;
- }

const customState: MyCustomState = { userId: '123' };

// App Router
return await wristbandAuth.appRouter.login(request, { customState });

// Pages Router
const authorizeUrl = await wristbandAuth.pagesRouter.login(req, res, { customState });
```

**After (v5.x):**
```typescript
+ type MyCustomState = {
+   userId: string;
+ };

const customState: MyCustomState = { userId: '123' };

// App Router
return await wristbandAuth.appRouter.login(request, { customState });

// Pages Router
const authorizeUrl = await wristbandAuth.pagesRouter.login(req, res, { customState });
```

**Key Changes:**
1. Values read from `customState` or `customClaims` must be narrowed or cast before use
2. A `customState` value declared with an `interface` is no longer assignable and causes a type error. Declare it with a `type` alias instead, or pass a spread copy (e.g. `customState: { ...myState }`).

<br>

## Return URL Validation in callback()

`callback()` now validates the return URL before including it in the returned callback data. In v4.x, the return URL was passed through unchanged. A return URL that fails validation is now left out of the callback data, and the flow continues without it.

**App Router**

**Before (v4.x):**
```typescript
// Login request: /api/auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.appRouter.callback(request);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
- // returnUrl === 'https://otherapp.com/dashboard'
- return await wristbandAuth.appRouter.createCallbackResponse(request, returnUrl);
}
```

**After (v5.x):**
```typescript
// Login request: /api/auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.appRouter.callback(request);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
+ // returnUrl === undefined (the host does not match the request's host or the root domain)
+ return await wristbandAuth.appRouter.createCallbackResponse(request, returnUrl || '/home');
}
```

**Pages Router**

**Before (v4.x):**
```typescript
// Login request: /api/auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.pagesRouter.callback(req, res);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
- // returnUrl === 'https://otherapp.com/dashboard'
- return res.redirect(returnUrl);
}
```

**After (v5.x):**
```typescript
// Login request: /api/auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.pagesRouter.callback(req, res);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
+ // returnUrl === undefined (the host does not match the request's host or the root domain)
+ return res.redirect(returnUrl || '/home');
}
```

**Key Changes:**
1. Relative paths (e.g. `/settings`) resolve against the current request's host
2. The protocol must match the request's protocol, which blocks downgrades like `https` to `http`
3. The hostname must be either the root domain (when `loginUrl` contains the `{tenant_name}` placeholder) or the request's host
4. When application-level authorization requests are enabled and `loginUrl` contains the `{tenant_name}` placeholder, a return URL on the bare root domain is rewritten to the tenant's subdomain (e.g. `yourapp.com` to `acme.yourapp.com`)

> **⚠️ Important:**
>
> Make sure your Callback Endpoint has a default redirect location for when `returnUrl` is not present, since a return URL that worked in v4.x may now be left out.

<br>

## Login State Cookie Encryption Changes

The Login State Cookie is now encrypted with Wristband's own in-house crypto implementation, replacing the `iron-webcrypto` and `uncrypto` dependencies. No code or config changes are needed: the cookie is still encrypted with `loginStateSecret`, or with `clientSecret` when `loginStateSecret` is not set.

**Key Changes:**
1. Login State Cookies created by v4.x cannot be decrypted by v5.x. A user who is mid-login during the upgrade is redirected to the Login Endpoint once, and because Wristband already has an authenticated session for that user, the new login flow completes without asking them to sign in again.
2. When the Login State Cookie cannot be decrypted (tampered, expired, encrypted with a different secret, or created by v4.x), `callback()` no longer throws. It returns `redirect_required` with the `invalid_login_state` reason.
3. Pages Router: `callback()` clears the undecryptable cookie. App Router: `callback()` cannot set response cookies, so the undecryptable cookie is left in place until it expires (its max age is 1 hour). The next `login()` creates a new Login State Cookie either way.

> **⚠️ Important:**
>
> If your Callback Endpoint already handles the `redirect_required` result type, no change is needed. Otherwise, make sure it redirects to `callbackResult.redirectUrl` when `type` is `'redirect_required'`.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
