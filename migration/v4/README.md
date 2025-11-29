<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v3.x to version v4.x
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

# Migration instruction from version v3.x to version v4.x

## Table of Contents

- [WristbandAuth API Rename](#wristbandauth-api-rename)
- [UserInfo Type Changes](#userinfo-type-changes)
- [LoginConfig Property Rename](#loginconfig-property-rename)
- [CallbackData Property Changes](#callbackdata-property-changes)
- [CallbackResultType Changes](#callbackresulttype-changes)
- [LogoutConfig Property Rename](#logoutconfig-property-rename)
- [Optional: Built-in Session Management](#optional-built-in-session-management)

<br>

## WristbandAuth API Rename

The `pageRouter` property has been renamed to `pagesRouter` to align with Next.js's official naming convention for the Pages Router.

**Before (v3.x):**
```typescript
const loginUrl = await wristbandAuth.pageRouter.login(req, res);
const callbackResult = await wristbandAuth.pageRouter.callback(req, res);
// etc...
```

**After (v4.x):**
```typescript
const loginUrl = await wristbandAuth.pagesRouter.login(req, res);
const callbackResult = await wristbandAuth.pagesRouter.callback(req, res);
// etc.
```

This change ensures consistency with Next.js documentation and terminology, which refers to this routing paradigm as the "Pages Router" (plural).

<br>

## UserInfo Type Changes

The SDK now provides a new `UserInfo` type that transforms raw OIDC claims from Wristband's Userinfo Endpoint into a structured format that provides better type safety and aligns with JavaScript/TypeScript naming conventions. The `CallbackData.userinfo` field now uses this new `UserInfo` type.

Key changes include:

- Standard OIDC claims are now mapped to camelCase properties (e.g., `sub` → `userId`, `tnt_id` → `tenantId`, `idp_name` → `identityProviderName`)
- All other user profile fields follow camelCase naming (e.g., `given_name` → `givenName`, `picture` → `pictureUrl`)
- The `roles` field now uses the new `UserInfoRole` type with properly typed properties

**Before (v3.x):**
```typescript
const callbackResult = await wristbandAuth.appRouter.callback(req);
const { userinfo } = callbackResult.callbackData;

// Access raw OIDC claims
const userId = userinfo.sub;
const tenantId = userinfo.tnt_id;
const identityProvider = userinfo.idp_name;
const givenName = userinfo.given_name;
```

**After (v4.x):**
```typescript
const callbackResult = await wristbandAuth.appRouter.callback(req);
const { userinfo } = callbackResult.callbackData;

// Access structured, camelCase properties
const userId = userinfo.userId;        // Previously: userinfo.sub
const tenantId = userinfo.tenantId;    // Previously: userinfo.tnt_id
const identityProvider = userinfo.identityProviderName;  // Previously: userinfo.idp_name
const givenName = userinfo.givenName;  // Previously: userinfo.given_name
...
```

For a complete mapping of all field names and types, refer to the `UserInfo` type documentation in the main [README](../../README.md#callback).

<br>

## LoginConfig Property Rename

The `LoginConfig` property `defaultTenantDomainName` has been renamed to `defaultTenantName` for better clarity.

**Before (v3.x):**
```typescript
// App Router
await wristbandAuth.appRouter.login(req, { defaultTenantDomainName: 'default' });

// Pages Router
await wristbandAuth.pagesRouter.login(req, res, { defaultTenantDomainName: 'default' });
```

**After (v4.x):**
```typescript
// App Router
await wristbandAuth.appRouter.login(req, { defaultTenantName: 'default' });

// Pages Router
await wristbandAuth.pagesRouter.login(req, res, { defaultTenantName: 'default' });
```

<br>

## CallbackData Property Changes

The `CallbackData` type has two property changes for better consistency and clarity:

- `tenantDomainName` has been renamed to `tenantName`
- `userinfo` now uses the new `UserInfo` type (see [UserInfo Type Changes](#userinfo-type-changes))

**Before (v3.x):**
```typescript
const callbackResult = await wristbandAuth.appRouter.callback(req);
const { callbackData } = callbackResult;

// Access tenant domain name
const tenantName = callbackData.tenantDomainName;

// Access userinfo with raw OIDC claims
const userId = callbackData.userinfo.sub;
const tenantId = callbackData.userinfo.tnt_id;
```

**After (v4.x):**
```typescript
const callbackResult = await wristbandAuth.appRouter.callback(req);
const { callbackData } = callbackResult;

// Access tenant name
const tenantName = callbackData.tenantName;

// Access userinfo with new camelCase properties
const userId = callbackData.userinfo.userId;
const tenantId = callbackData.userinfo.tenantId;
```

<br>

## CallbackResultType Changes

The `CallbackResultType` enum has been replaced with a string literal union type for better TypeScript ergonomics and consistency with modern TypeScript patterns.

**Before (v3.x):**
```typescript
import { CallbackResultType } from '@wristband/nextjs-auth';

const callbackResult = await wristbandAuth.appRouter.callback(req);
const { type } = callbackResult;

if (type === CallbackResultType.REDIRECT_REQUIRED) {
  return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
}

if (type === CallbackResultType.COMPLETED) {
  // Handle successful authentication
}
```

**After (v4.x):**
```typescript
// No need to import CallbackResultType anymore
const callbackResult = await wristbandAuth.appRouter.callback(req);
const { type } = callbackResult;

if (type === 'redirect_required') {
  return await wristbandAuth.appRouter.createCallbackResponse(req, redirectUrl);
}

if (type === 'completed') {
  // Handle successful authentication
}
```

<br>

## LogoutConfig Property Rename

The `LogoutConfig` property `tenantDomainName` has been renamed to `tenantName` for clarity.

**Before (v3.x):**
```typescript
// App Router
await wristbandAuth.appRouter.logout(req, { tenantDomainName: 'customer01' });

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, { tenantDomainName: 'customer01' });
```

**After (v4.x):**
```typescript
// App Router
await wristbandAuth.appRouter.logout(req, { tenantName: 'customer01' });

// Pages Router
await wristbandAuth.pagesRouter.logout(req, res, { tenantName: 'customer01' });
```

<br>

## Optional: Built-in Session Management (New Feature)

> **⚠️ Non-Breaking Change**
> 
> This is a new feature, not a breaking change. You can continue using your existing session management solution without any modifications. Migration to the built-in session management is completely optional.

Version 4.0 introduces optional built-in session management powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). This is entirely optional and **does not affect existing applications** using other session libraries.

If you want to reduce dependencies on third-party session libraries, you can now use Wristband's built-in session management. Refer to the [Session Management section](../../README.md#2-set-up-session-management) in the main README for complete documentation on how to adopt this feature.

**Key benefits of the built-in session management:**
- No external dependencies required
- Type-safe session data with TypeScript
- Encrypted cookie-based sessions (AES-256-GCM)
- Optional CSRF token protection
- Context-specific helpers for App Router, Pages Router, Server Components, Server Actions, and Middleware/Proxy
- Rolling session expiration
- Automatic token refresh when using authentication middleware

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
