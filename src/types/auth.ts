/**
 * Represents the configuration for Wristband authentication.
 * @typedef {Object} AuthConfig
 * @property {boolean} [autoConfigureEnabled] Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown.
 * @property {string} clientId The client ID for the application.
 * @property {string} clientSecret The client secret for the application.
 * @property {string} [customApplicationLoginPageUrl] Custom application login (tenant discovery) page URL if you are self-hosting the application login/tenant discovery UI.
 * @property {string} [dangerouslyDisableSecureCookies] If set to true, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development (if necessary).
 * @property {boolean} [isApplicationCustomDomainActive] Indicates whether custom domains are used for authentication.
 * @property {string} [loginStateSecret] A secret (32 or more characters in length) used for encryption and decryption of login state cookies.
 * @property {string} [loginUrl] The URL for initiating the login request.
 * @property {string} [redirectUri] The redirect URI for callback after authentication.
 * @property {string} [parseTenantFromRootDomain] The root domain for your application.
 * @property {string[]} [scopes] The scopes required for authentication.
 * @property {number} [tokenExpirationBuffer] Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls.
 * @property {string} wristbandApplicationVanityDomain The vanity domain of the Wristband application.
 */
export type AuthConfig = {
  autoConfigureEnabled?: boolean;
  clientId: string;
  clientSecret: string;
  customApplicationLoginPageUrl?: string;
  dangerouslyDisableSecureCookies?: boolean;
  isApplicationCustomDomainActive?: boolean;
  loginStateSecret?: string;
  loginUrl?: string;
  redirectUri?: string;
  parseTenantFromRootDomain?: string;
  scopes?: string[];
  tokenExpirationBuffer?: number;
  wristbandApplicationVanityDomain: string;
};

/**
 * Represents the configuration for login.
 * @typedef {Object} LoginConfig
 * @property {Object.<string, any>} [customState] Custom state data for the login request.
 * @property {string} [defaultTenantCustomDomain] An optional default tenant custom domain to use for the login request in the
 * event the tenant custom domain cannot be found in the "tenant_custom_domain" request query parameter.
 * @property {string} [defaultTenantName] An optional default tenant name to use for the login request in the
 * event the tenant domain cannot be found in either the subdomain or the "tenant_domain" request query parameter (depending on
 * your subdomain configuration).
 * @property {string} [returnUrl] The URL to return to after authentication is completed. If a value is provided, then it takes precence over the `return_url` request query parameter.
 */
export type LoginConfig = {
  customState?: { [key: string]: any };
  defaultTenantCustomDomain?: string;
  defaultTenantName?: string;
  returnUrl?: string;
};

/**
 * Enum representing different possible results from the execution of the callback handler.
 */
export enum CallbackResultType {
  /**
   * Indicates that the callback is successfully completed and data is available for creating a session.
   */
  COMPLETED = 'COMPLETED',
  /**
   * Indicates that a redirect is required, generally to a login route or page.
   */
  REDIRECT_REQUIRED = 'REDIRECT_REQUIRED',
}

/**
 * Represents the result of the callback execution after authentication. It can contain the set of callback
 * data necessary for creating an authenticated session.
 * @typedef {Object} CallbackResult
 * @property {CallbackData} [callbackData] The callback data received after authentication (COMPLETED only).
 * @property {string} [redirectUrl] The URL to redirect to (REDIRECT_REQUIRED only).
 * @property {CallbackResultType} type Enum representing the end result of callback execution.
 */
export interface CallbackResult {
  callbackData?: CallbackData;
  redirectUrl?: string;
  type: CallbackResultType;
}

/**
 * Represents the token data received after authentication.
 * @typedef {Object} TokenData
 * @property {string} accessToken The access token.
 * @property {number} expiresAt The absolute expiration time of the access token in milliseconds since the Unix epoch.
 * @property {number} expiresIn The durtaion from the current time until the access token is expired (in seconds).
 * @property {string} idToken The ID token.
 * @property {string} [refreshToken] The refresh token.
 */
export type TokenData = {
  accessToken: string;
  expiresAt: number;
  expiresIn: number;
  idToken: string;
  refreshToken?: string;
};

/**
 * User Info Role model representing a role assigned to a user.
 */
export interface UserInfoRole {
  /** Globally unique ID of the role */
  id: string;
  /** The role name (e.g., "app:app-name:admin") */
  name: string;
  /** The human-readable display name for the role */
  displayName: string;
}

/**
 * User Info model representing claims from the Wristband UserInfo endpoint.
 *
 * This model represents user information returned from Wristband's OIDC-compliant
 * UserInfo endpoint, with field names mapped to match the User entity field names
 * in Wristband's Resource Management API. The claims returned depend on the scopes
 * requested during authorization.
 *
 * Always returned claims: userId, tenantId, applicationId, identityProviderName
 *
 * Scope-dependent claims:
 * - profile: fullName, givenName, familyName, middleName, nickname, displayName,
 *            pictureUrl, gender, birthdate, timeZone, locale, updatedAt
 * - email: email, emailVerified
 * - phone: phoneNumber, phoneNumberVerified
 * - roles: roles
 *
 * @example
 * ```json
 * {
 *   "userId": "x25rpgafgvgedcvjw52ooul3xm",
 *   "tenantId": "lu4a47jcm2ejayovsgbgbpkihb",
 *   "applicationId": "hblu4a47jcm2ejayovsgbgbpki",
 *   "identityProviderName": "Wristband",
 *   "fullName": "Bob Jay Smith",
 *   "givenName": "Bob",
 *   "familyName": "Smith",
 *   "email": "bob@example.com",
 *   "emailVerified": true,
 *   "roles": [
 *     {
 *       "id": "x25rpgafgvgedcvjw52oool3xm",
 *       "name": "app:app-name:admin",
 *       "displayName": "Admin Role"
 *     }
 *   ],
 *   "customClaims": {
 *     "fieldA": "a",
 *     "fieldB": "b"
 *   }
 * }
 * ```
 */
export interface UserInfo {
  // Always returned - mapped from OIDC standard claims
  /** ID of the user (mapped from "sub" claim) */
  userId: string;
  /** ID of the tenant that the user belongs to (mapped from "tnt_id" claim) */
  tenantId: string;
  /** ID of the application that the user belongs to (mapped from "app_id" claim) */
  applicationId: string;
  /** Name of the identity provider (mapped from "idp_name" claim) */
  identityProviderName: string;

  // Profile scope - mapped to User entity field names
  /** End-User's full name in displayable form (mapped from "name" claim) */
  fullName?: string;
  /** Given name(s) or first name(s) of the End-User */
  givenName?: string;
  /** Surname(s) or last name(s) of the End-User */
  familyName?: string;
  /** Middle name(s) of the End-User */
  middleName?: string;
  /** Casual name of the End-User */
  nickname?: string;
  /** Shorthand name by which the End-User wishes to be referred (mapped from "preferred_username") */
  displayName?: string;
  /** URL of the End-User's profile picture (mapped from "picture") */
  pictureUrl?: string;
  /** End-User's gender */
  gender?: string;
  /** End-User's birthday in YYYY-MM-DD format */
  birthdate?: string;
  /** End-User's time zone (mapped from "zoneinfo") */
  timeZone?: string;
  /** End-User's locale as BCP47 language tag (e.g., "en-US") */
  locale?: string;
  /** The value is represented as the number of seconds from the Unix epoch. */
  updatedAt?: number;

  // Email scope
  /** End-User's preferred email address */
  email?: string;
  /** True if the End-User's email address has been verified */
  emailVerified?: boolean;

  // Phone scope
  /** End-User's telephone number in E.164 format */
  phoneNumber?: string;
  /** True if the End-User's phone number has been verified */
  phoneNumberVerified?: boolean;

  // Roles scope
  /** The roles assigned to the user */
  roles?: UserInfoRole[];

  // Custom claims
  /** Object containing any configured custom claims */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  customClaims?: Record<string, any>;
}

/**
 * Represents the callback data received after authentication.
 * @typedef {TokenData} CallbackData
 * @property {Object.<string, any>} [customState] Custom state data received in the callback.
 * @property {string} [returnUrl] The URL to return to after authentication.
 * @property {string} [tenantCustomDomain] The tenant custom domain for the tenant that the user belongs to.
 * @property {string} [tenantName] The domain name of the tenant the user belongs to.
 * @property {UserInfo} userinfo User information received in the callback.
 */
export type CallbackData = TokenData & {
  customState?: { [key: string]: any };
  returnUrl?: string;
  tenantCustomDomain?: string;
  tenantName: string;
  userinfo: UserInfo;
};

/**
 * Represents the configuration for logout.
 * @typedef {Object} LogoutConfig
 * @property {string} [redirectUrl] Optional URL that the logout endpoint will redirect to after completing the
 * logout operation.
 * @property {string} [refreshToken] The refresh token to revoke during logout.
 * @property {string} [state] Optional value that will be appended as a query parameter to the resolved redirect URL, if provided.
 * @property {string} [tenantCustomDomain] The tenant custom domain for the tenant that the user belongs to (if applicable).
 * @property {string} [tenantName] The name of the tenant the user belongs to.
 */
export type LogoutConfig = {
  redirectUrl?: string;
  refreshToken?: string;
  state?: string;
  tenantCustomDomain?: string;
  tenantName?: string;
};

// ====================================================== //
// ================== INTERNAL TYPES ==================== //
// ====================================================== //

/**
 * Configuration object containing URLs and settings discovered from the Wristband SDK Configuration Endpoint.
 * These values are typically auto-configured by calling the Wristband API, but can also be manually provided
 * to override auto-discovered settings.
 * @typedef {Object} SdkConfiguration
 * @property {string|null} customApplicationLoginPageUrl Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value is only needed if you are self-hosting the application login page. When null, the SDK will use your Wristband-hosted Application-Level Login page URL.
 * @property {boolean} isApplicationCustomDomainActive Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL.
 * @property {string} loginUrl The URL of your application's login endpoint that redirects to Wristband to initialize the login flow. If using tenant subdomains, this value must contain the `{tenant_domain}` token.
 * @property {string|null} loginUrlTenantDomainSuffix The domain suffix used when constructing login URLs with tenant subdomains. This value is null when tenant subdomains are not being used.
 * @property {string} redirectUri The URI that Wristband will redirect to after authenticating a user. This should point to your application's callback endpoint. If using tenant subdomains, this value must contain the `{tenant_domain}` token.
 */
export type SdkConfiguration = {
  customApplicationLoginPageUrl: string | null;
  isApplicationCustomDomainActive: boolean;
  loginUrl: string;
  loginUrlTenantDomainSuffix: string | null;
  redirectUri: string;
};

/**
 * Represents all possible state for the current login request, which is stored in the login state cookie.
 * @typedef {Object} LoginState
 * @property {string} codeVerifier The code verifier for PKCE.
 * @property {Object.<string, any>} [customState] Custom state data for the login state.
 * @property {string} redirectUri The redirect URI for callback after authentication.
 * @property {string} [returnUrl] The URL to return to after authentication.
 * @property {string} state The state of the login process.
 */
export type LoginState = {
  codeVerifier: string;
  customState?: { [key: string]: any };
  redirectUri: string;
  returnUrl?: string;
  state: string;
};

/**
 * Represents the configuration for the map which is stored in login state cookie.
 * @typedef {Object} LoginStateMapConfig
 * @property {Object.<string, any>} [customState] Custom state data for the login state map.
 * @property {string} [returnUrl] The URL to return to after authentication.
 */
export type LoginStateMapConfig = {
  customState?: { [key: string]: any };
  returnUrl?: string;
};

/**
 * Represents the token response received from the Wristband token endpoint.
 * @typedef {Object} TokenResponse
 * @property {string} access_token The access token.
 * @property {number} expires_in The expiration time of the access token (in seconds).
 * @property {string} id_token The ID token.
 * @property {string} [refresh_token] The refresh token.
 * @property {string} token_type The type of token.
 */
export type TokenResponse = {
  access_token: string;
  expires_in: number;
  id_token: string;
  refresh_token?: string;
  token_type: string;
};

/**
 * Raw userinfo response from Wristband's OIDC userinfo endpoint.
 *
 * Contains required OIDC claims that are always present, plus optional
 * scope-dependent claims and custom claims.
 *
 * @description Refer to the Wristband userinfo endpoint documentation to see the full list of
 * possible claims that can be returned, depending on your scopes.
 */
export interface WristbandUserinfoResponse {
  /** Subject - unique identifier for the user (OIDC standard claim) */
  sub: string;
  /** Tenant ID - unique identifier for the tenant (Wristband custom claim) */
  tnt_id: string;
  /** Application ID - unique identifier for the application (Wristband custom claim) */
  app_id: string;
  /** Identity Provider Name - name of the identity provider (Wristband custom claim) */
  idp_name: string;

  // All other fields are optional and dynamic based on scopes
  [key: string]: any;
}

/**
 * Login state cookie structure for App Router.
 * Contains the cookie name and encrypted value for login state management.
 *
 * @internal
 */
export type AppRouterLoginStateCookie = {
  name: string;
  value: string;
};
