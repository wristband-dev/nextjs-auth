/** *****************************
 * Externally available types
 ***************************** */

/**
 * Represents the configuration for Wristband authentication.
 * @typedef {Object} AuthConfig
 * @property {string} clientId - The client ID for the application.
 * @property {string} clientSecret - The client secret for the application.
 * @property {string} customApplicationLoginPageUrl - Custom application login (tenant discovery) page URL if you are self-hosting the application login/tenant discovery UI.
 * @property {string} dangerouslyDisableSecureCookies - If set to true, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development (if necessary).
 * @property {string} loginStateSecret - A secret (32 or more characters in length) used for encryption and decryption of login state cookies.
 * @property {string} loginUrl - The URL for initiating the login request.
 * @property {string} redirectUri - The redirect URI for callback after authentication.
 * @property {string} [rootDomain] - The root domain for your application.
 * @property {string[]} [scopes] - The scopes required for authentication.
 * @property {boolean} [useCustomDomains] - Indicates whether custom domains are used for authentication.
 * @property {boolean} [useTenantSubdomains] - Indicates whether tenant subdomains are used for authentication.
 * @property {string} wristbandApplicationDomain - The vanity domain of the Wristband application.
 */
export type AuthConfig = {
  clientId: string;
  clientSecret: string;
  customApplicationLoginPageUrl?: string;
  dangerouslyDisableSecureCookies?: boolean;
  loginStateSecret: string;
  loginUrl: string;
  redirectUri: string;
  rootDomain?: string;
  scopes?: string[];
  useCustomDomains?: boolean;
  useTenantSubdomains?: boolean;
  wristbandApplicationDomain: string;
};

/**
 * Represents the configuration for login.
 * @typedef {Object} LoginConfig
 * @property {Object.<string, any>} [customState] - Custom state data for the login request.
 * @property {string} [defaultTenantDomain] - An optional default tenant domain name to use for the login request in the
 * event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain
 * configuration).
 */
export type LoginConfig = {
  customState?: { [key: string]: any };
  defaultTenantDomain?: string;
};

/**
 * Represents the configuration for the auth callback.
 * @typedef {Object} CallbackConfig
 * @property {string} [defaultTenantDomain] - An optional default tenant domain name to use in the event a redirect to
 * the login endpoint is required. This can happen when subdomains are not utilized and the tenant domain from the login
 * state is not present (e.g login state cookie expired).
 */
export type CallbackConfig = {
  defaultTenantDomain?: string;
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
 * Represents the result of the callback execution after authentication. It can be the set of callback
 * data necessary for creating an authenticated session, or it can be a redirect URL.
 * @typedef {Object} CallbackResult
 * @property {CallbackData} [callbackData] - The callback data received after authentication (COMPLETED only).
 * @property {string} [redirectUrl] - The URL where the user should be redirected to (REDIRECT_REQUIRED only).
 * @property {CallbackResultType} [result] - Enum representing the end result of callback execution.
 */
export type CallbackResult = {
  callbackData?: CallbackData;
  redirectUrl?: string;
  result: CallbackResultType;
};

/**
 * Represents the token data received after authentication.
 * @typedef {Object} TokenData
 * @property {string} accessToken - The access token.
 * @property {number} expiresIn - The durtaion from the current time until the access token is expired (in seconds).
 * @property {string} idToken - The ID token.
 * @property {string} [refreshToken] - The refresh token.
 */
export type TokenData = {
  accessToken: string;
  expiresIn: number;
  idToken: string;
  refreshToken?: string;
};

/**
 * Represents the callback data received after authentication.
 * @typedef {TokenData} CallbackData
 * @property {Object.<string, any>} [customState] - Custom state data received in the callback.
 * @property {string} [returnUrl] - The URL to return to after authentication.
 * @property {string} [tenantDomainName] - The domain name of the tenant the user belongs to.
 * @property {Userinfo} userinfo - User information received in the callback.
 */
export type CallbackData = TokenData & {
  customState?: { [key: string]: any };
  returnUrl?: string;
  tenantDomainName: string;
  userinfo: Userinfo;
};

/**
 * Represents the configuration for logout.
 * @typedef {Object} LogoutConfig
 * @property {string} [refreshToken] - The refresh token to revoke during logout.
 * @property {string} [tenantDomainName] - The domain name of the tenant the user belongs to.
 * @property {string} [redirectUrl] - Optional URL that the logout endpoint will redirect to after completing the
 * logout operation.
 */
export type LogoutConfig = {
  refreshToken?: string;
  tenantDomainName?: string;
  redirectUrl?: string;
};

/** *****************************
 * Internal-only types
 ***************************** */

/**
 * Represents all possible state for the current login request, which is stored in the login state cookie.
 * @typedef {Object} LoginState
 * @property {string} codeVerifier - The code verifier for PKCE.
 * @property {Object.<string, any>} [customState] - Custom state data for the login state.
 * @property {string} redirectUri - The redirect URI for callback after authentication.
 * @property {string} [returnUrl] - The URL to return to after authentication.
 * @property {string} state - The state of the login process.
 * @property {string} [tenantDomainName] - The domain name of the tenant the user belongs to.
 */
export type LoginState = {
  codeVerifier: string;
  customState?: { [key: string]: any };
  redirectUri: string;
  returnUrl?: string;
  state: string;
  tenantDomainName?: string;
};

/**
 * Represents the configuration for the map which is stored in login state cookie.
 * @typedef {Object} LoginStateMapConfig
 * @property {Object.<string, any>} [customState] - Custom state data for the login state map.
 * @property {string} [tenantDomainName] - The domain name of the tenant the user belongs to.
 */
export type LoginStateMapConfig = {
  customState?: { [key: string]: any };
  tenantDomainName?: string;
};

/**
 * Represents the token response received from the Wristband token endpoint.
 * @typedef {Object} TokenResponse
 * @property {string} access_token - The access token.
 * @property {number} expires_in - The expiration time of the access token (in seconds).
 * @property {string} id_token - The ID token.
 * @property {string} [refresh_token] - The refresh token.
 * @property {string} token_type - The type of token.
 */
export type TokenResponse = {
  access_token: string;
  expires_in: number;
  id_token: string;
  refresh_token?: string;
  token_type: string;
};

/**
 * Represents user information for the user who is authenticating.
 * @typedef {Object.<string, any>} Userinfo
 * @description Refer to the Wristband userinfo endpoint documentation to see the full list of possible claims that
 * can be returned, depending on your scopes.
 */
export type Userinfo = {
  [key: string]: any;
};
