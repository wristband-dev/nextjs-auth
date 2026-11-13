export const FORM_URLENCODED_MEDIA_TYPE: string = 'application/x-www-form-urlencoded';
export const JSON_MEDIA_TYPE: string = 'application/json;charset=UTF-8';
export const LOGIN_REQUIRED_ERROR: string = 'login_required';
export const LOGIN_STATE_COOKIE_SEPARATOR = '#';
export const LOGIN_STATE_COOKIE_PREFIX: string = `login${LOGIN_STATE_COOKIE_SEPARATOR}`;
export const LOGIN_STATE_COOKIE_MAX_AGE_SEC: number = 3600;
export const STATE_PARAM_MAX_CHAR_LENGTH: number = 512;
// Common retry settings applied to all Wristband API calls made from WristbandService.
export const MAX_API_RETRY_ATTEMPTS: number = 3;
export const API_RETRY_DELAY_MS: number = 100;
// Multiplier applied to the delay after each retry attempt (exponential backoff).
export const API_RETRY_DELAY_MULTIPLIER: number = 2;
export const NO_CACHE_HEADERS = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };
export const REDIRECT_RESPONSE_INIT = { status: 302, headers: NO_CACHE_HEADERS };
export const TENANT_NAME_PLACEHOLDER: string = '{tenant_name}';
// Regexes to match the {tenant_name} placeholder
export const LEADING_TENANT_PLACEHOLDER_REGEX = /^https?:\/\/\{tenant_name\}\./;
export const TENANT_PLACEHOLDER_REGEX = /\{tenant_name\}/;
export const TENANT_PLACEHOLDER_MSG = '"{tenant_name}" placeholder';
// One DNS label: letters, digits, and inner hyphens, up to 63 characters.
const DNS_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
export const TENANT_NAME_REGEX = new RegExp(`^${DNS_LABEL}$`, 'i');
export const DOMAIN_NAME_REGEX = new RegExp(`^(?:${DNS_LABEL}\\.)+${DNS_LABEL}$`, 'i');
