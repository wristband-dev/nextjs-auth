export const FORM_URLENCODED_MEDIA_TYPE: string = 'application/x-www-form-urlencoded';
export const JSON_MEDIA_TYPE: string = 'application/json;charset=UTF-8';
export const LOGIN_REQUIRED_ERROR: string = 'login_required';
export const LOGIN_STATE_COOKIE_SEPARATOR = '#';
export const LOGIN_STATE_COOKIE_PREFIX: string = `login${LOGIN_STATE_COOKIE_SEPARATOR}`;
export const NO_CACHE_HEADERS = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };
export const REDIRECT_RESPONSE_INIT = { status: 302, headers: NO_CACHE_HEADERS };
export const TENANT_DOMAIN_TOKEN: string = '{tenant_domain}';
