import { FetchError } from '../error';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../utils/constants';

interface RequestOptions extends RequestInit {
  headers?: HeadersInit;
  body?: any;
}

export class WristbandApiClient {
  private baseURL: string;
  private defaultHeaders: HeadersInit;

  constructor(wristbandApplicationVanityDomain: string) {
    this.baseURL = `https://${wristbandApplicationVanityDomain}/api/v1`;
    this.defaultHeaders = { 'Content-Type': FORM_URLENCODED_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE };
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = { ...this.defaultHeaders, ...options.headers };
    const config: RequestInit = { ...options, headers };
    const response = await fetch(url, config);

    if (response.status === 204) {
      return undefined as T;
    }

    const responseBodyText = await response.text();
    const responseBody = responseBodyText ? (JSON.parse(responseBodyText) as T) : (undefined as T);

    if (response.status >= 400) {
      throw new FetchError(response, responseBody);
    }

    return responseBody;
  }

  public async get<T>(endpoint: string, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', headers, keepalive: true });
  }

  public async post<T>(endpoint: string, body: any, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'POST', headers, body, keepalive: true });
  }
}
