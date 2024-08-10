import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../utils/constants';

interface RequestOptions extends RequestInit {
  headers?: HeadersInit;
  body?: any;
}

export class WristbandApiClient {
  private baseURL: string;
  private defaultHeaders: HeadersInit;

  constructor(wristbandApplicationDomain: string) {
    this.baseURL = `https://${wristbandApplicationDomain}/api/v1`;
    this.defaultHeaders = { 'Content-Type': FORM_URLENCODED_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE };
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = { ...this.defaultHeaders, ...options.headers };
    const config: RequestInit = { ...options, headers };
    const response = await fetch(url, config);

    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return undefined as T;
    }

    const responseBody = await response.text();
    return responseBody ? (JSON.parse(responseBody) as T) : (undefined as T);
  }

  public async get<T>(endpoint: string, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', headers, keepalive: true });
  }

  public async post<T>(endpoint: string, body: any, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'POST', headers, body, keepalive: true });
  }
}
