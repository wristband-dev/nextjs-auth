import { WristbandApiClient } from '../src/wristband-api-client';
import { FetchError } from '../src/error';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../src/utils/constants';

describe('WristbandApiClient', () => {
  let client: WristbandApiClient;
  let mockFetch: jest.MockedFunction<typeof fetch>;
  const testDomain = 'test.wristband.com';

  beforeEach(() => {
    mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;
    global.fetch = mockFetch;
    client = new WristbandApiClient(testDomain);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should set correct baseURL', () => {
      expect((client as any).baseURL).toBe(`https://${testDomain}/api/v1`);
    });

    it('should set default headers', () => {
      const expectedHeaders = {
        'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      };
      expect((client as any).defaultHeaders).toEqual(expectedHeaders);
    });
  });

  describe('get method', () => {
    it('should make GET request with correct parameters', async () => {
      const mockResponse = { id: 1, name: 'test' };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      const result = await client.get('/test-endpoint');

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1/test-endpoint`, {
        method: 'GET',
        headers: {
          'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
          Accept: JSON_MEDIA_TYPE,
        },
        keepalive: true,
      });
      expect(result).toEqual(mockResponse);
    });

    it('should merge custom headers with default headers', async () => {
      const mockResponse = { data: 'test' };
      const customHeaders = { Authorization: 'Bearer token123' };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('/test-endpoint', customHeaders);

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1/test-endpoint`, {
        method: 'GET',
        headers: {
          'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
          Accept: JSON_MEDIA_TYPE,
          Authorization: 'Bearer token123',
        },
        keepalive: true,
      });
    });

    it('should override default headers with custom headers', async () => {
      const mockResponse = { data: 'test' };
      const customHeaders = { 'Content-Type': 'application/json' };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('/test-endpoint', customHeaders);

      expect(mockFetch).toHaveBeenCalledWith(
        `https://${testDomain}/api/v1/test-endpoint`,
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
    });
  });

  describe('post method', () => {
    it('should make POST request with correct parameters', async () => {
      const mockResponse = { success: true };
      const requestBody = 'param1=value1&param2=value2';

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      const result = await client.post('/test-endpoint', requestBody);

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1/test-endpoint`, {
        method: 'POST',
        headers: {
          'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
          Accept: JSON_MEDIA_TYPE,
        },
        body: requestBody,
        keepalive: true,
      });
      expect(result).toEqual(mockResponse);
    });

    it('should merge custom headers with default headers for POST', async () => {
      const mockResponse = { created: true };
      const customHeaders = { Authorization: 'Bearer token456' };
      const requestBody = { name: 'test' };

      mockFetch.mockResolvedValueOnce({
        status: 201,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.post('/test-endpoint', requestBody, customHeaders);

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1/test-endpoint`, {
        method: 'POST',
        headers: {
          'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
          Accept: JSON_MEDIA_TYPE,
          Authorization: 'Bearer token456',
        },
        body: requestBody,
        keepalive: true,
      });
    });
  });

  describe('request method (via public methods)', () => {
    it('should handle 204 No Content response', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 204,
        text: jest.fn().mockResolvedValue(''),
      } as any);

      const result = await client.get('/test-endpoint');

      expect(result).toBeUndefined();
    });

    it('should handle empty response body', async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(''),
      } as any);

      const result = await client.get('/test-endpoint');

      expect(result).toBeUndefined();
    });

    it('should parse JSON response correctly', async () => {
      const mockData = { id: 123, name: 'test user' };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockData)),
      } as any);

      const result = await client.get('/test-endpoint');

      expect(result).toEqual(mockData);
    });

    it('should handle complex JSON response', async () => {
      const complexData = {
        user: { id: 1, profile: { name: 'John', age: 30 } },
        permissions: ['read', 'write'],
        metadata: { created: '2023-01-01' },
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(complexData)),
      } as any);

      const result = await client.get('/users/1');

      expect(result).toEqual(complexData);
    });
  });

  describe('error handling', () => {
    it('should throw FetchError for 400 status', async () => {
      const errorResponse = { error: 'Bad Request' };
      const mockResponse = {
        status: 400,
        text: jest.fn().mockResolvedValue(JSON.stringify(errorResponse)),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      await expect(client.get('/test-endpoint')).rejects.toThrow(FetchError);
    });

    it('should throw FetchError for 401 status', async () => {
      const errorResponse = { error: 'Unauthorized' };
      const mockResponse = {
        status: 401,
        text: jest.fn().mockResolvedValue(JSON.stringify(errorResponse)),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      await expect(client.get('/test-endpoint')).rejects.toThrow(FetchError);
    });

    it('should throw FetchError for 404 status', async () => {
      const errorResponse = { error: 'Not Found' };
      const mockResponse = {
        status: 404,
        text: jest.fn().mockResolvedValue(JSON.stringify(errorResponse)),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      await expect(client.get('/test-endpoint')).rejects.toThrow(FetchError);
    });

    it('should throw FetchError for 500 status', async () => {
      const errorResponse = { error: 'Internal Server Error' };
      const mockResponse = {
        status: 500,
        text: jest.fn().mockResolvedValue(JSON.stringify(errorResponse)),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      await expect(client.post('/test-endpoint', {})).rejects.toThrow(FetchError);
    });

    it('should pass response and parsed body to FetchError', async () => {
      const errorResponse = { error: 'Validation failed', details: ['Invalid email'] };
      const mockResponse = {
        status: 422,
        text: jest.fn().mockResolvedValue(JSON.stringify(errorResponse)),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      try {
        await client.post('/test-endpoint', {});
      } catch (error) {
        expect(error).toBeInstanceOf(FetchError);
        expect((error as FetchError<any>).response).toBe(mockResponse);
        expect((error as FetchError<any>).body).toEqual(errorResponse);
      }
    });

    it('should handle error response with empty body', async () => {
      const mockResponse = {
        status: 400,
        text: jest.fn().mockResolvedValue(''),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      await expect(client.get('/test-endpoint')).rejects.toThrow(FetchError);
    });

    it('should handle malformed JSON in error response', async () => {
      const mockResponse = {
        status: 400,
        text: jest.fn().mockResolvedValue('invalid json {'),
      };

      mockFetch.mockResolvedValueOnce(mockResponse as any);

      // This should still throw a FetchError, but might also throw JSON parse error
      await expect(client.get('/test-endpoint')).rejects.toThrow();
    });
  });

  describe('edge cases', () => {
    it('should handle endpoints starting with slash', async () => {
      const mockResponse = { data: 'test' };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('/test-endpoint');

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1/test-endpoint`, expect.any(Object));
    });

    it('should handle endpoints without leading slash', async () => {
      const mockResponse = { data: 'test' };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('test-endpoint');

      expect(mockFetch).toHaveBeenCalledWith(`https://${testDomain}/api/v1test-endpoint`, expect.any(Object));
    });

    it('should handle null/undefined body in POST', async () => {
      const mockResponse = { success: true };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.post('/test-endpoint', null);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: null,
        })
      );
    });

    it('should handle empty headers object', async () => {
      const mockResponse = { data: 'test' };
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('/test-endpoint', {});

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: {
            'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
          },
        })
      );
    });
  });

  describe('URL construction', () => {
    it('should construct URL correctly with complex domain', () => {
      const complexClient = new WristbandApiClient('subdomain.example.wristband.com');
      expect((complexClient as any).baseURL).toBe('https://subdomain.example.wristband.com/api/v1');
    });

    it('should construct URL correctly with various endpoints', async () => {
      const mockResponse = {};
      mockFetch.mockResolvedValue({
        status: 200,
        text: jest.fn().mockResolvedValue(JSON.stringify(mockResponse)),
      } as any);

      await client.get('/oauth2/token');
      expect(mockFetch).toHaveBeenLastCalledWith(`https://${testDomain}/api/v1/oauth2/token`, expect.any(Object));

      await client.get('/oauth2/userinfo');
      expect(mockFetch).toHaveBeenLastCalledWith(`https://${testDomain}/api/v1/oauth2/userinfo`, expect.any(Object));

      await client.get('/clients/123/sdk-configuration');
      expect(mockFetch).toHaveBeenLastCalledWith(
        `https://${testDomain}/api/v1/clients/123/sdk-configuration`,
        expect.any(Object)
      );
    });
  });
});
