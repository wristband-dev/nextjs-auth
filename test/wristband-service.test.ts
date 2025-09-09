import { WristbandService } from '../src/wristband-service';
import { WristbandApiClient } from '../src/wristband-api-client';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../src/utils/constants';
import { encodeBase64 } from '../src/utils/auth/common-utils';

// Mock the WristbandApiClient
jest.mock('../src/wristband-api-client');
jest.mock('../src/utils/auth/common-utils');

describe('WristbandService', () => {
  let service: WristbandService;
  let mockApiClient: jest.Mocked<WristbandApiClient>;
  let mockEncodeBase64: jest.MockedFunction<typeof encodeBase64>;

  const testDomain = 'test.wristband.com';
  const testClientId = 'test-client-id';
  const testClientSecret = 'test-client-secret';
  const encodedCredentials = 'dGVzdC1jbGllbnQtaWQ6dGVzdC1jbGllbnQtc2VjcmV0';

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup mock for encodeBase64
    mockEncodeBase64 = encodeBase64 as jest.MockedFunction<typeof encodeBase64>;
    mockEncodeBase64.mockReturnValue(encodedCredentials);

    // Create service instance
    service = new WristbandService(testDomain, testClientId, testClientSecret);

    // Get the mocked API client instance
    mockApiClient = (service as any).wristbandApiClient as jest.Mocked<WristbandApiClient>;
  });

  describe('constructor', () => {
    it('should create WristbandApiClient with correct domain', () => {
      expect(WristbandApiClient).toHaveBeenCalledWith(testDomain);
    });

    it('should encode credentials for basic auth', () => {
      expect(mockEncodeBase64).toHaveBeenCalledWith(`${testClientId}:${testClientSecret}`);
    });

    it('should set basic auth headers correctly', () => {
      const expectedHeaders = {
        'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
        Authorization: `Basic ${encodedCredentials}`,
      };
      expect((service as any).basicAuthHeaders).toEqual(expectedHeaders);
    });

    it('should store clientId', () => {
      expect((service as any).clientId).toBe(testClientId);
    });
  });

  describe('getSdkConfiguration', () => {
    it('should call API client with correct parameters', async () => {
      const mockSdkConfig = {
        customApplicationLoginPageUrl: 'https://example.com/login',
        isApplicationCustomDomainActive: false,
        loginUrl: 'https://example.com/auth/login',
        loginUrlTenantDomainSuffix: null,
        redirectUri: 'https://example.com/auth/callback',
      };

      mockApiClient.get.mockResolvedValue(mockSdkConfig);

      const result = await service.getSdkConfiguration();

      expect(mockApiClient.get).toHaveBeenCalledWith(`/clients/${testClientId}/sdk-configuration`, {
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      });
      expect(result).toEqual(mockSdkConfig);
    });

    it('should propagate API client errors', async () => {
      const error = new Error('API Error');
      mockApiClient.get.mockRejectedValue(error);

      await expect(service.getSdkConfiguration()).rejects.toThrow('API Error');
    });
  });

  describe('getTokens', () => {
    const testCode = 'test-auth-code';
    const testRedirectUri = 'https://example.com/callback';
    const testCodeVerifier = 'test-code-verifier';

    it('should call API client with correct parameters', async () => {
      const mockTokenResponse = {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockApiClient.post.mockResolvedValue(mockTokenResponse);

      const result = await service.getTokens(testCode, testRedirectUri, testCodeVerifier);

      const expectedAuthData = [
        'grant_type=authorization_code',
        `code=${testCode}`,
        `redirect_uri=${encodeURIComponent(testRedirectUri)}`,
        `code_verifier=${encodeURIComponent(testCodeVerifier)}`,
      ].join('&');

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/oauth2/token',
        expectedAuthData,
        (service as any).basicAuthHeaders
      );
      expect(result).toEqual(mockTokenResponse);
    });

    it('should properly encode redirect URI and code verifier', async () => {
      const specialRedirectUri = 'https://example.com/callback?param=value&other=test';
      const specialCodeVerifier = 'code-verifier-with-special-chars+/=';

      mockApiClient.post.mockResolvedValue({});

      await service.getTokens(testCode, specialRedirectUri, specialCodeVerifier);

      const expectedAuthData = [
        'grant_type=authorization_code',
        `code=${testCode}`,
        `redirect_uri=${encodeURIComponent(specialRedirectUri)}`,
        `code_verifier=${encodeURIComponent(specialCodeVerifier)}`,
      ].join('&');

      expect(mockApiClient.post).toHaveBeenCalledWith('/oauth2/token', expectedAuthData, expect.any(Object));
    });

    it('should propagate API client errors', async () => {
      const error = new Error('Token request failed');
      mockApiClient.post.mockRejectedValue(error);

      await expect(service.getTokens(testCode, testRedirectUri, testCodeVerifier)).rejects.toThrow(
        'Token request failed'
      );
    });
  });

  describe('getUserinfo', () => {
    const testAccessToken = 'test-access-token';

    it('should call API client with correct parameters', async () => {
      const mockUserinfo = {
        sub: 'user-123',
        email: 'user@example.com',
        name: 'Test User',
        tnt_id: 'tenant-123',
        idp_name: 'google',
      };

      mockApiClient.get.mockResolvedValue(mockUserinfo);

      const result = await service.getUserinfo(testAccessToken);

      expect(mockApiClient.get).toHaveBeenCalledWith('/oauth2/userinfo', {
        Authorization: `Bearer ${testAccessToken}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      });
      expect(result).toEqual(mockUserinfo);
    });

    it('should propagate API client errors', async () => {
      const error = new Error('Userinfo request failed');
      mockApiClient.get.mockRejectedValue(error);

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow('Userinfo request failed');
    });
  });

  describe('refreshToken', () => {
    const testRefreshToken = 'test-refresh-token';

    it('should call API client with correct parameters', async () => {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockApiClient.post.mockResolvedValue(mockTokenResponse);

      const result = await service.refreshToken(testRefreshToken);

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/oauth2/token',
        `grant_type=refresh_token&refresh_token=${testRefreshToken}`,
        (service as any).basicAuthHeaders
      );
      expect(result).toEqual(mockTokenResponse);
    });

    it('should propagate API client errors', async () => {
      const error = new Error('Token refresh failed');
      mockApiClient.post.mockRejectedValue(error);

      await expect(service.refreshToken(testRefreshToken)).rejects.toThrow('Token refresh failed');
    });
  });

  describe('revokeRefreshToken', () => {
    const testRefreshToken = 'test-refresh-token';

    it('should call API client with correct parameters', async () => {
      mockApiClient.post.mockResolvedValue(undefined);

      await service.revokeRefreshToken(testRefreshToken);

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/oauth2/revoke',
        `token=${testRefreshToken}`,
        (service as any).basicAuthHeaders
      );
    });

    it('should not return anything on success', async () => {
      mockApiClient.post.mockResolvedValue(undefined);

      const result = await service.revokeRefreshToken(testRefreshToken);

      expect(result).toBeUndefined();
    });

    it('should propagate API client errors', async () => {
      const error = new Error('Token revocation failed');
      mockApiClient.post.mockRejectedValue(error);

      await expect(service.revokeRefreshToken(testRefreshToken)).rejects.toThrow('Token revocation failed');
    });
  });

  describe('integration with WristbandApiClient', () => {
    it('should use the same API client instance for all methods', async () => {
      // Mock all API client methods
      mockApiClient.get.mockResolvedValue({});
      mockApiClient.post.mockResolvedValue({});

      // eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
      const apiClientInstance = (service as any).wristbandApiClient;

      await service.getSdkConfiguration();
      await service.getTokens('code', 'uri', 'verifier');
      await service.getUserinfo('token');
      await service.refreshToken('refresh');
      await service.revokeRefreshToken('refresh');

      // All calls should use the same instance
      expect(mockApiClient.get).toHaveBeenCalledTimes(2); // getSdkConfiguration + getUserinfo
      expect(mockApiClient.post).toHaveBeenCalledTimes(3); // getTokens + refreshToken + revokeRefreshToken
    });
  });

  describe('header consistency', () => {
    it('should use JSON headers for GET requests', async () => {
      mockApiClient.get.mockResolvedValue({});

      await service.getSdkConfiguration();
      await service.getUserinfo('token');

      // Check that JSON headers are used for GET requests
      expect(mockApiClient.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          'Content-Type': JSON_MEDIA_TYPE,
          Accept: JSON_MEDIA_TYPE,
        })
      );
    });

    it('should use form headers for POST requests', async () => {
      mockApiClient.post.mockResolvedValue({});

      await service.getTokens('code', 'uri', 'verifier');
      await service.refreshToken('refresh');
      await service.revokeRefreshToken('refresh');

      // Check that form headers are used for POST requests
      const expectedHeaders = {
        'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
        Authorization: `Basic ${encodedCredentials}`,
      };

      expect(mockApiClient.post).toHaveBeenCalledWith(expect.any(String), expect.any(String), expectedHeaders);
    });

    it('should use bearer token headers for userinfo', async () => {
      const token = 'test-token';
      mockApiClient.get.mockResolvedValue({});

      await service.getUserinfo(token);

      expect(mockApiClient.get).toHaveBeenCalledWith('/oauth2/userinfo', {
        Authorization: `Bearer ${token}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      });
    });
  });
});
