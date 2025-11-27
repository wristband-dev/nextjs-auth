import { FetchError, InvalidGrantError } from '../src/error';
import { WristbandService } from '../src/wristband-service';
import { WristbandApiClient } from '../src/wristband-api-client';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../src/utils/constants';
import { encodeBase64 } from '../src/utils/crypto';

// Mock the WristbandApiClient
jest.mock('../src/wristband-api-client');
jest.mock('../src/utils/crypto');

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

    it('should throw error when code is missing', async () => {
      await expect(service.getTokens('', testRedirectUri, testCodeVerifier)).rejects.toThrow(
        'Authorization code is required'
      );
    });

    it('should throw error when code is whitespace only', async () => {
      await expect(service.getTokens('   ', testRedirectUri, testCodeVerifier)).rejects.toThrow(
        'Authorization code is required'
      );
    });

    it('should throw error when redirectUri is missing', async () => {
      await expect(service.getTokens(testCode, '', testCodeVerifier)).rejects.toThrow('Redirect URI is required');
    });

    it('should throw error when redirectUri is whitespace only', async () => {
      await expect(service.getTokens(testCode, '   ', testCodeVerifier)).rejects.toThrow('Redirect URI is required');
    });

    it('should throw error when codeVerifier is missing', async () => {
      await expect(service.getTokens(testCode, testRedirectUri, '')).rejects.toThrow('Code verifier is required');
    });

    it('should throw error when codeVerifier is whitespace only', async () => {
      await expect(service.getTokens(testCode, testRedirectUri, '   ')).rejects.toThrow('Code verifier is required');
    });

    it('should throw InvalidGrantError when API returns invalid_grant error', async () => {
      const error = { error: 'invalid_grant', error_description: 'Authorization code has expired' };
      const mockResponse = new Response(JSON.stringify(error), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
      const fetchError = new FetchError(mockResponse, error);
      mockApiClient.post.mockRejectedValue(fetchError);
      await expect(service.getTokens(testCode, testRedirectUri, testCodeVerifier)).rejects.toThrow(InvalidGrantError);
      await expect(service.getTokens(testCode, testRedirectUri, testCodeVerifier)).rejects.toThrow(
        'Authorization code has expired'
      );
    });

    it('should throw InvalidGrantError with default message when no error_description', async () => {
      const error = { error: 'invalid_grant' };
      const mockResponse = new Response(JSON.stringify(error), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
      const fetchError = new FetchError(mockResponse, error);
      mockApiClient.post.mockRejectedValue(fetchError);
      await expect(service.getTokens(testCode, testRedirectUri, testCodeVerifier)).rejects.toThrow('Invalid grant');
    });

    it('should propagate non-invalid_grant API client errors', async () => {
      const error = new Error('Network error');
      mockApiClient.post.mockRejectedValue(error);

      await expect(service.getTokens(testCode, testRedirectUri, testCodeVerifier)).rejects.toThrow('Network error');
    });
  });

  describe('getUserinfo', () => {
    const testAccessToken = 'test-access-token';

    it('should call API client with correct parameters and map claims', async () => {
      const mockWristbandUserinfo = {
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
        email: 'user@example.com',
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User',
      };

      mockApiClient.get.mockResolvedValue(mockWristbandUserinfo);

      const result = await service.getUserinfo(testAccessToken);

      expect(mockApiClient.get).toHaveBeenCalledWith('/oauth2/userinfo', {
        Authorization: `Bearer ${testAccessToken}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      });

      // Verify camelCase mapping
      expect(result).toEqual({
        userId: 'user-123',
        tenantId: 'tenant-123',
        applicationId: 'app-123',
        identityProviderName: 'google',
        email: 'user@example.com',
        fullName: 'Test User',
        givenName: 'Test',
        familyName: 'User',
        middleName: undefined,
        nickname: undefined,
        displayName: undefined,
        pictureUrl: undefined,
        gender: undefined,
        birthdate: undefined,
        timeZone: undefined,
        locale: undefined,
        updatedAt: undefined,
        emailVerified: undefined,
        phoneNumber: undefined,
        phoneNumberVerified: undefined,
        roles: undefined,
        customClaims: undefined,
      });
    });

    it('should map minimal userinfo response with only required fields', async () => {
      const mockMinimalUserinfo = {
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'local',
      };

      mockApiClient.get.mockResolvedValue(mockMinimalUserinfo);

      const result = await service.getUserinfo(testAccessToken);

      expect(result.userId).toBe('user-123');
      expect(result.tenantId).toBe('tenant-123');
      expect(result.applicationId).toBe('app-123');
      expect(result.identityProviderName).toBe('local');
      expect(result.email).toBeUndefined();
      expect(result.fullName).toBeUndefined();
    });

    it('should map complete userinfo response with all profile fields', async () => {
      const mockCompleteUserinfo = {
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
        name: 'John Doe',
        given_name: 'John',
        family_name: 'Doe',
        middle_name: 'Robert',
        nickname: 'Johnny',
        preferred_username: 'jdoe',
        picture: 'https://example.com/photo.jpg',
        gender: 'male',
        birthdate: '1990-01-01',
        zoneinfo: 'America/New_York',
        locale: 'en-US',
        updated_at: 1234567890,
        email: 'john@example.com',
        email_verified: true,
        phone_number: '+1234567890',
        phone_number_verified: true,
        custom_claims: { department: 'Engineering' },
      };

      mockApiClient.get.mockResolvedValue(mockCompleteUserinfo);

      const result = await service.getUserinfo(testAccessToken);

      expect(result).toEqual({
        userId: 'user-123',
        tenantId: 'tenant-123',
        applicationId: 'app-123',
        identityProviderName: 'google',
        fullName: 'John Doe',
        givenName: 'John',
        familyName: 'Doe',
        middleName: 'Robert',
        nickname: 'Johnny',
        displayName: 'jdoe',
        pictureUrl: 'https://example.com/photo.jpg',
        gender: 'male',
        birthdate: '1990-01-01',
        timeZone: 'America/New_York',
        locale: 'en-US',
        updatedAt: 1234567890,
        email: 'john@example.com',
        emailVerified: true,
        phoneNumber: '+1234567890',
        phoneNumberVerified: true,
        roles: undefined,
        customClaims: { department: 'Engineering' },
      });
    });

    it('should map roles array with display_name field', async () => {
      const mockUserinfoWithRoles = {
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
        roles: [
          { id: 'role-1', name: 'admin', display_name: 'Administrator' },
          { id: 'role-2', name: 'user', display_name: 'User' },
        ],
      };

      mockApiClient.get.mockResolvedValue(mockUserinfoWithRoles);

      const result = await service.getUserinfo(testAccessToken);

      expect(result.roles).toEqual([
        { id: 'role-1', name: 'admin', displayName: 'Administrator' },
        { id: 'role-2', name: 'user', displayName: 'User' },
      ]);
    });

    it('should map roles array with camelCase displayName fallback', async () => {
      const mockUserinfoWithRoles = {
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
        roles: [{ id: 'role-1', name: 'admin', displayName: 'Admin User' }],
      };

      mockApiClient.get.mockResolvedValue(mockUserinfoWithRoles);

      const result = await service.getUserinfo(testAccessToken);

      expect(result.roles).toEqual([{ id: 'role-1', name: 'admin', displayName: 'Admin User' }]);
    });

    it('should throw error when access token is missing', async () => {
      await expect(service.getUserinfo('')).rejects.toThrow('Access token is required');
    });

    it('should throw error when access token is whitespace only', async () => {
      await expect(service.getUserinfo('   ')).rejects.toThrow('Access token is required');
    });

    it('should throw error when response is not an object', async () => {
      mockApiClient.get.mockResolvedValue(null);
      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow('Invalid userinfo response: expected object');

      mockApiClient.get.mockResolvedValue([]);
      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow('Invalid userinfo response: expected object');

      mockApiClient.get.mockResolvedValue('string');
      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow('Invalid userinfo response: expected object');
    });

    it('should throw error when sub claim is missing', async () => {
      mockApiClient.get.mockResolvedValue({
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
      });

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow(
        'Invalid userinfo response: missing sub claim'
      );
    });

    it('should throw error when sub claim is not a string', async () => {
      mockApiClient.get.mockResolvedValue({
        sub: 123,
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
      });

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow(
        'Invalid userinfo response: missing sub claim'
      );
    });

    it('should throw error when tnt_id claim is missing', async () => {
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        app_id: 'app-123',
        idp_name: 'google',
      });

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow(
        'Invalid userinfo response: missing tnt_id claim'
      );
    });

    it('should throw error when app_id claim is missing', async () => {
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        tnt_id: 'tenant-123',
        idp_name: 'google',
      });

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow(
        'Invalid userinfo response: missing app_id claim'
      );
    });

    it('should throw error when idp_name claim is missing', async () => {
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
      });

      await expect(service.getUserinfo(testAccessToken)).rejects.toThrow(
        'Invalid userinfo response: missing idp_name claim'
      );
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

    it('should throw error when refresh token is missing', async () => {
      await expect(service.refreshToken('')).rejects.toThrow('Refresh token is required');
    });

    it('should throw error when refresh token is whitespace only', async () => {
      await expect(service.refreshToken('   ')).rejects.toThrow('Refresh token is required');
    });

    it('should throw InvalidGrantError when API returns invalid_grant error', async () => {
      const error = { error: 'invalid_grant', error_description: 'Refresh token has expired' };
      const mockResponse = new Response(JSON.stringify(error), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
      const fetchError = new FetchError(mockResponse, error);
      mockApiClient.post.mockRejectedValue(fetchError);
      await expect(service.refreshToken(testRefreshToken)).rejects.toThrow(InvalidGrantError);
      await expect(service.refreshToken(testRefreshToken)).rejects.toThrow('Refresh token has expired');
    });

    it('should throw InvalidGrantError with default message when no error_description', async () => {
      const error = { error: 'invalid_grant' };
      const mockResponse = new Response(JSON.stringify(error), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
      const fetchError = new FetchError(mockResponse, error);
      mockApiClient.post.mockRejectedValue(fetchError);
      await expect(service.refreshToken(testRefreshToken)).rejects.toThrow('Invalid grant');
    });

    it('should propagate non-invalid_grant API client errors', async () => {
      const error = new Error('Network error');
      mockApiClient.post.mockRejectedValue(error);

      await expect(service.refreshToken(testRefreshToken)).rejects.toThrow('Network error');
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

    it('should throw error when refresh token is missing', async () => {
      await expect(service.revokeRefreshToken('')).rejects.toThrow('Refresh token is required');
    });

    it('should throw error when refresh token is whitespace only', async () => {
      await expect(service.revokeRefreshToken('   ')).rejects.toThrow('Refresh token is required');
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
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
      });
      mockApiClient.post.mockResolvedValue({});

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
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
      });

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
      mockApiClient.get.mockResolvedValue({
        sub: 'user-123',
        tnt_id: 'tenant-123',
        app_id: 'app-123',
        idp_name: 'google',
      });

      await service.getUserinfo(token);

      expect(mockApiClient.get).toHaveBeenCalledWith('/oauth2/userinfo', {
        Authorization: `Bearer ${token}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      });
    });
  });
});
