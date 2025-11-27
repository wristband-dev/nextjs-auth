import { getSession as getWristbandSession, SessionData } from '@wristband/typescript-session';
import { getMutableSessionFromCookies } from '../../src/session/from-cookies-session';
import { NextJsCookieStore, SERVER_COMPONENT_SESSION } from '../../src/types';

jest.mock('@wristband/typescript-session', () => {
  return {
    getSession: jest.fn(),
  };
});

const mockGetWristbandSession = getWristbandSession as jest.MockedFunction<typeof getWristbandSession>;

describe('getMutableSessionFromCookies', () => {
  const sessionOptions = {
    secrets: 'test-secret-key-at-least-32-chars-long',
    cookieName: 'test-session',
  };

  let mockCookieStore: NextJsCookieStore;

  beforeEach(() => {
    jest.clearAllMocks();

    mockCookieStore = {
      get: jest.fn(),
      set: jest.fn(),
    };
  });

  const createMockSession = (data: Record<string, any> = {}) => {
    // Separate methods from data
    const {
      get = jest.fn(),
      set = jest.fn(),
      delete: deleteFn = jest.fn(),
      save = jest.fn(),
      destroy = jest.fn(),
      saveToResponse = jest.fn(),
      destroyToResponse = jest.fn(),
      fromCallback = jest.fn(),
      enableDeferredMode = jest.fn(),
      flush = jest.fn(),
      flushSync = jest.fn(),
      getCookieDataForSave = jest.fn(),
      getCookieDataForDestroy = jest.fn(),
      toJSON = jest.fn(),
      toString = jest.fn(),
      ...sessionData
    } = data;

    return {
      ...sessionData,
      get,
      set,
      delete: deleteFn,
      save,
      destroy,
      saveToResponse,
      destroyToResponse,
      fromCallback,
      enableDeferredMode,
      flush,
      flushSync,
      getCookieDataForSave,
      getCookieDataForDestroy,
      toJSON,
      toString,
    };
  };

  describe('Happy Path', () => {
    it('should return a session with accessible data', async () => {
      const mockSessionData = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        isAuthenticated: true,
      };

      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      mockGetWristbandSession.mockResolvedValue(createMockSession(mockSessionData) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      expect(session.userId).toBe('user-123');
      expect(session.tenantId).toBe('tenant-456');
      expect(session.isAuthenticated).toBe(true);
    });

    it('should work with custom session data types', async () => {
      interface CustomSessionData extends SessionData {
        theme: string;
        preferences: {
          language: string;
          timezone: string;
        };
      }

      const mockSessionData: CustomSessionData = {
        userId: 'user-123',
        theme: 'dark',
        preferences: {
          language: 'en',
          timezone: 'UTC',
        },
      };

      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      mockGetWristbandSession.mockResolvedValue(createMockSession(mockSessionData) as any);

      const session = await getMutableSessionFromCookies<CustomSessionData>(mockCookieStore, sessionOptions);

      expect(session.theme).toBe('dark');
      expect(session.preferences.language).toBe('en');
      expect(session.preferences.timezone).toBe('UTC');
    });

    it('should work when no cookie exists (empty session)', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue(undefined);
      mockGetWristbandSession.mockResolvedValue(createMockSession() as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      expect(session).toBeDefined();
      expect(mockGetWristbandSession).toHaveBeenCalledTimes(1);

      const request = mockGetWristbandSession.mock.calls[0][0] as Request;
      expect(request.headers.get('cookie')).toBe('');
    });
  });

  describe('Allowed Mutations', () => {
    beforeEach(() => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });
    });

    it('should allow calling set() method', async () => {
      const mockSet = jest.fn();
      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123', set: mockSet }) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      (session as any).set('theme', 'dark');
      expect(mockSet).toHaveBeenCalledWith('theme', 'dark');
    });

    it('should allow calling delete() method', async () => {
      const mockDelete = jest.fn();
      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123', delete: mockDelete }) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      (session as any).delete('theme');
      expect(mockDelete).toHaveBeenCalledWith('theme');
    });
  });

  describe('Allowed Read Methods', () => {
    beforeEach(() => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });
    });

    it('should allow calling get() method', async () => {
      const mockGet = jest.fn().mockReturnValue('some-value');
      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123', get: mockGet }) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      const result = session.get('userId');
      expect(result).toBe('some-value');
      expect(mockGet).toHaveBeenCalledWith('userId');
    });

    it('should allow calling toJSON() method', async () => {
      const mockToJSON = jest.fn().mockReturnValue({ userId: 'user-123' });
      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123', toJSON: mockToJSON }) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      const json = session.toJSON();
      expect(mockToJSON).toHaveBeenCalled();
      expect(json).toEqual({ userId: 'user-123' });
    });

    it('should allow calling toString() method', async () => {
      const mockToString = jest.fn().mockReturnValue('[Session]');
      mockGetWristbandSession.mockResolvedValue(
        createMockSession({ userId: 'user-123', toString: mockToString }) as any
      );

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      const str = session.toString();
      expect(mockToString).toHaveBeenCalled();
      expect(str).toBe('[Session]');
    });
  });

  describe('No Server Component Marker', () => {
    it('should NOT add SERVER_COMPONENT_SESSION marker', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123' }) as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      // Should not have the marker at all
      expect((session as any)[SERVER_COMPONENT_SESSION]).toBeUndefined();
    });
  });

  describe('Cookie Extraction', () => {
    it('should extract cookie with default name when not specified', async () => {
      const optionsWithoutCookieName = {
        secrets: 'test-secret-key-at-least-32-chars-long',
      };

      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123' }) as any);

      await getMutableSessionFromCookies(mockCookieStore, optionsWithoutCookieName);

      expect(mockCookieStore.get).toHaveBeenCalledWith('session');
    });

    it('should extract cookie with custom name when specified', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      mockGetWristbandSession.mockResolvedValue(createMockSession({ userId: 'user-123' }) as any);

      await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      expect(mockCookieStore.get).toHaveBeenCalledWith('test-session');
    });
  });

  describe('Error Handling', () => {
    it('should propagate errors from getWristbandSession', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({
        value: 'encrypted-cookie-value',
      });

      const underlyingError = new Error('Session decryption failed');
      mockGetWristbandSession.mockRejectedValue(underlyingError);

      await expect(getMutableSessionFromCookies(mockCookieStore, sessionOptions)).rejects.toThrow(
        'Session decryption failed'
      );
    });
  });

  describe('Cookie Edge Cases', () => {
    it('should handle null cookie value', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue(null);
      mockGetWristbandSession.mockResolvedValue(createMockSession() as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      expect(session).toBeDefined();
      const request = mockGetWristbandSession.mock.calls[0][0] as Request;
      expect(request.headers.get('cookie')).toBe('');
    });

    it('should handle empty string cookie value', async () => {
      (mockCookieStore.get as jest.Mock).mockReturnValue({ value: '' });
      mockGetWristbandSession.mockResolvedValue(createMockSession() as any);

      const session = await getMutableSessionFromCookies(mockCookieStore, sessionOptions);

      expect(session).toBeDefined();
      const request = mockGetWristbandSession.mock.calls[0][0] as Request;
      expect(request.headers.get('cookie')).toBe(''); // Empty value = no cookie
    });
  });
});
