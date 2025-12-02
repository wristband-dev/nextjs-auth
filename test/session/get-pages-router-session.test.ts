import * as http from 'http';
import { Socket } from 'net';
import { SessionData, SessionOptions } from '@wristband/typescript-session';
import { getPagesRouterSession } from '../../src/session';

interface TestSessionData extends SessionData {
  email?: string;
  cartId?: string;
}

// Helper to create a proper mock IncomingMessage that the SDK will accept
function createMockRequest(headers: http.IncomingHttpHeaders = {}): http.IncomingMessage {
  const socket = new Socket();
  const req = new http.IncomingMessage(socket);
  req.headers = headers;
  req.method = 'GET';
  req.url = '/api/test';
  return req;
}

// Helper to create a proper mock ServerResponse
function createMockResponse(req: http.IncomingMessage): http.ServerResponse {
  return new http.ServerResponse(req);
}

describe('getPagesRouterSession', () => {
  const sessionOptions: SessionOptions = {
    secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
    cookieName: 'test-session',
    maxAge: 3600,
  };

  it('should create a new empty session when no cookies exist', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    expect(session).toBeDefined();
    expect(typeof session.get).toBe('function');
    expect(typeof session.set).toBe('function');
    expect(typeof session.delete).toBe('function');
    expect(typeof session.toJSON).toBe('function');
  });

  it('should allow setting and getting session data', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    session.set('userId', 'user-123');
    session.set('email', 'test@example.com');
    expect(session.get('userId')).toBe('user-123');
    expect(session.get('email')).toBe('test@example.com');
  });

  it('should support direct property access for session data', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    session.userId = 'user-456';
    session.tenantId = 'tenant-789';
    expect(session.userId).toBe('user-456');
    expect(session.tenantId).toBe('tenant-789');
  });

  it('should read cookies from request headers', async () => {
    const req = createMockRequest({
      cookie: 'test-session=some-encrypted-value; other-cookie=value',
    });
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    // Should successfully create session (even if cookie is invalid, it creates empty session)
    expect(session).toBeDefined();
  });

  it('should support Node.js save() method', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    session.userId = 'user-123';
    await session.save();
    // save() should not throw
    expect(session.userId).toBe('user-123');
  });

  it('should support Node.js destroy() method', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    session.userId = 'user-123';
    session.destroy();
    // destroy() should not throw
    expect(true).toBe(true);
  });

  it('should work with custom session data types', async () => {
    interface CustomSessionData extends SessionData {
      userId?: string;
      email?: string;
      tenantId?: string;
      cartId?: string;
    }
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<CustomSessionData>(req, res, sessionOptions);
    session.userId = 'user-123';
    session.email = 'test@example.com';
    session.cartId = 'cart-abc';
    expect(session.userId).toBe('user-123');
    expect(session.email).toBe('test@example.com');
    expect(session.cartId).toBe('cart-abc');
  });

  it('should accept all session configuration options', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const fullOptions: SessionOptions = {
      secrets: [
        'secret1-must-be-at-least-32-characters-long-for-security',
        'secret2-must-be-at-least-32-characters-long-for-security',
      ],
      cookieName: 'custom-session',
      maxAge: 7200,
      path: '/api',
      secure: true,
      sameSite: 'Strict',
      domain: '.example.com',
      enableCsrfProtection: true,
      csrfCookieName: 'CUSTOM-CSRF',
    };
    const session = await getPagesRouterSession<TestSessionData>(req, res, fullOptions);
    expect(session).toBeDefined();
    expect(typeof session.set).toBe('function');
  });

  it('should work with Wristband authentication data', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    session.isAuthenticated = true;
    session.userId = 'user-123';
    session.tenantId = 'tenant-456';
    session.accessToken = 'eyJhbGc...';
    session.expiresAt = Date.now() + 3600000;
    expect(session.isAuthenticated).toBe(true);
    expect(session.userId).toBe('user-123');
    expect(session.accessToken).toBe('eyJhbGc...');
  });

  it('should have Wristband-specific methods available', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    expect(typeof session.fromCallback).toBe('function');
    expect(typeof session.getSessionResponse).toBe('function');
    expect(typeof session.getTokenResponse).toBe('function');
  });

  it('should have Node.js specific methods available', async () => {
    const req = createMockRequest();
    const res = createMockResponse(req);
    const session = await getPagesRouterSession<TestSessionData>(req, res, sessionOptions);
    expect(typeof session.save).toBe('function');
    expect(typeof session.destroy).toBe('function');
    // Note: Edge methods also exist on the session object (saveToResponse, destroyToResponse)
    // but they're available for all contexts. The SDK handles which ones work based on context.
  });
});
