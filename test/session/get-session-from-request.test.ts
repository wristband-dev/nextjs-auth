import { NextRequest } from 'next/server';
import { SessionData, SessionOptions } from '@wristband/typescript-session';
import { getSessionFromRequest } from '../../src/session';

interface TestSessionData extends SessionData {
  email?: string;
}

describe('getSession', () => {
  const sessionOptions: SessionOptions = {
    secrets: 'test-secret-must-be-at-least-32-characters-long-for-security',
    cookieName: 'test-session',
    maxAge: 3600,
  };

  it('should create a new empty session when no cookies exist', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    expect(session).toBeDefined();
    expect(typeof session.get).toBe('function');
    expect(typeof session.set).toBe('function');
    expect(typeof session.delete).toBe('function');
    expect(typeof session.toJSON).toBe('function');
  });

  it('should allow setting and getting session data', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    session.set('userId', 'user-123');
    session.set('email', 'test@example.com');
    expect(session.get('userId')).toBe('user-123');
    expect(session.get('email')).toBe('test@example.com');
  });

  it('should support direct property access for session data', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    session.userId = 'user-456';
    session.tenantId = 'tenant-789';
    expect(session.userId).toBe('user-456');
    expect(session.tenantId).toBe('tenant-789');
  });

  it('should work with custom session data types', async () => {
    interface CustomSessionData extends SessionData {
      userId?: string;
      email?: string;
      tenantId?: string;
      cartId?: string;
    }
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<CustomSessionData>(nextRequest, sessionOptions);
    session.userId = 'user-123';
    session.email = 'test@example.com';
    session.cartId = 'cart-abc';
    expect(session.userId).toBe('user-123');
    expect(session.email).toBe('test@example.com');
    expect(session.cartId).toBe('cart-abc');
  });

  it('should support delete operation', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    session.userId = 'user-123';
    session.delete('userId');
    expect(session.userId).toBeUndefined();
  });

  it('should return session data as JSON', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    session.userId = 'user-123';
    session.email = 'test@example.com';
    const json = session.toJSON();
    expect(json).toEqual({ userId: 'user-123', email: 'test@example.com' });
  });

  it('should accept session options with all available configuration', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const fullOptions: SessionOptions = {
      secrets: ['secret1-must-be-32-chars-long-123', 'secret2-must-be-32-chars-long-123'],
      cookieName: 'custom-session',
      maxAge: 7200,
      path: '/api',
      secure: true,
      sameSite: 'Strict',
      domain: '.example.com',
      enableCsrfProtection: true,
      csrfCookieName: 'CUSTOM-CSRF',
    };
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, fullOptions);
    expect(session).toBeDefined();
    expect(typeof session.set).toBe('function');
  });

  it('should work with Wristband authentication data', async () => {
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
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
    const nextRequest = new NextRequest('https://example.com/test');
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    expect(typeof session.fromCallback).toBe('function');
    expect(typeof session.getSessionResponse).toBe('function');
    expect(typeof session.getTokenResponse).toBe('function');
  });

  it('should build cookie header when cookies exist', async () => {
    const nextRequest = new NextRequest('https://example.com/test', {
      headers: { cookie: 'foo=bar; baz=qux' },
    });
    const session = await getSessionFromRequest<TestSessionData>(nextRequest, sessionOptions);
    expect(session).toBeDefined();
    // optionally verify cookie processing indirectly
  });
});
