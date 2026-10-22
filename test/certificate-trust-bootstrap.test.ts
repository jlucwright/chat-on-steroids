import { beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => {
  const handlers: Record<string, (created: unknown) => void> = {};
  return {
    handlers,
    hardenNodeTrust: vi.fn(),
    chromiumTrustDecision: vi.fn(() => -3),
    defaultSession: { setCertificateVerifyProc: vi.fn() },
    on: vi.fn((event: string, handler: (created: unknown) => void) => { handlers[event] = handler; }),
    whenReady: vi.fn(() => Promise.resolve())
  };
});
vi.mock('electron', () => ({
  app: { on: fixture.on, whenReady: fixture.whenReady },
  session: { defaultSession: fixture.defaultSession }
}));
vi.mock('../src/main/certificate-trust.js', () => ({
  hardenNodeTrust: fixture.hardenNodeTrust,
  chromiumTrustDecision: fixture.chromiumTrustDecision
}));

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  await import('../src/main/certificate-trust-bootstrap.js');
  await Promise.resolve();
});

describe('early certificate trust bootstrap', () => {
  it('restricts Node trust before registering application readiness work', () => {
    expect(fixture.hardenNodeTrust).toHaveBeenCalledOnce();
    expect(fixture.hardenNodeTrust.mock.invocationCallOrder[0]).toBeLessThan(fixture.whenReady.mock.invocationCallOrder[0]!);
  });
  it('protects the default session after readiness', async () => {
    await Promise.resolve();
    expect(fixture.defaultSession.setCertificateVerifyProc).toHaveBeenCalledOnce();
  });
  it('protects each new partition once and forwards the restrictive decision', () => {
    const partition = { setCertificateVerifyProc: vi.fn() };
    const handler = fixture.handlers['session-created']!;
    handler(partition);
    handler(partition);
    expect(partition.setCertificateVerifyProc).toHaveBeenCalledOnce();
    const verify = partition.setCertificateVerifyProc.mock.calls[0]![0];
    const callback = vi.fn();
    verify({}, callback);
    expect(callback).toHaveBeenCalledExactlyOnceWith(-3);
  });
});
