import { readFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';
import { describe, expect, it } from 'vitest';
import {
  certificateFingerprint, chromiumTrustDecision, COMPROMISED_ROOT_SHA256, excludeCompromisedRoot
} from '../src/main/certificate-trust.js';

type TestCertificateChain = { data: string; issuerCert?: TestCertificateChain };

const compromised = readFileSync(new URL('./fixtures/emsign-ecc-root-g3.crt', import.meta.url), 'utf8');
const other = rootCertificates.find((pem) => certificateFingerprint(pem) !== COMPROMISED_ROOT_SHA256)!;

describe('certificate trust restriction', () => {
  it('identifies the public compromised-root fixture by exact DER fingerprint', () => {
    expect(certificateFingerprint(compromised)).toBe(COMPROMISED_ROOT_SHA256);
  });
  it('removes only that root and preserves other roots and duplicates unchanged', () => {
    expect(excludeCompromisedRoot([other, compromised, other])).toEqual([other, other]);
    expect(excludeCompromisedRoot([other])).toEqual([other]);
  });
  it('refuses malformed PEM instead of silently accepting it', () => {
    expect(() => excludeCompromisedRoot(['not a certificate'])).toThrow();
  });
  it('rejects the root directly and at the end of a validated issuer chain', () => {
    const root = { data: compromised };
    expect(chromiumTrustDecision({ validatedCertificate: root })).toBe(-2);
    expect(chromiumTrustDecision({ validatedCertificate: { data: other, issuerCert: root } })).toBe(-2);
  });
  it('checks the original chain when Chromium has no validated chain', () => {
    expect(chromiumTrustDecision({ certificate: { data: compromised } })).toBe(-2);
  });
  it('defers other certificates to Chromium without accepting them itself', () => {
    expect(chromiumTrustDecision({ validatedCertificate: { data: other } })).toBe(-3);
    expect(chromiumTrustDecision({})).toBe(-3);
  });
  it('handles self-signed cycles without looping and rejects malformed certificates', () => {
    const root: TestCertificateChain = { data: other };
    root.issuerCert = root;
    expect(chromiumTrustDecision({ validatedCertificate: root })).toBe(-3);
    expect(chromiumTrustDecision({ validatedCertificate: { data: 'invalid' } })).toBe(-2);
  });
  it('bounds unexpectedly deep chains', () => {
    let root: TestCertificateChain = { data: other };
    for (let index = 0; index < 33; index++) root = { data: other, issuerCert: root };
    expect(chromiumTrustDecision({ validatedCertificate: root })).toBe(-2);
  });
  it('loads trust protection before every application import', () => {
    const main = readFileSync(new URL('../src/main/index.ts', import.meta.url), 'utf8');
    expect(main.startsWith("import './certificate-trust-bootstrap.js';")).toBe(true);
  });
});
