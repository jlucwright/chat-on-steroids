import { X509Certificate } from 'node:crypto';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

// Remove only the compromised root, preserving system/enterprise/extra CA trust.
export const COMPROMISED_ROOT_SHA256 = '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b';

export function certificateFingerprint(pem: string): string {
  return new X509Certificate(pem).fingerprint256.replaceAll(':', '').toLowerCase();
}

export function excludeCompromisedRoot(certificates: readonly string[]): string[] {
  return certificates.filter((certificate) => certificateFingerprint(certificate) !== COMPROMISED_ROOT_SHA256);
}

// Must run before application modules can create/cache an HTTPS connection.
// Worker threads here run bounded computation/native desktop calls, not TLS.
export function hardenNodeTrust(): { removed: number } {
  const current = getCACertificates('default');
  const retained = excludeCompromisedRoot(current);
  if (!retained.length) throw new Error('Refusing an empty TLS trust store');
  if (retained.length !== current.length) setDefaultCACertificates(retained);
  return { removed: current.length - retained.length };
}

interface CertificateChain {
  data: string;
  issuerCert?: CertificateChain;
}

// -3 keeps Chromium's normal hostname, expiry, revocation and CT verification.
// This guard never returns 0 (which would override normal verification).
export function chromiumTrustDecision(request: {
  validatedCertificate?: CertificateChain | null;
  certificate?: CertificateChain | null;
}): -2 | -3 {
  let certificate = request.validatedCertificate ?? request.certificate;
  const visited = new Set<CertificateChain>();
  try {
    while (certificate && !visited.has(certificate)) {
      if (visited.size >= 32) return -2;
      visited.add(certificate);
      if (certificateFingerprint(certificate.data) === COMPROMISED_ROOT_SHA256) return -2;
      certificate = certificate.issuerCert;
    }
  } catch {
    return -2;
  }
  return -3;
}
