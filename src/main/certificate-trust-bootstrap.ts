import { app, session, type Session } from 'electron';
import { chromiumTrustDecision, hardenNodeTrust } from './certificate-trust.js';

hardenNodeTrust();

const protectedSessions = new WeakSet<Session>();
function protectSession(created: Session): void {
  if (protectedSessions.has(created)) return;
  created.setCertificateVerifyProc((request, callback) => callback(chromiumTrustDecision(request)));
  protectedSessions.add(created);
}

app.on('session-created', protectSession);
void app.whenReady().then(() => protectSession(session.defaultSession));
