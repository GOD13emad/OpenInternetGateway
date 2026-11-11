'use strict';

// Shared, pure protocol boundary for app-owned OpenVPN Community management.
// This module NEVER starts OpenVPN, configures routes, opens sockets or stores
// credentials. A separate, explicitly authorized lifecycle owns those effects.
const MAX_LOGIN_BYTES = 96;
const MAX_SECRET_BYTES = 256;

function checkedAtom(value, max) {
  if (typeof value !== 'string' || value.length === 0 ||
      Buffer.byteLength(value, 'utf8') > max ||
      !/^[A-Za-z0-9._@!#$%&*+/:=\-]+$/.test(value)) {
    throw new Error('UNSAFE_OPENVPN_MANAGEMENT_CREDENTIAL');
  }
  return value;
}

function formatAuthResponse(username, password) {
  const user = checkedAtom(username, MAX_LOGIN_BYTES);
  const secret = checkedAtom(password, MAX_SECRET_BYTES);
  // Both lines must be sent in one write to avoid interleaved parser state.
  // Never log or return this frame outside the management transport.
  return 'username "Auth" ' + user + '\n' +
         'password "Auth" ' + secret + '\n';
}

function createAuthSession({username, password, send, stop, onEvent = () => {}}) {
  if (typeof send !== 'function' || typeof stop !== 'function' ||
      typeof onEvent !== 'function') {
    throw new Error('INVALID_OPENVPN_MANAGEMENT_CHANNEL');
  }
  checkedAtom(username, MAX_LOGIN_BYTES);
  checkedAtom(password, MAX_SECRET_BYTES);
  let credentials = {username, password};
  let holdObserved = false;
  let prompted = false;
  let rejected = false;
  let challenges = 0;
  const emit = label => onEvent(label); // fixed protocol labels, never raw lines

  function onLine(line) {
    // During teardown a late management event must never resurrect a
    // credential exchange or throw from an asynchronous socket callback.
    if (!credentials) return;
    if (typeof line !== 'string' || line.length > 16384) {
      stop();
      emit('INVALID_MANAGEMENT_EVENT');
      return;
    }
    if (line.startsWith('>HOLD:') && !holdObserved) {
      holdObserved = true;
      emit('HOLD_READY');
      send('hold release\n');
      emit('HOLD_RELEASE_SENT');
    }
    if (line.startsWith('>PASSWORD:') &&
        line.includes("Need 'Auth' username/password")) {
      challenges++;
      if (challenges > 3) {
        stop();
        emit('MANAGEMENT_AUTH_CHALLENGE_LIMIT');
        return;
      }
      if (!prompted) {
        prompted = true;
        emit('PASSWORD_CHALLENGE_OBSERVED');
      }
      send(formatAuthResponse(credentials.username, credentials.password));
      emit('PASSWORD_ANSWERED_IN_MEMORY');
    }
    if (line.includes('Verification Failed')) {
      rejected = true;
      emit('AUTH_REJECTED_MANAGEMENT');
    }
  }

  const snapshot = () => Object.freeze({
    holdObserved, prompted, rejected, challenges,
    credentialsCleared: credentials === null
  });
  function clear() {
    credentials = null;
  }
  return {onLine, snapshot, clear};
}

module.exports = {formatAuthResponse, createAuthSession};
