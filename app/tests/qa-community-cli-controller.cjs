'use strict';

// QA-only prototype of an app-owned OpenVPN Community management lifecycle.
// Never import into the production connect/disconnect path. A disposable
// Windows GitHub runner is mandatory; localhost --dev null is enforced.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');

const WIN_EXE_SHA = '0b9b5ad60279b912ae826da5e13a57750fdc918d9ec28b73f031aaffef8dd485';
const MODES = new Set(['valid', 'bad-cn', 'bad-password']);

function assertDisposable() {
  const ci = process.platform === 'win32' &&
    process.env.GITHUB_ACTIONS === 'true' &&
    process.env.RUNNER_OS === 'Windows' &&
    process.env.RUNNER_ENVIRONMENT === 'github-hosted' &&
    process.env.GITHUB_REPOSITORY === 'GOD13emad/OpenInternetGateway';
  const localLinux = process.platform === 'linux' &&
    process.env.OIG_LOOPBACK_LOCAL_QA === '1';
  if (!ci && !localLinux) throw new Error('DISPOSABLE_QA_RUNNER_ONLY');
}

function localFile(root, file) {
  if (typeof file !== 'string' || !file || file.includes('\0')) throw new Error('INVALID_QA_PATH');
  const real = fs.realpathSync(file);
  const relative = path.relative(root, real);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('QA_FILE_OUTSIDE_SCRATCH');
  }
  if (!fs.lstatSync(file).isFile()) throw new Error('NONREGULAR_QA_FILE');
  return real;
}

function boundedInput(data) {
  assertDisposable();
  const root = fs.realpathSync(data.root);
  if (!path.basename(root).startsWith('oig-community-loopback-') ||
      !fs.lstatSync(root).isDirectory() || fs.lstatSync(root).isSymbolicLink()) {
    throw new Error('NONPRIVATE_QA_ROOT');
  }
  const expectedParent = fs.realpathSync(os.tmpdir());
  if (path.dirname(root) !== expectedParent) throw new Error('QA_SCRATCH_NOT_SYSTEM_TEMP');
  if (!MODES.has(data.mode)) throw new Error('INVALID_QA_MODE');
  if (!Number.isInteger(data.port) || data.port < 1 || data.port > 65535) {
    throw new Error('INVALID_LOCAL_PORT');
  }
  if (data.username !== 'oig_user' ||
      (data.password !== 'oig_pass' && data.password !== 'wrong-pass')) {
    throw new Error('NOT_SYNTHETIC_CREDENTIALS');
  }
  if ((data.mode === 'bad-password') !== (data.password === 'wrong-pass')) {
    throw new Error('TEST_MODE_CREDENTIAL_MISMATCH');
  }
  const binary = fs.realpathSync(data.exe);
  if (!fs.lstatSync(binary).isFile()) throw new Error('NO_OPENVPN_EXECUTABLE');
  if (process.platform === 'win32') {
    const digest = crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex');
    if (digest !== WIN_EXE_SHA) throw new Error('UNPINNED_WINDOWS_OPENVPN_EXECUTABLE');
  }
  return {
    root, binary, ca: localFile(root, data.ca),
    cert: localFile(root, data.cert), key: localFile(root, data.key),
    mode: data.mode, port: data.port, username: data.username,
    password: data.password
  };
}

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function getLog(file) {
  if (!fs.existsSync(file)) return '';
  if (fs.statSync(file).size > 128 * 1024) throw new Error('QA_LOG_BOUND_EXCEEDED');
  return fs.readFileSync(file, 'utf8');
}

function waitForProcessExit(child, milliseconds) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise(resolve => {
    const done = () => { clearTimeout(timer); child.off('exit', onExit); resolve(true); };
    const onExit = () => done();
    const timer = setTimeout(() => {
      child.off('exit', onExit);
      resolve(child.exitCode !== null || child.signalCode !== null);
    }, milliseconds);
    child.once('exit', onExit);
  });
}

async function executeSyntheticLifecycle(data) {
  const a = boundedInput(data);
  const server = net.createServer();
  let socket = null;
  let child = null;
  let managementConnected = false;
  let sawHold = false, prompted = false, rejectedViaManagement = false;
  let bytesSeen = 0;
  let disposed = false;
  const logFile = path.join(a.root, a.mode + '-controller-client.log');
  const events = [];
  // Track only discrete, public protocol states. Never expose management
  // traffic, credentials, certificate contents or user-controlled logs.
  const append = value => { if (events.length < 24) events.push(value); };
  let pending = '';
  const onLine = line => {
    if (line.startsWith('>HOLD:') && !sawHold) {
      sawHold = true;
      append('HOLD_READY');
      socket.write('hold release\n');
      append('HOLD_RELEASE_SENT');
    }
    if (line.includes("Need 'Auth' username/password") && !prompted) {
      prompted = true;
      append('PASSWORD_CHALLENGE_OBSERVED');
      socket.write('username "Auth" ' + a.username + '\n');
      socket.write('password "Auth" ' + a.password + '\n');
      // JS temporary strings cannot be reliably zeroized. Credentials are
      // synthetic and never copied to a file, argv, log or receipt.
      a.password = null;
      append('PASSWORD_ANSWERED_IN_MEMORY');
    }
    if (line.includes('Verification Failed')) {
      rejectedViaManagement = true;
      append('AUTH_REJECTED_MANAGEMENT');
    }
  };
  server.on('connection', accepted => {
    if (socket) { accepted.destroy(); return; }
    if (accepted.remoteAddress !== '127.0.0.1' &&
        accepted.remoteAddress !== '::ffff:127.0.0.1') {
      accepted.destroy(); return;
    }
    managementConnected = true;
    socket = accepted;
    socket.setEncoding('utf8');
    socket.on('data', chunk => {
      bytesSeen += Buffer.byteLength(chunk);
      if (bytesSeen > 192 * 1024) { socket.destroy(); return; }
      pending += chunk;
      while (pending.includes('\n')) {
        const index = pending.indexOf('\n');
        const line = pending.slice(0, index).replace(/\r$/, '');
        pending = pending.slice(index + 1);
        onLine(line);
      }
      if (pending.length > 16384) socket.destroy();
    });
    socket.on('error', () => {});
    append('MANAGEMENT_CONNECTED');
  });
  server.on('error', () => {});
  let final = null;
  let processStopped = false;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    const managementPort = server.address().port;
    const expectedCN = a.mode === 'bad-cn' ? 'wrong-oig-local-server' : 'oig-local-server';
    const argv = [
      '--dev', 'null', '--ifconfig-noexec', '--route-noexec',
      '--ca', a.ca, '--cert', a.cert, '--key', a.key,
      '--proto', 'tcp-client', '--nobind',
      '--remote', '127.0.0.1', String(a.port), '--tls-client',
      '--remote-cert-tls', 'server', '--verify-x509-name', expectedCN, 'name',
      '--data-ciphers', 'AES-256-GCM', '--auth-user-pass', '--pull',
      '--auth-retry', 'none', '--auth-nocache',
      '--management', '127.0.0.1', String(managementPort),
      '--management-client', '--management-hold',
      '--management-query-passwords', '--management-forget-disconnect',
      '--connect-retry-max', '1', '--tls-exit',
      '--verb', '3', '--log', logFile
    ];
    child = spawn(a.binary, argv, {
      windowsHide: true, shell: false,
      stdio: ['ignore', 'ignore', 'ignore'],
      cwd: a.root, env: {...process.env}
    });
    child.on('error', () => { append('OWNED_PROCESS_START_ERROR'); });
    append('OWNED_CLIENT_STARTED');
    const until = Date.now() + 16500;
    while (Date.now() < until) {
      const log = getLog(logFile);
      const initialized = log.includes('Initialization Sequence Completed');
      const identityRejected = log.includes('VERIFY X509NAME ERROR');
      const authRejected = rejectedViaManagement ||
        log.includes('AUTH_FAILED') || log.includes('AUTH: Received control message: AUTH_FAILED');
      if (a.mode === 'valid' && initialized && prompted) {
        final = { tlsAccepted: true, identityRejected: false, authRejected: false };
        break;
      }
      if (a.mode === 'bad-cn' && identityRejected && !initialized) {
        final = { tlsAccepted: false, identityRejected: true, authRejected: false };
        break;
      }
      if (a.mode === 'bad-password' && authRejected && !initialized && prompted) {
        final = { tlsAccepted: false, identityRejected: false, authRejected: true };
        break;
      }
      if (child.exitCode !== null || child.signalCode !== null) break;
      await pause(100);
    }
    if (!final) {
      const log = getLog(logFile);
      const markers = ['Initialization Sequence Completed', 'VERIFY X509NAME ERROR', 'AUTH_FAILED',
        'Options error', 'Connection reset', 'SIGTERM', 'TLS Error', 'AUTH: Received']
        .filter(marker => log.includes(marker));
      throw new Error('SYNTHETIC_LIFECYCLE_NOT_ACCEPTED_'+a.mode+
        '_observed='+markers.join(',')+'_management='+managementConnected+
        '_hold='+sawHold+'_challenge='+prompted);
    }
  } finally {
    // The only process signalled is the child PID we spawned. No service,
    // task, route, NetworkManager or unrelated OpenVPN instance is touched.
    try { if (socket && !socket.destroyed) socket.write('signal SIGTERM\n'); } catch {}
    if (child) {
      processStopped = await waitForProcessExit(child, 1800);
      if (!processStopped) {
        try { child.kill('SIGTERM'); } catch {}
        processStopped = await waitForProcessExit(child, 1800);
      }
      if (!processStopped) {
        try { child.kill('SIGKILL'); } catch {}
        processStopped = await waitForProcessExit(child, 1000);
      }
    }
    if (socket) socket.destroy();
    await new Promise(resolve => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
    });
    disposed = true;
  }
  if (!processStopped || !disposed) throw new Error('OWNED_CLIENT_NOT_CLEANLY_STOPPED');
  if (!managementConnected || !sawHold || !prompted) {
    throw new Error('MANAGEMENT_LIFECYCLE_INCOMPLETE');
  }
  return {
    schema: 'oig-community-controller-qa-v1', mode: a.mode,
    managementConnected, managementHoldObserved: sawHold,
    managementPromptObserved: prompted, ownedProcessStopped: processStopped,
    closedManagementListener: !server.listening,
    tlsAccepted: final.tlsAccepted,
    identityRejected: final.identityRejected,
    authRejected: final.authRejected,
    localOnly: true, devNull: true, routesNotExecuted: true,
    independentPublicServerVerified: false, productionEngineChanged: false,
    lifecycleEvents: events
  };
}

async function main() {
  assertDisposable();
  let raw = '';
  for await (const fragment of process.stdin) {
    raw += fragment.toString('utf8');
    if (Buffer.byteLength(raw) > 16 * 1024) throw new Error('QA_INPUT_TOO_LARGE');
  }
  const data = JSON.parse(raw);
  const result = await executeSyntheticLifecycle(data);
  process.stdout.write(JSON.stringify(result) + '\n');
}

if (require.main === module) {
  main().catch(error => {
    // Never log credentials or arbitrary process output.
    const message = String(error && error.message || 'QA_CONTROLLER_ERROR');
    process.stderr.write('FAIL_QA_CONTROLLER: ' + message.replace(/[\r\n]/g, ' ').slice(0, 350) + '\n');
    process.exitCode = 1;
  });
}

module.exports = { assertDisposable, boundedInput, executeSyntheticLifecycle };
