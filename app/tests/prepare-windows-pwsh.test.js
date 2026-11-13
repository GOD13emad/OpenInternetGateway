const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  downloadWithRetry,
  isTransientDownloadError
} = require('../tools/prepareWindowsPwsh');

function temporaryArchive(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-pwsh-retry-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, archive: path.join(root, 'PowerShell.zip') };
}

test('PowerShell downloader retries HTTP 504 with isolated partial files and exponential backoff', async t => {
  const { root, archive } = temporaryArchive(t);
  let attempts = 0;
  const waits = [];
  await downloadWithRetry('https://example.invalid/PowerShell.zip', archive, {
    attempts: 4,
    baseDelayMs: 25,
    wait: async ms => waits.push(ms),
    logger: { warn() {} },
    downloader: async (_url, attemptFile) => {
      attempts += 1;
      fs.writeFileSync(attemptFile, attempts === 1 ? 'partial-response' : 'verified-archive');
      if (attempts === 1) {
        const error = new Error('HTTP 504');
        error.statusCode = 504;
        throw error;
      }
    }
  });
  assert.equal(attempts, 2);
  assert.deepEqual(waits, [25]);
  assert.equal(fs.readFileSync(archive, 'utf8'), 'verified-archive');
  assert.deepEqual(fs.readdirSync(root), ['PowerShell.zip']);
});

test('PowerShell downloader retries transient network resets but does not retry permanent HTTP errors', async t => {
  const { archive } = temporaryArchive(t);
  let attempts = 0;
  const waits = [];
  await downloadWithRetry('https://example.invalid/PowerShell.zip', archive, {
    attempts: 3,
    baseDelayMs: 10,
    wait: async ms => waits.push(ms),
    logger: { warn() {} },
    downloader: async (_url, attemptFile) => {
      attempts += 1;
      if (attempts < 3) {
        const error = new Error('connection reset');
        error.code = 'ECONNRESET';
        throw error;
      }
      fs.writeFileSync(attemptFile, 'complete');
    }
  });
  assert.equal(attempts, 3);
  assert.deepEqual(waits, [10, 20]);
  assert.equal(fs.readFileSync(archive, 'utf8'), 'complete');

  attempts = 0;
  await assert.rejects(downloadWithRetry('https://example.invalid/PowerShell.zip', archive, {
    attempts: 4,
    wait: async () => assert.fail('permanent HTTP errors must not be retried'),
    logger: { warn() {} },
    downloader: async (_url, attemptFile) => {
      attempts += 1;
      fs.writeFileSync(attemptFile, 'bad-response');
      const error = new Error('HTTP 404');
      error.statusCode = 404;
      throw error;
    }
  }), /HTTP 404/);
  assert.equal(attempts, 1);
  assert.equal(fs.existsSync(archive), false);
});

test('PowerShell retry classification is limited to transient HTTP and network failures', () => {
  for (const statusCode of [408, 425, 429, 500, 502, 503, 504]) {
    assert.equal(isTransientDownloadError({ statusCode }), true);
  }
  for (const code of ['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH']) {
    assert.equal(isTransientDownloadError({ code }), true);
  }
  assert.equal(isTransientDownloadError({ statusCode: 404 }), false);
  assert.equal(isTransientDownloadError({ code: 'CERT_HAS_EXPIRED' }), false);
});
