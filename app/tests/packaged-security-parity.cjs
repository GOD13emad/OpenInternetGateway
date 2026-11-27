'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const asar = require('@electron/asar');

const paths = process.argv.slice(2);
assert.equal(paths.length, 2, 'Exactly one DEB ASAR and one AppImage ASAR are required');
const source = path.resolve(__dirname, '..');
const expected = [
  'src/main/main.js',
  'src/main/dashboard-security.js',
  'src/preload/preload.js',
  'src/renderer/index.html',
  'src/renderer/app.js'
];
const digests = {};
for (const name of expected) {
  const actualSource = fs.readFileSync(path.join(source, name));
  const digest = crypto.createHash('sha256').update(actualSource).digest('hex');
  for (const archive of paths) {
    assert.equal(path.basename(archive), 'app.asar', 'Unexpected archive file');
    assert.ok(fs.statSync(archive).isFile(), 'ASAR is missing');
    const packaged = asar.extractFile(archive, name);
    assert.ok(actualSource.equals(packaged),
      `Packaged ${name} differs from exact source: ${archive}`);
  }
  digests[name] = digest;
}
console.log('PACKAGED_SECURITY_BOUNDARY_PARITY_PASS ' + JSON.stringify({
  formats: ['deb', 'AppImage'],
  files: expected.length,
  digests
}));
