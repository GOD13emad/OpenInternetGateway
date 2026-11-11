const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const afterAllArtifactBuild = require('../tools/afterAllArtifactBuild');

test('Linux DEB hook repairs desktop/icon modes with a compatible fast compressor', {
  skip: process.platform !== 'linux'
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-deb-hook-fixture-'));
  const run = (args) => spawnSync('dpkg-deb', args, {
    encoding: 'utf8', timeout: 10000
  });
  try {
    const root = path.join(dir, 'package');
    const control = path.join(root, 'DEBIAN');
    const desktop = path.join(root, 'usr/share/applications/OpenInternetGateway.desktop');
    const icon = path.join(root, 'usr/share/icons/hicolor/512x512/apps/open-internet-gateway.png');
    for (const folder of [control, path.dirname(desktop), path.dirname(icon)]) {
      fs.mkdirSync(folder, {recursive: true, mode: 0o755});
    }
    fs.chmodSync(root, 0o755);
    fs.chmodSync(control, 0o755);
    fs.writeFileSync(path.join(control, 'control'), [
      'Package: open-internet-gateway',
      'Version: 2.5.20',
      'Architecture: amd64',
      'Maintainer: OIG QA <oig-qa@example.invalid>',
      'Description: Local build-only package permission fixture',
      ''
    ].join('\n'));
    fs.writeFileSync(desktop, '[Desktop Entry]\nType=Application\nName=OIG-QA\n', {mode: 0o600});
    fs.writeFileSync(icon, 'synthetic-qa-fixture', {mode: 0o600});
    const oldTarget = '/opt/Open Internet Gateway/open-internet-gateway';
    const newTarget = '/opt/open-internet-gateway/open-internet-gateway';
    const postrm = path.join(control, 'postrm');
    fs.writeFileSync(postrm, [
      '#!/bin/bash',
      "update-alternatives --remove 'open-internet-gateway' '" + oldTarget + "'",
      "APPARMOR_PROFILE_DEST='/etc/apparmor.d/open-internet-gateway'",
      ''
    ].join('\n'), {mode: 0o755});
    fs.chmodSync(postrm, 0o755);
    fs.chmodSync(desktop, 0o600);
    fs.chmodSync(icon, 0o600);
    const deb = path.join(dir, 'OpenInternetGateway-2.5.20-amd64.deb');
    const built = run(['--root-owner-group', '-Zgzip', '-z1', '--build', root, deb]);
    assert.equal(built.status, 0, built.stderr);
    const before = run(['--contents', deb]);
    assert.equal(before.status, 0, before.stderr);
    assert.match(before.stdout, /-rw-------[^\n]*OpenInternetGateway\.desktop/);
    const oneClick = await afterAllArtifactBuild({artifactPaths: [deb]});
    assert.equal(oneClick.length, 1, 'Exactly one Linux one-file setup per Debian package');
    const setup = oneClick[0];
    assert.ok(setup.endsWith('-amd64.run'), 'Installer must be a Linux AMD64 .run');
    assert.equal(fs.statSync(setup).mode & 0o111, 0o111, 'Installer must be executable');
    const verify = spawnSync('bash', [setup, '--verify-only'], {encoding: 'utf8', timeout: 12000});
    assert.equal(verify.status, 0, verify.stderr);
    assert.match(verify.stdout, /OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED/);
    const help = spawnSync('bash', [setup, '--help'], {encoding: 'utf8', timeout: 5000});
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /--verify-only/);
    const unsupported = spawnSync('bash', [setup, '--install-now-without-auth'], {encoding: 'utf8', timeout: 5000});
    assert.equal(unsupported.status, 64, 'Unknown arguments must never install');
    // Modifying the private QA payload must fail verification before any OS
    // authorization prompt; no system package commands are invoked.
    const altered = path.join(dir, 'altered.run');
    fs.copyFileSync(setup, altered);
    const fd = fs.openSync(altered, 'r+');
    const last = fs.statSync(altered).size - 1;
    const original = Buffer.alloc(1);
    fs.readSync(fd, original, 0, 1, last);
    const corrupt = Buffer.from([original[0] ^ 0xff]);
    fs.writeSync(fd, corrupt, 0, 1, last);
    fs.closeSync(fd);
    const refused = spawnSync('bash', [altered, '--verify-only'], {encoding: 'utf8', timeout: 12000});
    assert.notEqual(refused.status, 0, 'Tampered installer must refuse');
    assert.match(refused.stderr, /SHA-256 mismatch/);
    const after = run(['--contents', deb]);
    assert.equal(after.status, 0, after.stderr);
    assert.match(after.stdout, /-rw-r--r--[^\n]*OpenInternetGateway\.desktop/);
    assert.match(after.stdout, /-rw-r--r--[^\n]*open-internet-gateway\.png/);
    const controlExtract = path.join(dir, 'control-after');
    const extracted = run(['--control', deb, controlExtract]);
    assert.equal(extracted.status, 0, extracted.stderr);
    const installedPostrm = fs.readFileSync(path.join(controlExtract, 'postrm'), 'utf8');
    assert.ok(!installedPostrm.includes(oldTarget), 'Stale postrm path must be removed');
    assert.ok(installedPostrm.includes(newTarget), 'Uninstall must target the actual package directory');
    assert.match(installedPostrm, /APPARMOR_PROFILE_DEST/, 'AppArmor cleanup must survive');
    assert.ok(fs.statSync(path.join(controlExtract, 'postrm')).mode & 0o111,
      'postrm must stay executable');
    const meta = run(['--field', deb, 'Package', 'Version', 'Architecture']);
    assert.equal(meta.status, 0, meta.stderr);
    assert.match(meta.stdout, /Version: 2\.5\.20/);
    assert.match(meta.stdout, /Architecture: amd64/);
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});
