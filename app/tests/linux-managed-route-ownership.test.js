const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('Linux imported profile filename collision never authorizes deleting a foreign saved NM profile',
  { skip: process.platform !== 'linux' }, () => {
    const fs = require('node:fs');
    const source = fs.readFileSync(path.join(__dirname,'../backend/linux/oig-linux.sh'),'utf8');
    for (const [begin,end] of [['preflight_one() {','write_profile_state() {'],['connect_one() {','record_success() {']]) {
      const body=source.slice(source.indexOf(begin),source.indexOf(end));
      const collision=body.indexOf('grep -Fxq -- "$import_name"');
      const imported=body.indexOf('nmcli connection import type openvpn file "$profile"');
      assert.ok(collision > 0 && imported > collision, begin);
      assert.doesNotMatch(body,/delete_connection_name "\$import_name"/);
    }
    const switchStart=source.indexOf('connect-profile)');
    const switchEnd=source.indexOf('disconnect) disconnect_gateway',switchStart);
    const branch=source.slice(switchStart,switchEnd);
    assert.ok(branch.indexOf('preconnect_no_foreign_nm_vpn')>=0);
    assert.ok(branch.indexOf('preconnect_public_ipv6_absent')>=0);
    assert.ok(branch.indexOf('preconnect_public_ipv6_absent') < branch.indexOf('teardown_gateway'));
  });

test('Linux connects only after the read-only all-tables IPv6 guard, before cache/import/network mutation',
  { skip: process.platform !== 'linux' }, () => {
    const fs = require('node:fs');
    const source = fs.readFileSync(path.join(__dirname,'../backend/linux/oig-linux.sh'),'utf8');
    const start = source.indexOf('connect_gateway() {');
    const end = source.indexOf('record_success() {', start);
    const body = source.slice(start, end);
    const external = body.indexOf('if ! preconnect_no_foreign_nm_vpn; then');
    const guard = body.indexOf('if ! preconnect_public_ipv6_absent; then');
    const cache = body.indexOf('python3 "$FACTORY_PY" ensure --common "$OIG_COMMON"');
    const watchdog = body.indexOf('start_watchdog');
    const imported = body.indexOf('connect_one "$host"');
    assert.ok(start > 0 && external >= 0 && guard > external && cache > guard && watchdog > cache && imported > watchdog);
    assert.match(source,/from operator_full_device import public_ipv6_route_present/);
    assert.match(source,/sys\.exit\(1 if public_ipv6_route_present\(\) else 0\)/);
  });

test('Linux status attributes full routes only to the OIG-owned VPN source, not another tunnel',
  { skip: process.platform !== 'linux' }, () => {
    const r = spawnSync('python3', ['-B', path.join(__dirname, 'linux-managed-route-ownership-smoke.py')], {
      // 26 route/DNS cases + 5 recovery cases each launch isolated local
      // command shims; keep bounded headroom under parallel node:test.
      encoding: 'utf8', timeout: 45000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.match(r.stdout, /PASS: only managed VPN source/);
  });
