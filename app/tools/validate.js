const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const root = path.resolve(__dirname, '..');
const required = [
  'package.json','src/main/main.js','src/main/platform-backend.js','src/preload/preload.js',
  'src/renderer/index.html','src/renderer/styles.css','src/renderer/app.js',
  'backend/linux/oig-linux.sh','backend/linux/refresh_cache.py','assets/icon.png','assets/icon.ico'
];
let failures = [];
for (const f of required) if (!fs.existsSync(path.join(root,f))) failures.push('Missing '+f);
for (const f of ['src/main/main.js','src/main/platform-backend.js','src/preload/preload.js','src/renderer/app.js']) {
  const r=cp.spawnSync(process.execPath,['--check',path.join(root,f)],{encoding:'utf8'});
  if(r.status!==0) failures.push(f+': '+r.stderr.trim());
}
const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
if(pkg.build?.win?.target?.[0]?.target!=='nsis') failures.push('Windows NSIS target missing');
if(!Array.isArray(pkg.build?.linux?.target) || !pkg.build.linux.target.includes('deb') || !pkg.build.linux.target.includes('AppImage')) failures.push('Linux deb/AppImage targets missing');
if(failures.length){console.error(failures.join('\n'));process.exit(1)}
console.log('PASS: app structure, JS syntax, and package targets');
