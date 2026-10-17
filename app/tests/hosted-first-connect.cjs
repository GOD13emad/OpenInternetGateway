'use strict';
// Native first Connect test for a fresh, disposable GitHub-hosted Windows runner only.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),Module=require('node:module');

for(const [k,v] of Object.entries({GITHUB_ACTIONS:'true',RUNNER_OS:'Windows',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_REPOSITORY:'GOD13emad/OpenInternetGateway'}))assert.equal(process.env[k],v,'WRONG_RUNNER_'+k);
assert.equal(process.platform,'win32','WINDOWS_ONLY');
const asar=require('@electron/asar');
const root=process.argv[2],receiptFile=process.argv[3];assert.ok(root&&receiptFile,'ARGUMENTS_REQUIRED');
const res=path.join(root,'resources'),archive=path.join(res,'app.asar');
const hits=asar.listPackage(archive).filter(s=>s.replaceAll('\\','/').replace(/^\/+/,'')==='src/main/platform-backend.js');
assert.equal(hits.length,1,'PACKAGED_BACKEND_AMBIGUOUS');
const m=new Module(path.join(os.tmpdir(),'oig-installed-backend.cjs'),module);
m.filename=path.join(os.tmpdir(),'oig-installed-backend.cjs');m.paths=Module._nodeModulePaths(os.tmpdir());
m._compile(asar.extractFile(archive,hits[0].replace(/^[\\/]+/,'')).toString('utf8'),m.filename);
const Backend=m.exports;
const report={schema:'oig-hosted-first-connect-v1',scope:'actual-packaged-backend-no-GUI',source:process.env.GITHUB_SHA,connectPass:false,rollbackPass:false,connectError:'',disconnectError:'',baseline:null,connected:null,after:null};
const b=new Backend({version:'2.5.19',resourcesPath:res,appPath:archive,userData:path.join(os.tmpdir(),'oig-test-userdata'),emit:()=>{}});
(async()=>{
  try{
    await b.initialize();report.baseline=await b.status();
    assert.equal(report.baseline.connected,false,'NOT_A_CLEAN_BASELINE');
    console.log('FIRST_CONNECT_START');
    await b.action('connect');await new Promise(r=>setTimeout(r,3000));
    report.connected=await b.status();const a=report.connected,z=report.baseline;
    report.checks={connected:a.connected===true,ipChanged:!!z.ip&&!!a.ip&&z.ip!==a.ip,foreign:!!a.country&&a.country!=='IR',routes:Number(a.fullRoutes)>=2,dnsClean:a.poison===false,relay:!!a.relay,autoRecovery:a.autoRecovery===true};
    report.connectPass=Object.values(report.checks).every(Boolean);
    console.log('FIRST_CONNECT_VALIDATION='+String(report.connectPass));
  }catch(e){
    report.connectError=String(e?.message||e);
    console.error('FIRST_CONNECT_ERROR='+report.connectError);
    const snap=(relative,fields)=>{
      try{
        const full=path.join(b.backendRoot,relative);
        if(!fs.existsSync(full))return {present:false};
        const src=JSON.parse(fs.readFileSync(full,'utf8'));
        const picked={present:true};
        for(const k of fields){if(Object.hasOwn(src,k))picked[k]=src[k]}
        return picked;
      }catch(err){return {present:true,parseError:String(err?.message||err)}}
    };
    report.diagnostics={
      bootstrap:snap('evidence/headless-bootstrap.json',['result','error','steps','service']),
      ensureError:snap('evidence/ensure-last-error.json',['error']),
      headless:snap('evidence/headless-control-last.json',['result','action']),
      shadow:snap('evidence/shadow-handover-last.json',['result','native','dataPlane']),
      desired:snap('state/desired-state.json',['desired'])
    };
    console.log('FIRST_CONNECT_DIAGNOSTICS='+JSON.stringify(report.diagnostics));
  }
  finally{
    try{
      if(b.backendRoot){await b.action('disconnect');await new Promise(r=>setTimeout(r,1600));report.after=await b.status();report.rollbackPass=report.after.connected===false&&Number(report.after.fullRoutes)===0;}
    }catch(e){report.disconnectError=String(e?.message||e)}
    report.pass=report.connectPass&&report.rollbackPass;
    fs.mkdirSync(path.dirname(receiptFile),{recursive:true});
    fs.writeFileSync(receiptFile,JSON.stringify(report,null,2)+'\n');
    console.log('FIRST_CONNECT_ROLLBACK='+String(report.rollbackPass));
    if(!report.pass)process.exitCode=1;
  }
})().catch(e=>{console.error(e);process.exitCode=2});
