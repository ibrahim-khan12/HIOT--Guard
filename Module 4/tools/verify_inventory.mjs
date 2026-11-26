import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFileSync,spawn} from 'node:child_process';
const require=createRequire(import.meta.url);
const {chromium}=require(path.join(process.env.RUNTIME_NODE_MODULES,'playwright'));
const output=path.resolve(process.argv[2]);
await fs.mkdir(output,{recursive:true});
const python=process.env.PILOT_PYTHON||'python';
const baseline='runs/module4-stage2-evaluation-20261124/A';
const live=process.argv.includes('--live');
const evaluation=process.argv.includes('--ml-evaluation');
let state=baseline, assessment=['--classification',path.join(baseline,'classification.json')];
if(live){
 state=path.join(output,'inventory-state');
 await fs.mkdir(state,{recursive:false});
 const backup='import sqlite3,sys; from pathlib import Path; a=sqlite3.connect(Path(sys.argv[1]).resolve().as_uri()+"?mode=ro",uri=True); b=sqlite3.connect(sys.argv[2]); a.backup(b); b.close(); a.close()';
 execFileSync(python,['-c',backup,path.join(baseline,'inventory.sqlite3'),path.join(state,'inventory.sqlite3')],{windowsHide:true});
 assessment=['--scope','module4-stage2-pilot-A','--live-assessment-root',path.join(baseline,'module2'),
             '--assessment-tshark','C:\\Program Files\\Wireshark\\tshark.exe','--interval','0.2'];
}
if(evaluation)assessment.push('--module4-evaluation','Module 4/docs/final-evaluation-scorecard.json');
const server=spawn(python,['-m','module3','--state',state,'serve','--offline','--port','8894',...assessment],
 {windowsHide:true,env:{...process.env,PYTHONPATH:'Module 3'},stdio:['ignore','pipe','pipe']});
let serverOutput='';server.stdout.on('data',b=>serverOutput+=b);server.stderr.on('data',b=>serverOutput+=b);
for(let attempt=0;attempt<40;attempt++){
 try{const r=await fetch('http://127.0.0.1:8894/api/ready');if(r.ok)break;}catch{}
 if(server.exitCode!==null)throw Error('Demo server failed: '+serverOutput);
 await new Promise(resolve=>setTimeout(resolve,250));
}
const browser=await chromium.launch({headless:true,channel:'chrome'});
const report={checks:[],errors:[]};
function check(name,passed){report.checks.push({name,passed});if(!passed)throw Error(name);}
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>report.errors.push(e.message));
 await page.goto('http://127.0.0.1:8894/');
 await page.waitForFunction(()=>document.querySelectorAll('#assetRows tr').length>0);
 const assets=await (await page.request.get('http://127.0.0.1:8894/api/assets')).json();
 check('Seven labelled IPv4 pilot endpoints',assets.records.filter(a=>a.ip.startsWith('10.88.0.')).length===7);
 const ct=assets.records.find(a=>a.ip==='10.88.0.15');
 if(live){
  await page.waitForFunction(async id=>{
   const detail=await (await fetch('/api/assets/'+id)).json();
   return detail.classification?.state==='current';
  },ct.asset_id);
 }
 const details=await (await page.request.get('http://127.0.0.1:8894/api/assets/'+ct.asset_id)).json();
 check('Forwarding workstation remains unknown',details.classification?.category==='unknown');
 check('Workflow retained with current provenance',details.classification?.state==='current'&&details.classification.workflows.includes('ct_storage'));
 check('Registry context remains separate',JSON.stringify(details.configured)===JSON.stringify(ct.configured));
 await page.getByRole('button',{name:'Open 10.88.0.15',exact:true}).click();
 await page.getByRole('heading',{name:'Module 4 assessment',exact:true}).waitFor();
 check('Workflow visible in endpoint view',(await page.locator('#unknown').textContent()).includes('CT image storage'));
 if(evaluation){
  const summary=page.locator('#module4Evaluation');
  await summary.waitFor({state:'visible'});
  const rows=await summary.locator('tbody tr').allTextContents();
  check('Saved ML results display both held-out cohorts',rows.length===2&&rows[0].includes('Familiar Python')&&rows[1].includes('HAPI/DCMTK transfer'));
  check('Rules and fallback match the scorecard',rows.every(row=>row.match(/0\.700/g)?.length===2));
  check('The model and zero fallback gain are shown',(await summary.textContent()).includes('histogram gradient boosting')&&(await summary.textContent()).includes('0 correct and 0 incorrect'));
  check('The assessment keeps its rules method',(await page.locator('#module4Assessment').textContent()).includes('Conservative workflow rules'));
 }
 await page.getByText('Supporting packet references',{exact:true}).click();
 check('Packet references visible',(await page.locator('#unknown').textContent()).includes('capture_sha256'));
 await page.screenshot({path:path.join(output,'inventory-workflow.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});
 if(evaluation)check('ML results fit the mobile table',await page.locator('#module4Evaluation .table-scroll').evaluate(el=>el.scrollWidth<=el.clientWidth));
 await page.screenshot({path:path.join(output,'inventory-mobile.png'),fullPage:true});
 check('No browser runtime errors',report.errors.length===0);
}finally{await browser.close();server.kill();await fs.writeFile(path.join(output,'browser-checks.json'),JSON.stringify(report,null,2));}
console.log(JSON.stringify(report));
