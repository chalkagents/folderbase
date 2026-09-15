#!/usr/bin/env node
import assert from "node:assert/strict";
import {randomUUID, createHash} from "node:crypto";
import {mkdtemp, mkdir, writeFile, readFile, rm, readdir, lstat} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, resolve, basename, extname} from "node:path";
import {spawnSync} from "node:child_process";

const argv = process.argv.slice(2);
if (argv.length !== 2 || argv[0] !== "--implementation") throw Error("usage: run.mjs --implementation /path/to/folderbase");
const implementation = resolve(argv[1]);
const timeout = Number(process.env.FOLDERBASE_CAPABILITY_COMMAND_TIMEOUT_MS ?? 120000);
if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 2147483647) throw Error("invalid command timeout");
const command = [".mjs", ".js", ".cjs"].includes(extname(implementation)) ? process.execPath : implementation;
const prefix = command === process.execPath ? [implementation] : [];
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
function execute(args, input) {
  const result = spawnSync(command, [...prefix, ...args], {input, encoding:"utf8", timeout, killSignal:"SIGKILL", maxBuffer:8*1024*1024});
  if (result.error) throw result.error;
  assert.equal(result.signal, null, `unexpected signal: ${result.signal}`);
  return result;
}
function ok(args, input) { const r=execute(args,input); assert.equal(r.status,0,r.stderr); assert.equal(r.stderr,""); return JSON.parse(r.stdout); }
function refusal(args, input, code) {const r=execute(args,input); assert.equal(r.status,2,r.stdout || r.stderr); assert.equal(r.stdout,""); const doc=JSON.parse(r.stderr); if(code) assert.equal(doc.error.code,code); else assert.equal(typeof doc.error.code,"string"); return doc;}
const owner = await mkdtemp(join(tmpdir(),"folderbase-create-capability-"));
const root=join(owner,"source");
const createArgs=(path,id)=>["workspace","create",root,path,"--operation-id",id,"--stdin","--json"];
const report={format:"folderbase-capability-suite-report-v1",capability:"folderbase.workspace-create@0.1.0",implementation:basename(implementation),passed:0,failed:0,cases:[]};
const state={};
async function snapshot(path,prefix="") { const result=[]; for(const name of (await readdir(path)).sort()){const child=join(path,name);const info=await lstat(child);assert.equal(info.isSymbolicLink(),false);result.push([prefix+name,info.isFile()?hash(await readFile(child)):"directory"]);if(info.isDirectory())result.push(...await snapshot(child,prefix+name+"/"));}return result;}
const cases=[
 {id:"binary-empty-unicode-create-and-complete-history",async run(){
  await mkdir(join(root,"tasks"),{recursive:true}); await writeFile(join(root,"untouched.txt"),"keep ordinary bytes");ok(["init",root,"--json"]);
  for(const [path,bytes] of [["tasks/résumé.json",Buffer.from('{"title":"First 🗂️","unknown":{"keep":7}}\r\n')],["tasks/attachment.bin",Buffer.from([0,255,128,13,10])],["tasks/empty.bin",Buffer.alloc(0)]]){
   const id=randomUUID(), result=ok(createArgs(path,id),bytes);assert.equal(result.format,"folderbase-workspace-create-result-v1");assert.equal(result.operation_id,id);assert.equal(result.path,path);assert.equal(result.replayed,false);assert.ok(Number.isFinite(Date.parse(result.created_at)));assert.match(result.object_id,/^obj_[0-9a-f-]{36}$/);assert.match(result.version_id,/^version_[0-9a-f-]{36}$/);assert.deepEqual(result.content,{algorithm:"sha256",digest:hash(bytes),bytes:bytes.length});assert.deepEqual(await readFile(join(root,path)),bytes);
   const history=ok(["version","list",root,path,"--json"]);assert.equal(history.object_id,result.object_id);assert.equal(history.current_version,result.version_id);assert.equal(history.versions.length,1);assert.equal(history.versions[0].id,result.version_id);assert.deepEqual(history.versions[0].content,result.content);assert.equal(history.versions[0].captured_at,result.created_at);
   if(path.endsWith("json"))Object.assign(state,{id,path,bytes,result});
  }
  assert.equal(await readFile(join(root,"untouched.txt"),"utf8"),"keep ordinary bytes");
 }},
 {id:"original-result-replay-and-request-conflict",async run(){
  const {path,id,bytes,result}=state;const replay=ok(createArgs(path,id),bytes);assert.deepEqual(replay,{...result,replayed:true});
  refusal(createArgs(path,id),"different","workspace_create_operation_conflict");refusal(createArgs("tasks/other.json",id),bytes,"workspace_create_operation_conflict");refusal(createArgs(path,randomUUID()),bytes,"workspace_create_destination_occupied");assert.deepEqual(await readFile(join(root,path)),bytes);
 }},
 {id:"cas-history-recovery-and-stale-writes",async run(){
  const {path,result}=state;const current=ok(["workspace","read",root,path,"--json"]);const changed=Buffer.from('{"title":"Second","unknown":{"keep":7}}');
  const saved=ok(["workspace","save",root,path,"--expected-sha256",current.sha256,"--stdin","--json"],changed);assert.equal(saved.object_id,result.object_id);assert.notEqual(saved.version_id,result.version_id);
  refusal(["workspace","save",root,path,"--expected-sha256",current.sha256,"--stdin","--json"],"stale");assert.deepEqual(await readFile(join(root,path)),changed);
  const history=ok(["version","list",root,path,"--json"]);assert.deepEqual(history.versions.map(v=>v.id),[result.version_id,saved.version_id]);
  ok(["version","restore",root,result.version_id,"tasks/recovered.json","--json"]);assert.deepEqual(await readFile(join(root,"tasks/recovered.json")),state.bytes);
 }},
 {id:"completed-replay-preserves-native-edit-and-deletion",async run(){
  await writeFile(join(root,state.path),"later external edit");assert.deepEqual(ok(createArgs(state.path,state.id),state.bytes),{...state.result,replayed:true});assert.equal(await readFile(join(root,state.path),"utf8"),"later external edit");
  await rm(join(root,state.path));assert.deepEqual(ok(createArgs(state.path,state.id),state.bytes),{...state.result,replayed:true});await assert.rejects(readFile(join(root,state.path)),{code:"ENOENT"});
 }},
 {id:"unsafe-parent-reserved-path-and-input-refusal",async run(){
  for(const path of ["missing/new.bin","../escape.bin",".folderbase/private.bin",".folderbaseignore","tasks"]){refusal(createArgs(path,randomUUID()),Buffer.from("never"));}
  refusal(createArgs("tasks/oversize.bin",randomUUID()),Buffer.alloc(8*1024*1024+1),"workspace_create_content_too_large");refusal(createArgs("tasks/id.bin","bad-id"),Buffer.alloc(0),"workspace_create_invalid_operation_id");
  await assert.rejects(readFile(join(root,"tasks/oversize.bin")),{code:"ENOENT"});await assert.rejects(readFile(join(owner,"escape.bin")),{code:"ENOENT"});assert.equal(await readFile(join(root,"untouched.txt"),"utf8"),"keep ordinary bytes");
 }},
 {id:"pending-create-refuses-other-writers-and-history-without-repair",async run(){
  const pending=join(root,".folderbase/transactions/workspace-create/active.json");await writeFile(pending,'{"interrupted":');const before=await snapshot(root);
  refusal(["version","capture",root,"untouched.txt","--json"],undefined,"recovery_required");refusal(["version","list",root,"untouched.txt","--json"],undefined,"file_history_recovery_required");refusal(createArgs("tasks/blocked.bin",randomUUID()),"blocked","workspace_create_state_invalid");assert.deepEqual(await snapshot(root),before);
 }}
];
try {for(const c of cases){const entry={id:c.id,status:"passed"};try{await c.run();report.passed++;}catch(error){entry.status="failed";entry.message=error.stack??String(error);report.failed++;}report.cases.push(entry);if(entry.status==="failed")break;}}finally{await rm(owner,{recursive:true,force:true});}
process.stdout.write(JSON.stringify(report,null,2)+"\n");process.exitCode=report.failed?1:0;
