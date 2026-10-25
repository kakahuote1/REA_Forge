import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
import { casePath } from "./guestCasePrograms.js";

/** Existing full-guest wrapper behavior; no source executes in the host interpreter. */
export const guestIdaWrapper = (binding: GuestCaseBinding, jobId: string, resultPath: string, source: string): string => {
  if (!/^ida-job-[a-f0-9]{24}$/u.test(jobId) || resultPath !== `${casePath(binding)}\\ida_jobs\\${jobId}\\result.json` || Buffer.byteLength(source, "utf8") > 128 * 1024) throw new Error("Invalid bounded guest IDAPython wrapper");
  return `import base64, hashlib, json, os, traceback
import ida_auto, ida_kernwin, ida_loader, ida_pro, idc
_result_path = ${JSON.stringify(resultPath)}
_source=base64.b64decode(${JSON.stringify(Buffer.from(source).toString("base64"))}).decode('utf-8')
_result={'schema_version':1,'case_id':${JSON.stringify(binding.caseId)},'job_id':${JSON.stringify(jobId)},'main_thread_dispatch':False,'ok':False}
def _run():
    scope={'__name__':'__forge_guest_ida__','__file__':'<forge_guest_ida>'}
    try:
        exec(compile(_source,'<forge_guest_ida>','exec'),scope,scope)
        value=scope.get('forge_result')
        try: json.dumps(value,ensure_ascii=False)
        except Exception: value={'repr':repr(value)[:4096]}
        _result.update(ok=True,returned=value)
    except BaseException as error:
        _result.update(exception_type=type(error).__name__,exception=str(error)[:4096],traceback=traceback.format_exc(limit=12)[-16384:])
    return 1
try:
    ida_auto.auto_wait()
    ida_kernwin.execute_sync(_run,getattr(ida_kernwin,'MFF_WRITE',getattr(ida_kernwin,'MFF_FAST',0)))
    _result['main_thread_dispatch']=True
except BaseException as error:
    _result.update(exception_type=type(error).__name__,exception=str(error)[:4096])
finally:
    try:
        if _result.get('ok'):
            _result['idb_path']=idc.get_idb_path()
            _result['idb_saved']=bool(ida_loader.save_database(_result['idb_path'],0))
            if os.path.isfile(_result['idb_path']):
                hasher=hashlib.sha256()
                with open(_result['idb_path'],'rb') as stream:
                    for block in iter(lambda:stream.read(1024*1024),b''): hasher.update(block)
                _result['idb_sha256']=hasher.hexdigest()
    except BaseException as error:
        _result.update(ok=False,save_exception=type(error).__name__+': '+str(error)[:2048])
    pending=_result_path+'.tmp'
    with open(pending,'w',encoding='utf-8',newline='\\n') as stream: json.dump(_result,stream,ensure_ascii=False,sort_keys=True)
    os.replace(pending,_result_path)
    ida_pro.qexit(0)
`;
};
