"""Build an offline evidence explorer from local inventory snapshots.

No credentials, requests, repository mutations, or publication. Inputs may be private;
the generated HTML retains their metadata and must remain in the same trust boundary.
Static build success is not browser, accessibility, performance or runtime proof.
"""
from pathlib import Path
import base64
import datetime
import hashlib
import html
import json
from urllib.parse import urlsplit, urlunsplit

import argparse
import os
import re
import tempfile

def clean(value, limit=1200):
    if value is None:
        return "UNAVAILABLE"
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("\x00", "")[:limit]

def url(value):
    try:
        p = urlsplit(value or "")
        if p.port in (None, 443) and p.scheme == "https" and p.hostname in {"github.com", "huggingface.co"} and not p.username and not p.password:
            return urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    except ValueError:
        pass
    return None


HERE = Path(__file__).resolve().parent
MAX_INPUT_BYTES = 25_000_000
MAX_RECORDS = 10000
IDENTITY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")

def require(condition, label):
    if not condition:
        raise ValueError(label)

def check_revision(value):
    require(value is None or (isinstance(value,str) and REVISION.fullmatch(value)), "invalid immutable revision")

def load_inputs(estate_dir, output):
    expected={"github":("schema","szl.github-metadata-inventory.v1","repositories"),
              "huggingface":("schema_version","szl.huggingface_inventory.v1","assets"),
              "local":("schema_version","1.0","repositories")}
    inputs, raw_inputs = {}, {}
    for key, (schema_field,schema_value,records_field) in expected.items():
        path=estate_dir/(key+"_inventory.json")
        require(output.resolve()!=path.resolve(), "output aliases inventory input")
        if output.exists():
            require(not os.path.samefile(output,path), "output aliases inventory input")
        require(path.is_file() and 0 < path.stat().st_size <= MAX_INPUT_BYTES, "input size outside budget")
        raw=path.read_bytes()
        require(len(raw)<=MAX_INPUT_BYTES, "input size outside budget")
        data=json.loads(raw)
        require(isinstance(data,dict) and data.get(schema_field)==schema_value, "unsupported inventory schema")
        rows=data.get(records_field)
        require(isinstance(rows,list) and len(rows)<=MAX_RECORDS and all(isinstance(r,dict) for r in rows), "invalid inventory rows")
        inputs[key],raw_inputs[key]=data,raw
    gh,hf,local=inputs["github"],inputs["huggingface"],inputs["local"]
    require(isinstance(gh.get("summary"),dict) and type(gh["summary"].get("private")) is int, "missing GitHub counts")
    require(gh["summary"]["private"]==sum(r.get("visibility")=="PRIVATE" for r in gh["repositories"]), "GitHub count mismatch")
    seen=set()
    for r in gh["repositories"]:
        identity=r.get("nameWithOwner")
        require(isinstance(identity,str) and IDENTITY.fullmatch(identity) and identity.lower() not in seen, "invalid or duplicate GitHub identity")
        seen.add(identity.lower())
        require(isinstance(r.get("name"),str), "missing repository name")
        require(r.get("visibility") in ("PUBLIC","PRIVATE"), "unsupported GitHub visibility")
        check_revision(((r.get("defaultBranchRef") or {}).get("target") or {}).get("oid"))
    require(isinstance(hf.get("counts"),dict), "missing Hugging Face counts")
    for plural,singular in (("models","model"),("datasets","dataset"),("spaces","space")):
        require(type(hf["counts"].get(plural)) is int and hf["counts"][plural]==sum(r.get("type")==singular for r in hf["assets"]), "Hugging Face count mismatch")
    require(type(hf["counts"].get("collections")) is int and hf["counts"]["collections"]>=0, "invalid collections count")
    seen=set()
    for r in hf["assets"]:
        identity=r.get("id")
        require(isinstance(identity,str) and IDENTITY.fullmatch(identity) and r.get("type") in ("model","dataset","space"), "invalid Hugging Face identity")
        require((r["type"],identity.lower()) not in seen, "duplicate Hugging Face identity")
        seen.add((r["type"],identity.lower()))
        require(all(isinstance(r.get(k),str) for k in ("owner","name")), "missing Hugging Face identity fields")
        check_revision(r.get("revision"))
    require(isinstance(local.get("scope"),dict) and isinstance(local.get("summary"),dict), "missing local coverage")
    require(type(local["scope"].get("discovered_git_roots")) is int and local["scope"]["discovered_git_roots"]>=len(local["repositories"]), "invalid local discovered count")
    require(type(local["summary"].get("checkouts_with_tracked_changes")) is int, "missing local change count")
    seen=set()
    for r in local["repositories"]:
        require(isinstance(r.get("path"),str) and r["path"] and r["path"] not in seen, "invalid or duplicate local path")
        seen.add(r["path"])
        check_revision(r.get("head"))
    return inputs,raw_inputs

def build(estate_dir, output):
    estate_dir,output=Path(estate_dir),Path(output)
    inputs,raw_inputs=load_inputs(estate_dir,output)
    assets = []
    for r in inputs["github"]["repositories"]:
        branch = r.get("defaultBranchRef") or {}
        target = branch.get("target") or {}
        supplement = r.get("supplement") or {}
        notices = []
        if not r.get("licenseInfo"):
            notices.append("License not detected in GitHub metadata")
        if (target.get("statusCheckRollup") or {}).get("state") == "FAILURE":
            notices.append("Default revision reports a failing check rollup")
        if supplement.get("workflows", {}).get("state") == "UNAVAILABLE":
            notices.append("Workflow enumeration unavailable")
        if r.get("isArchived"):
            notices.append("Archived repository")
        assets.append({"id": "github/" + r["nameWithOwner"], "name": clean(r["name"]), "owner": clean(r["nameWithOwner"].split("/")[0]), "platform": "GitHub", "type": "repository", "visibility": clean(r.get("visibility")), "source": url("https://github.com/" + r["nameWithOwner"]), "revisionSource": url("https://github.com/" + r["nameWithOwner"] + "/commit/" + target["oid"]) if target.get("oid") else None, "revision": clean(target.get("oid")), "branch": clean(branch.get("name")), "evidence": "OBSERVED_METADATA", "runtime": "UNAVAILABLE", "authorization": "UNVERIFIED", "signer": "UNVERIFIED", "readiness": "UNVERIFIED", "timestamp": clean(inputs["github"].get("observed_at")), "notices": notices, "facts": {"Language": clean((r.get("primaryLanguage") or {}).get("name")), "License (metadata)": clean((r.get("licenseInfo") or {}).get("spdxId")), "Default revision check rollup": clean((target.get("statusCheckRollup") or {}).get("state")), "Open pull requests": clean((r.get("pullRequests") or {}).get("totalCount")), "Workflow enumeration": clean(supplement.get("workflows", {}).get("state")), "Last source push": clean(r.get("pushedAt")), "Lifecycle": "ARCHIVED" if r.get("isArchived") else "ACTIVE"}, "limit": "Repository metadata and check rollups were observed. These do not establish deployed application health, execution authority or signature verification."})

    for r in inputs["huggingface"]["assets"]:
        revision = clean(r.get("revision"))
        source = url("https://huggingface.co/" + {"model":"", "dataset":"datasets/", "space":"spaces/"}[r["type"]] + r["id"])
        notices = [clean(x) for x in r.get("blockers", [])]
        for f in inputs["huggingface"].get("findings", []):
            if f.get("asset_id") == r.get("id") and f.get("asset_type") == r.get("type"):
                if f["code"] not in notices:
                    notices.append(clean(f["code"]))
        runtime = r.get("runtime_state", "UNAVAILABLE")
        assets.append({"id": "huggingface/" + r["type"] + "/" + r["id"], "name": clean(r["name"]), "owner": clean(r["owner"]), "platform": "Hugging Face", "type": clean(r["type"]), "visibility": clean(r.get("visibility")), "source": source, "revisionSource": url(source + "/tree/" + revision) if source and re.fullmatch(r"[a-f0-9]{40}", revision) else None, "revision": revision, "branch": clean(r.get("default_branch")), "evidence": "OBSERVED_METADATA", "runtime": clean(runtime), "authorization": "UNVERIFIED", "signer": "UNVERIFIED", "readiness": "UNVERIFIED", "timestamp": clean(r.get("source_timestamp")), "notices": notices, "facts": {"Artifact observations": ", ".join(r.get("artifact_classification", [])) or "UNAVAILABLE", "License (metadata)": clean(r.get("license")), "SDK / framework": clean(r.get("sdk") or r.get("framework")), "File count": clean(r.get("file_count")), "Metadata inventory": clean(r.get("metadata_inventory", {}).get("status")), "Immutable file tree": clean(r.get("file_inventory", {}).get("status")), "Source binding": clean(r.get("lineage", {}).get("immutable_source_binding")), "Publication eligibility": clean(r.get("publication_eligibility"))}, "limit": "Provider runtime describes the hosting platform only. Metadata, filenames and README declarations do not prove application readiness, valid weights, training quality, signer validity or authorization."})

    for index, r in enumerate(inputs["local"]["repositories"]):
        source = next((url(m.get("url", "").removesuffix(".git")) for m in r.get("remotes", []) if url(m.get("url", "").removesuffix(".git"))), None)
        path = r["path"]
        changes = r.get("tracked_changes", {})
        assets.append({"id": "local/" + str(index), "name": Path(path).name, "owner": "Local checkout", "platform": "Local", "type": "checkout", "visibility": "LOCAL", "source": source, "revisionSource": url(source + "/commit/" + r["head"]) if source and "github.com" in source and r.get("head") else None, "revision": clean(r.get("head")), "branch": clean(r.get("branch")), "evidence": "OBSERVED_METADATA", "runtime": "UNAVAILABLE", "authorization": "UNVERIFIED", "signer": "UNVERIFIED", "readiness": "UNVERIFIED", "timestamp": clean(r.get("observed_at")), "notices": [clean(x) for x in r.get("blockers", [])], "facts": {"Local path": path, "Tracked changes": clean(changes.get("count")), "Untracked files": clean(changes.get("untracked")), "Tracked files": clean(r.get("tracked_file_count")), "Tracked environment paths": clean(r.get("tracked_environment", {}).get("count")), "Weight filename candidates": clean(r.get("tracked_weight_candidates", {}).get("count")), "Remote refresh": clean(r.get("remote_state")), "Repository code execution": clean(r.get("code_execution"))}, "limit": "Local checkout records can refer to the same remote repository. Only tracked status was counted; untracked files and repository contents were not audited. Local revisions were not fetched or verified against current remote heads."})

    assets.sort(key=lambda a: (a["platform"], a["name"].lower(), a["id"]))
    data = {"assets": assets, "created": datetime.datetime.now(datetime.timezone.utc).isoformat(), "snapshots": {key: value.get("completed_at") or value.get("observed_at") for key, value in inputs.items()}, "counts": {"github": len(inputs["github"]["repositories"]), "huggingface": len(inputs["huggingface"]["assets"]), "models": inputs["huggingface"]["counts"]["models"], "datasets": inputs["huggingface"]["counts"]["datasets"], "spaces": inputs["huggingface"]["counts"]["spaces"], "collections": inputs["huggingface"]["counts"]["collections"], "local": len(inputs["local"]["repositories"]), "local_discovered": inputs["local"]["scope"]["discovered_git_roots"], "local_dirty": inputs["local"]["summary"]["checkouts_with_tracked_changes"], "github_private": inputs["github"]["summary"]["private"], "workflow_unavailable": sum(r.get("supplement", {}).get("workflows", {}).get("state") == "UNAVAILABLE" for r in inputs["github"]["repositories"])}, "digests": {key + "_inventory.json": hashlib.sha256(raw_inputs[key]).hexdigest() for key in inputs}}


    css = (HERE / "style.css").read_text(encoding="utf-8")
    js = (HERE / "app.js").read_text(encoding="utf-8")
    data_json = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    sha = lambda value: base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()
    csp = f"default-src 'none'; script-src 'sha256-{sha(js)}' 'sha256-{sha(data_json)}'; style-src 'sha256-{sha(css)}'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    replacements = {"__CSP__":html.escape(csp, quote=True), "__STYLE__":css, "__DATA__":data_json, "__SCRIPT__":js}
    page = re.sub(r"__(?:CSP|STYLE|DATA|SCRIPT)__", lambda m: replacements[m.group()], (HERE/"template.html").read_text(encoding="utf-8"))
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".frontier-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(page.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return {"records":len(assets), "counts":data["counts"], "sha256":hashlib.sha256(page.encode("utf-8")).hexdigest(), "signer_state":"UNSIGNED", "browser_validation":"UNVERIFIED"}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estate-dir",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        result=build(args.estate_dir,args.output)
    except (ValueError,KeyError,TypeError,AttributeError,OSError) as exc:
        print(json.dumps({"status":"FAILED","error_type":type(exc).__name__}))
        return 2
    print(json.dumps({"status":"BUILT_STATIC_ONLY",**result}))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
