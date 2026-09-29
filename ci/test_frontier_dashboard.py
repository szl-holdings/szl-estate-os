from pathlib import Path
import importlib.util
import unittest
import tempfile
import json
import hashlib
import base64
import re
import html
import sys
import subprocess
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("dashboard",ROOT/"tools/frontier_dashboard/build.py")
dashboard=importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)

def fixtures():
    gh={"schema":"szl.github-metadata-inventory.v1","observed_at":"2026-01-01T00:00:00Z","summary":{"private":0},"repositories":[{"nameWithOwner":"example/repo","name":"repo","visibility":"PUBLIC","defaultBranchRef":{"name":"main","target":{"oid":"a"*40}}}]}
    hf={"schema_version":"szl.huggingface_inventory.v1","completed_at":"2026-01-01T00:00:00Z","counts":{"models":1,"datasets":0,"spaces":0,"collections":0},"assets":[{"id":"example/model","owner":"example","name":"model","type":"model","revision":"b"*40}],"findings":[]}
    local={"schema_version":"1.0","observed_at":"2026-01-01T00:00:00Z","scope":{"discovered_git_roots":1},"summary":{"checkouts_with_tracked_changes":0},"repositories":[{"path":"/synthetic/repo","head":"c"*40}]}
    return {"github":gh,"huggingface":hf,"local":local}

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.output=self.root/"result.html"
        self.data=fixtures()
    def tearDown(self):
        self.tmp.cleanup()
    def write(self):
        for key,value in self.data.items():
            (self.root/(key+"_inventory.json")).write_text(json.dumps(value),encoding="utf-8")
    def build(self):
        self.write()
        return dashboard.build(self.root,self.output)
    def embedded(self):
        return json.loads(re.search(r'<script id="inventory" type="application/json">(.*?)</script>',self.output.read_text(encoding="utf-8"),re.S).group(1))
    def test_offline_build_has_exact_source_hashes_and_truth_boundaries(self):
        with patch("socket.socket",side_effect=AssertionError("network prohibited")):
            result=self.build()
        self.assertEqual(result["records"],3)
        data=self.embedded()
        for name,digest in data["digests"].items():
            self.assertEqual(digest,hashlib.sha256((self.root/name).read_bytes()).hexdigest())
        for asset in data["assets"]:
            self.assertEqual(asset["authorization"],"UNVERIFIED")
            self.assertEqual(asset["signer"],"UNVERIFIED")
            self.assertEqual(asset["readiness"],"UNVERIFIED")
    def test_markup_and_template_tokens_are_inert(self):
        value='</script><script>alert(1)</script>__SCRIPT__'
        self.data["github"]["repositories"][0]["name"]=value
        self.build()
        self.assertEqual(self.embedded()["assets"][0]["name"],value)
        self.assertNotIn('<script>alert(1)</script>',self.output.read_text(encoding="utf-8"))
    def test_input_cannot_promote_evidence(self):
        self.data["huggingface"]["assets"][0].update(readiness="READY",authorization="APPROVED",signer_state="VERIFIED",evidence_class="LIVE")
        self.build()
        asset=next(a for a in self.embedded()["assets"] if a["platform"]=="Hugging Face")
        self.assertEqual([asset[k] for k in ("readiness","authorization","signer")],["UNVERIFIED"]*3)
        self.assertEqual(asset["evidence"],"OBSERVED_METADATA")
    def test_rebuilds_have_identical_bytes_and_receipts(self):
        first=self.build()
        first_bytes=self.output.read_bytes()
        second=dashboard.build(self.root,self.output)
        self.assertEqual(first_bytes,self.output.read_bytes())
        self.assertEqual(first,second)
        self.assertNotIn("created",self.embedded())
    def test_local_names_are_portable_without_primary_path_exposure(self):
        for path in (r"C:\synthetic\repo","C:\\synthetic\\repo\\","/synthetic/repo","/synthetic/repo/",r"\\server\share\repo"):
            with self.subTest(path=path):
                self.data["local"]["repositories"][0]["path"]=path
                self.build()
                asset=next(a for a in self.embedded()["assets"] if a["platform"]=="Local")
                self.assertEqual(asset["name"],"repo")
                self.assertEqual(asset["facts"]["Local path"],path)
    def test_missing_or_invalid_snapshot_times_stay_unavailable(self):
        for value in (None,"",0,False,"UNAVAILABLE","2026-01-01","2026-02-30T00:00:00Z","2026-01-01T00:00:00"):
            with self.subTest(value=value):
                self.data["huggingface"]["completed_at"]=value
                self.build()
                self.assertIsNone(self.embedded()["snapshots"]["huggingface"])
        for value in ("2026-01-01T00:00:00Z","2026-01-01T00:00:00.123456+00:00"):
            self.assertEqual(dashboard.snapshot_timestamp(value),value)
    def test_browser_time_never_coerces_missing_values_to_epoch(self):
        source=(ROOT/"tools/frontier_dashboard/app.js").read_text(encoding="utf-8")
        helper=re.search(r"  const time = (.*);\n  const c =",source,re.S).group(1)
        cases=[None,"",0,False,"UNAVAILABLE","not-a-date","2026-01-01","2026-01-01T25:00:00Z","2026-01-01T24:00:00Z","2026-02-30T00:00:00Z","2026-02-29T00:00:00Z","2026-04-31T00:00:00Z","1900-02-29T00:00:00Z","2026-01-01T00:00:00+24:00"]
        script="const time="+helper+";process.stdout.write(JSON.stringify("+json.dumps(cases)+".map(time)));"
        result=subprocess.run(["node","-e",script],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout),["Timestamp unavailable"]*len(cases))
        valid=["2024-02-29T00:00:00Z","2000-02-29T00:00:00Z","2026-01-01T01:30:00+01:30"]
        script="const time="+helper+";process.stdout.write(JSON.stringify("+json.dumps(valid)+".map(time)));"
        result=subprocess.run(["node","-e",script],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout),["2024-02-29 00:00:00 UTC","2000-02-29 00:00:00 UTC","2026-01-01 00:00:00 UTC"])
    def test_links_are_derived_from_identity_and_revision(self):
        self.data["github"]["repositories"][0]["url"]="https://github.com/foreign/unrelated"
        self.data["github"]["repositories"][0]["defaultBranchRef"]["target"]["url"]="javascript:alert(1)"
        self.build()
        item=self.embedded()["assets"][0]
        self.assertEqual(item["source"],"https://github.com/example/repo")
        self.assertEqual(item["revisionSource"],"https://github.com/example/repo/commit/"+"a"*40)
    def test_unsafe_urls_are_removed(self):
        for value in ("javascript:alert(1)","https://evil.example/x","https://token@github.com/x","https://github.com:8443/x","file:///x"):
            self.assertIsNone(dashboard.url(value))
        self.assertEqual(dashboard.url("https://github.com/example/repo?token=hidden#x"),"https://github.com/example/repo")
    def test_csp_hashes_match_actual_inline_bytes(self):
        self.build()
        text=self.output.read_text(encoding="utf-8")
        csp=html.unescape(re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"',text).group(1))
        for tag in re.findall(r"<(?:style|script)[^>]*>(.*?)</(?:style|script)>",text,re.S):
            digest=base64.b64encode(hashlib.sha256(tag.encode()).digest()).decode()
            self.assertIn("sha256-"+digest,csp)
        self.assertIn("connect-src 'none'",csp)
        self.assertNotRegex(text,r'<(?:script|link)[^>]+(?:src|href)="https?://')
    def test_bad_schema_preserves_existing_output(self):
        self.output.write_text("retained")
        self.data["github"]["schema"]="wrong"
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.output.read_text(),"retained")
    def test_duplicate_identity_rejected(self):
        self.data["github"]["repositories"]*=2
        with self.assertRaises(ValueError): self.build()
    def test_bad_revision_rejected(self):
        self.data["huggingface"]["assets"][0]["revision"]="main"
        with self.assertRaises(ValueError): self.build()
    def test_bad_counts_rejected(self):
        self.data["huggingface"]["counts"]["models"]=2
        with self.assertRaises(ValueError): self.build()
    def test_output_input_alias_rejected(self):
        self.write()
        path=self.root/"github_inventory.json"
        before=path.read_bytes()
        with self.assertRaises(ValueError): dashboard.build(self.root,path)
        self.assertEqual(path.read_bytes(),before)
    def test_cli_failure_does_not_print_metadata(self):
        self.write()
        self.data["github"]["schema"]="SENSITIVE_SENTINEL"
        self.write()
        import io,contextlib
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            rc=dashboard.main(["--estate-dir",str(self.root),"--output",str(self.output)])
        self.assertEqual(rc,2)
        self.assertNotIn("SENSITIVE_SENTINEL",stream.getvalue())

if __name__=="__main__":
    unittest.main(verbosity=2)
