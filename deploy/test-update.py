#!/usr/bin/env python3
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("update_helper",HERE/"update-helper.py")
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class FakeOpener:
    def __init__(self,body): self.body=body
    def open(self,*args,**kwargs): return io.BytesIO(self.body)


class HelperTests(unittest.TestCase):
    def test_entry_rejects_invalid_capacity_before_any_install_action(self):
        for args in [['--max-connections','0'],['--max-connections','100001'],['--max-connections','oops'],['--max-connections'],['--unknown']]:
            result=subprocess.run(['bash',str(HERE.parent/'update.sh')]+args,text=True,capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertTrue('Usage:' in result.stderr or 'Connection limit' in result.stderr,result.stderr)

    def test_capacity_changes_only_requested_key(self):
        original = '# keep comments\nPANEL_TOKEN="test-only=$value"\nexport PANEL_MAX_CONNECTIONS=20000\nPANEL_DOMAIN=test.example\nPANEL_MAX_CONNECTIONS=10000\n'
        with tempfile.TemporaryDirectory() as directory:
            source,target=Path(directory)/'env',Path(directory)/'candidate'
            source.write_text(original)
            helper.configure_env(source,target,'100000')
            self.assertEqual(source.read_text(),original)
            self.assertEqual(target.read_text(),'# keep comments\nPANEL_TOKEN="test-only=$value"\nPANEL_DOMAIN=test.example\nPANEL_MAX_CONNECTIONS=100000\n')
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertRaises(FileExistsError,helper.configure_env,source,target,'50000')

    def test_capacity_invalid_or_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            source,target=Path(directory)/'env',Path(directory)/'candidate'
            source.write_text('PANEL_MAX_CONNECTIONS=20000\n')
            for value in ['0','100001','-1','1; echo test','oops']:
                self.assertRaises(ValueError,helper.configure_env,source,target,value)
                self.assertFalse(target.exists())
            helper.configure_env(source,target,'')
            self.assertEqual(target.read_bytes(),source.read_bytes())

    def test_backup_validates_and_secures_archive(self):
        content=io.BytesIO()
        with zipfile.ZipFile(content,"w") as archive:
            for name in ["manifest.json","panel.db","certs/fallback.pem"]:
                archive.writestr(name,b"test")
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/"panel.zip"
            with patch.object(helper,"panel_client",return_value=(FakeOpener(content.getvalue()),"http://localhost")):
                helper.backup({},target)
            self.assertTrue(target.is_file())
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertFalse(target.with_suffix(".partial").exists())

    def test_backup_failure_leaves_no_false_success_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/"panel.zip"
            with patch.object(helper,"panel_client",return_value=(FakeOpener(b"truncated ZIP"),"http://localhost")):
                with self.assertRaises(zipfile.BadZipFile): helper.backup({},target)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".partial").exists())

    def test_rollback_preserves_volume_and_environment(self):
        config={"services":{"panel":{"build":{"context":"/old"},"environment":{"PANEL_TOKEN":"test-only"},"network_mode":"service:haproxy"},"haproxy":{"build":{"context":"/old/haproxy"}}},"volumes":{"panel-data":{"name":"fluxgate_panel-data"}}}
        with tempfile.TemporaryDirectory() as directory:
            source,target=Path(directory)/"source.json",Path(directory)/"rollback.json"
            source.write_text(json.dumps(config))
            helper.rollback_config(source,target,"test")
            saved=json.loads(target.read_text())
            self.assertEqual(saved["volumes"],config["volumes"])
            self.assertEqual(saved["services"]["panel"]["environment"],config["services"]["panel"]["environment"])
            self.assertEqual(saved["services"]["panel"]["image"],"fluxgate-rollback-panel:test")
            self.assertNotIn("build",saved["services"]["panel"])
            self.assertEqual(target.stat().st_mode&0o777,0o600)


# Exercise the real Bash orchestration with isolated fake Docker/Git commands.
# HTTP/ZIP behavior of the actual helper is covered separately above.
MOCK_COMMAND='''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
name=Path(sys.argv[0]).name
with open(os.environ['EVENT_LOG'],'a') as f:f.write(json.dumps([name]+args)+'\\n')
case=os.environ['TEST_CASE']
if name=='git':
 if 'rev-parse' in args: print('old-revision')
 sys.exit(0)
if args[:2]==['image','tag']:sys.exit(0)
if args[0]=='inspect':
 if '.Config.Labels' in args[2]:
  print(os.environ['FLUXGATE_DIR']+'/compose.yaml'+(',/custom/override.yaml' if case=='custom-compose' else ''))
 else:print(json.dumps(['PANEL_TOKEN=test-only']) if '.Config.Env' in args[2] else 'sha256:old-image')
elif 'ps' in args:print('container-'+args[-1])
elif 'config' in args:print(json.dumps({'services':{'panel':{},'haproxy':{}},'volumes':{'panel-data':{'name':'existing-data'}}}))
elif 'build' in args and case=='build-failure':sys.exit(17)
elif 'up' in args and '--wait' in args and case=='activation-failure':sys.exit(18)
'''
MOCK_HELPER='''import json,os,sys
from pathlib import Path
if sys.argv[1] in ('backup','verify'):json.load(sys.stdin)
with open(os.environ['EVENT_LOG'],'a') as f:f.write(json.dumps(['helper']+sys.argv[1:])+'\\n')
if sys.argv[1]=='rollback-config':Path(sys.argv[3]).write_text('{}')
elif sys.argv[1]=='configure-env':
 content=Path(sys.argv[2]).read_text()
 if sys.argv[4]:content+='PANEL_MAX_CONNECTIONS='+sys.argv[4]+'\\n'
 Path(sys.argv[3]).write_text(content)
elif sys.argv[1]=='backup':
 if os.environ['TEST_CASE']=='backup-failure':sys.exit(19)
 Path(sys.argv[2]).write_bytes(b'validated-in-helper-tests')
'''


class UpdateFlowTests(unittest.TestCase):
    def run_case(self,case):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            stage,checkout,commands=root/"stage",root/"checkout",root/"bin"
            for path in [stage/"deploy",checkout,commands]:path.mkdir(parents=True)
            shutil.copy(HERE/"update-docker.sh",stage/"deploy/update-docker.sh")
            (stage/"deploy/update-helper.py").write_text(MOCK_HELPER)
            (checkout/".env").write_text("PANEL_TOKEN=test-only\n")
            for name in ["docker","git"]:
                path=commands/name
                path.write_text(MOCK_COMMAND)
                path.chmod(0o700)
            log=root/"events.jsonl"
            env=dict(os.environ,PATH=str(commands)+os.pathsep+os.environ["PATH"],EVENT_LOG=str(log),TEST_CASE=case,FLUXGATE_DIR=str(checkout),FLUXGATE_REVISION="new-revision",FLUXGATE_BACKUP_DIR=str(root/"backups"),FLUXGATE_MAX_CONNECTIONS='100000')
            result=subprocess.run(["bash",str(stage/"deploy/update-docker.sh")],env=env,text=True,capture_output=True,timeout=15)
            events=[json.loads(line) for line in log.read_text().splitlines()]
            expected='PANEL_TOKEN=test-only\n'+('PANEL_MAX_CONNECTIONS=100000\n' if case=='success' else '')
            self.assertEqual((checkout/'.env').read_text(),expected,'capacity update/rollback lost original env')
            for saved in (root/'backups').glob('*/env'):
                self.assertEqual(saved.read_text(),'PANEL_TOKEN=test-only\n')
            return result,events

    def test_custom_compose_is_rejected_before_build_or_restart(self):
        result,events=self.run_case("custom-compose")
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("Custom or unknown Compose",result.stderr)
        self.assertFalse(any("build" in event or "up" in event or "merge" in event for event in events))

    def test_build_failure_never_restarts_services(self):
        result,events=self.run_case("build-failure")
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(any("up" in event or "merge" in event for event in events))

    def test_backup_failure_never_restarts_services(self):
        result,events=self.run_case("backup-failure")
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(any("up" in event or "merge" in event for event in events))

    def test_activation_failure_restores_previous_images(self):
        result,events=self.run_case("activation-failure")
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        updates=[event for event in events if "up" in event]
        self.assertEqual(len(updates),2,events)
        self.assertTrue(any("rollback.compose.json" in value for value in updates[-1]))
        self.assertIn("--force-recreate",updates[-1])
        self.assertTrue(any(event[:2]==["helper","verify"] for event in events))

    def test_success_backs_up_then_activates_both_services(self):
        result,events=self.run_case("success")
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        backup=next(i for i,e in enumerate(events) if e[:2]==["helper","backup"])
        activation=next(i for i,e in enumerate(events) if "up" in e)
        self.assertLess(backup,activation)
        self.assertEqual(sum("up" in event for event in events),1)
        self.assertIn("--force-recreate",events[activation])
        self.assertIn("--wait",events[activation])


if __name__=="__main__":unittest.main(verbosity=2)
