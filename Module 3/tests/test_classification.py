import copy
import json
from pathlib import Path
import tempfile
import unittest

from module3.classification import Classification
from module3.input import stage, encode
from module3.store import Store, recording
from test_module3 import flow


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.store=Store(self.root/"inventory.sqlite3",{"10.77.20.20":{"role":"configured_pump"}})
        with stage((encode(flow())+"\n",),"sensor","test",True) as (db,header):
            self.store.apply(db,header)
        record=recording(self.store.path,"sensor","test")
        self.data={"schema_version":"hiot.classification.projection.v1","source_id":"sensor","scope":"test",
                   "inventory_revision":record["revision"],"inventory_digest":record["digest"],"capture_sha256":"abc",
                   "records":[{"schema_version":"hiot.workflow-evidence.v2.0","endpoint":"10.77.20.20","category":"unknown",
                               "workflows":["flow_rate_reporting"],"evidence":[{"capture_sha256":"abc","frames":[1,2]}]}]}
        with self.store.connect() as db:
            db.execute("INSERT OR REPLACE INTO captures(source,scope,id,data) VALUES(?,?,?,?)",("sensor","test","cap",json.dumps({"sha256":"abc"})))
        self.asset=next(a for a in self.store.assets()["records"] if a["ip"]=="10.77.20.20")

    def tearDown(self):
        self.temp.cleanup()

    def load(self):
        path=self.root/"projection.json"
        path.write_text(json.dumps(self.data))
        return Classification(path)

    def test_current_projection_preserves_registry(self):
        before=copy.deepcopy(self.asset)
        result=self.load().for_asset(self.store,self.asset)
        self.assertEqual(result["state"],"current")
        self.assertEqual(result["category"],"unknown")
        self.assertEqual(self.asset,before)

    def test_scope_and_source_must_match(self):
        for key in ("source_id","scope"):
            asset={**self.asset,key:"different"}
            self.assertIsNone(self.load().for_asset(self.store,asset))

    def test_revision_change_hides_prediction(self):
        self.data["inventory_revision"] += "-changed"
        result=self.load().for_asset(self.store,self.asset)
        self.assertEqual(result["state"],"stale")
        self.assertNotIn("category",result)

    def test_capture_mismatch_hides_prediction(self):
        self.data["capture_sha256"]="different"
        self.assertEqual(self.load().for_asset(self.store,self.asset)["state"],"unverified")

    def test_duplicate_or_unreviewed_category_rejected(self):
        self.data["records"].append(self.data["records"][0])
        with self.assertRaises(ValueError): self.load()
        self.data["records"].pop()
        self.data["records"][0]["category"]="infusion_pump"
        with self.assertRaises(ValueError): self.load()


if __name__=="__main__": unittest.main()
