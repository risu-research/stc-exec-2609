import pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runner"))
from rac import Action, ALLOW, DENY, UNRESOLVED, SELECTOR, EFFECT, compile_contract
from rac_runtime import IndexedContract, SelectorAdapter, SelectorCall, EffectAdapter, EffectCall, descriptor

class G6Tests(unittest.TestCase):
    def setUp(self):
        self.c=compile_contract("mixed",[Action("update","update"),Action("delete","delete")],SELECTOR)
        self.i=IndexedContract.build(self.c)
    def test_index_preserves_contract_id_and_decisions(self):
        self.assertEqual(self.i.contract_id,self.c.contract_id)
        self.assertEqual(self.i.mediate("update"),ALLOW)
        self.assertEqual(self.i.mediate("delete"),DENY)
        self.assertEqual(self.i.mediate("unknown"),UNRESOLVED)
    def test_final_resolved_identity_wins(self):
        a=SelectorAdapter({"mixed":self.i})
        self.assertEqual(a.mediate(SelectorCall("mixed","update","delete")),DENY)
    def test_receipt_cannot_cross_identity(self):
        r=self.i.authorize("update")
        self.assertTrue(self.i.permits(r,"update")); self.assertFalse(self.i.permits(r,"delete"))
    def test_effect_adapter_mediates_each_effect(self):
        c=compile_contract("execute",[Action("GET /x","GET /x"),Action("DELETE /x","DELETE /x")],EFFECT)
        e=EffectAdapter(IndexedContract.build(c))
        self.assertEqual(e.mediate(EffectCall("execute",("GET /x","DELETE /x"))),(ALLOW,DENY))
    def test_descriptor_does_not_enumerate_domain(self):
        d=descriptor(self.i,"abc","resolved-action"); raw=str(d)
        self.assertNotIn("update",raw); self.assertNotIn("delete",raw); self.assertEqual(d["contractId"],self.c.contract_id)

if __name__=="__main__": unittest.main()
