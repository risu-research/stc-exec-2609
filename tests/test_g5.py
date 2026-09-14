import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))

from rac import (  # noqa: E402
    ALLOW, DENY, UNRESOLVED, STATIC, SELECTOR, EFFECT,
    Action, compile_contract, mediate_trace, pdel, resolve_unique_identity,
)


class RACTests(unittest.TestCase):
    def test_policy_tokenization_is_exact(self):
        self.assertEqual(pdel("foo_delete_bar"), DENY)
        self.assertEqual(pdel("cancelWorkflow"), DENY)
        self.assertEqual(pdel("remove-item"), DENY)
        self.assertEqual(pdel("undeleted"), ALLOW)
        self.assertEqual(pdel("submit_pending"), ALLOW)

    def test_homogeneous_compiles_static(self):
        c = compile_contract(
            "read_bundle",
            [Action("get_a", "get_a"), Action("list_b", "list_b")],
            SELECTOR,
        )
        self.assertEqual(c.form, STATIC)
        self.assertEqual(c.decide("get_a"), ALLOW)
        self.assertEqual(c.decide("unknown"), UNRESOLVED)

    def test_mixed_compiles_selector(self):
        c = compile_contract(
            "edit_bundle",
            [Action("update", "update"), Action("delete", "delete")],
            SELECTOR,
        )
        self.assertEqual(c.form, SELECTOR)
        self.assertEqual(c.decide("update"), ALLOW)
        self.assertEqual(c.decide("delete"), DENY)

    def test_effect_contract_preserves_mixed_trace(self):
        c = compile_contract(
            "execute",
            [Action("GET /x", "GET /x"), Action("DELETE /x", "DELETE /x")],
            EFFECT,
        )
        self.assertEqual(c.form, EFFECT)
        self.assertEqual(mediate_trace(c, ["GET /x", "DELETE /x"]), [ALLOW, DENY])

    def test_unknown_and_ambiguous_fail_closed(self):
        c = compile_contract(
            "edit_bundle",
            [Action("update", "update"), Action("delete", "delete")],
            SELECTOR,
        )
        self.assertEqual(c.decide("missing"), UNRESOLVED)
        self.assertIsNone(resolve_unique_identity(["update", "delete"]))
        self.assertIsNone(resolve_unique_identity([]))

    def test_decision_is_bound_to_action_identity(self):
        c = compile_contract(
            "edit_bundle",
            [Action("update", "update"), Action("delete", "delete")],
            SELECTOR,
        )
        receipt = c.authorize("update")
        self.assertTrue(c.permits_commit(receipt, "update"))
        self.assertFalse(c.permits_commit(receipt, "delete"))

    def test_conflicting_identity_subjects_rejected(self):
        with self.assertRaises(ValueError):
            compile_contract(
                "bad",
                [Action("same", "update"), Action("same", "delete")],
                SELECTOR,
            )


if __name__ == "__main__":
    unittest.main()
