import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("g4", ROOT / "runner" / "g4.py")
g4 = importlib.util.module_from_spec(spec); spec.loader.exec_module(g4)
TOKENS = {"delete","remove","cancel"}

class G4Tests(unittest.TestCase):
    def test_tokenization_exact(self):
        self.assertTrue(g4.is_restricted("foo_delete_bar", TOKENS))
        self.assertTrue(g4.is_restricted("deletePending", TOKENS))
        self.assertTrue(g4.is_restricted("cancel-workflow", TOKENS))
        self.assertFalse(g4.is_restricted("undeleted", TOKENS))
        self.assertFalse(g4.is_restricted("submit_pending", TOKENS))

    def test_collision_and_negative_controls(self):
        groups = [
            {"tool":"mixed", "actions":["create", "delete"]},
            {"tool":"safe_compressed", "actions":["get", "list", "read"]},
            {"tool":"restricted_homogeneous", "actions":["delete", "remove"]},
        ]
        r = g4.relation_metrics(groups, TOKENS)
        self.assertEqual(r["source_action_memberships"], 7)
        self.assertEqual(r["unique_source_action_ids"], 6)
        self.assertEqual(r["colliding_tools"], 1)
        self.assertEqual(r["restricted_memberships_inside_colliding_tools"], 1)
        self.assertEqual(r["nonrestricted_memberships_inside_colliding_tools"], 1)
        self.assertEqual(r["negative_control_groups_count"], 2)

    def test_relation_allows_multi_exposure(self):
        # One source action may be exposed through multiple tools. Collision is
        # evaluated within each tool fiber, without arbitrary reassignment.
        groups = [
            {"tool":"t1", "actions":["shared_create", "delete"]},
            {"tool":"t2", "actions":["shared_create", "update"]},
        ]
        r = g4.relation_metrics(groups, TOKENS)
        self.assertEqual(r["source_action_memberships"], 4)
        self.assertEqual(r["unique_source_action_ids"], 3)
        self.assertEqual(r["colliding_tools"], 1)

    def test_policy_preservation_criterion(self):
        groups = [{"tool":"read_bundle", "actions":["get_a","get_b"]}]
        r = g4.relation_metrics(groups, TOKENS)
        self.assertEqual(r["colliding_tools"], 0)

if __name__ == "__main__":
    unittest.main()
