import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("g4", ROOT / "runner" / "g4.py")
g4 = importlib.util.module_from_spec(spec); spec.loader.exec_module(g4)

class G4Tests(unittest.TestCase):
    def test_tokenization_exact(self):
        self.assertTrue(g4.is_restricted("foo_delete_bar", {"delete","remove","cancel"}))
        self.assertTrue(g4.is_restricted("deletePending", {"delete","remove","cancel"}))
        self.assertFalse(g4.is_restricted("undeleted", {"delete","remove","cancel"}))
        self.assertFalse(g4.is_restricted("submit_pending", {"delete","remove","cancel"}))

    def test_collision_and_negative_control(self):
        groups = [
            {"tool":"mixed", "actions":["create", "delete"]},
            {"tool":"safe_compressed", "actions":["get", "list", "read"]},
            {"tool":"restricted_homogeneous", "actions":["delete", "remove"]},
        ]
        r = g4.group_metrics(groups, {"delete","remove","cancel"})
        self.assertEqual(r["source_actions"], 7)
        self.assertEqual(r["colliding_tools"], 1)
        self.assertEqual(r["restricted_actions_inside_colliding_tools"], 1)
        self.assertEqual(r["nonrestricted_actions_inside_colliding_tools"], 1)

    def test_policy_preservation_criterion(self):
        # If all source actions in a tool have the same fixed policy decision,
        # static tool-level policy loses no P_DEL distinction.
        groups = [{"tool":"read_bundle", "actions":["get_a","get_b"]}]
        r = g4.group_metrics(groups, {"delete","remove","cancel"})
        self.assertEqual(r["colliding_tools"], 0)

if __name__ == "__main__":
    unittest.main()
