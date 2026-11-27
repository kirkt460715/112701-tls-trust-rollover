"""验证按站点和入口办理轮换的判定。"""

import json
from pathlib import Path
import tempfile
import unittest

from rotation import evaluate, load_records

RECORDS = Path(__file__).with_name("records")


def load():
    return load_records(RECORDS)


def entry(report, name):
    for service in report["services"]:
        for item in service["entries"]:
            if item["entry"] == name:
                return item
    raise AssertionError(f"缺少入口 {name}")


class EvidenceLayeringTests(unittest.TestCase):
    def setUp(self):
        self.report = evaluate(load())

    def test_accepted_gateway_is_not_treated_as_effective(self):
        edge_b = entry(self.report, "edge-b")
        self.assertFalse(edge_b["new_chain"]["gateway_approved"])
        self.assertIsNone(edge_b["new_chain"]["gateway_live_from"])
        self.assertEqual(edge_b["new_chain"]["gateway_gap"], "not_approved")
        self.assertIn("queued-b", edge_b["new_chain"]["accepted_but_not_effective"])

    def test_plan_does_not_count_as_client_trust(self):
        edge_b = entry(self.report, "edge-b")
        self.assertEqual(edge_b["new_chain"]["clients_missing_trust"], ["stock-b"])
        self.assertEqual(edge_b["new_chain"]["client_gap"], "client_not_trusting")
        self.assertEqual([p["id"] for p in edge_b["plans"]], ["plan-b"])
        self.assertFalse(edge_b["plans"][0]["effective"])

    def test_gateway_effective_and_client_observation_are_separate(self):
        edge_a = entry(self.report, "edge-a")
        self.assertEqual(edge_a["new_chain"]["gateway_live_from"], 60)
        self.assertEqual(edge_a["new_chain"]["client_trust_from"], 49)
        self.assertEqual(edge_a["both_sides_from"], 60)

    def test_revocation_blocks_fallback_and_overrides_approval(self):
        edge_a = entry(self.report, "edge-a")
        old = edge_a["old_chain"]
        self.assertEqual((old["stop"], old["stop_source"]), (64, "revocation"))
        self.assertFalse(old["fallback_allowed"])
        self.assertTrue(old["revocation_overrides_approval"])

    def test_late_observation_is_flagged_as_conflict(self):
        edge_b = entry(self.report, "edge-b")
        (observation,) = edge_b["old_chain"]["observations"]
        self.assertTrue(observation["conflict"])
        self.assertTrue(observation["valid_at_capture"])
        self.assertFalse(observation["usable_at_receipt"])


class PerEntryTests(unittest.TestCase):
    def setUp(self):
        self.report = evaluate(load())

    def test_one_entry_cannot_sign_for_another(self):
        service = self.report["services"][0]
        self.assertEqual(service["status"], "partial")
        self.assertEqual(service["stable_entries"], ["edge-a"])
        self.assertEqual(service["blocked_entries"], ["edge-b"])
        self.assertNotEqual(entry(self.report, "edge-a")["status"],
                            entry(self.report, "edge-b")["status"])

    def test_missing_evidence_names_owner(self):
        edge_b = entry(self.report, "edge-b")
        self.assertEqual(edge_b["status"], "blocked")
        self.assertIn("gateway_not_approved", edge_b["missing_evidence"])
        self.assertIn("client_not_trusting", edge_b["missing_evidence"])
        self.assertEqual(edge_b["owner"], "变更审批人")

    def test_station_may_break_when_old_chain_stopped(self):
        stations = entry(self.report, "edge-b")["stations"]
        self.assertEqual(stations["stock-b"]["state"], "at_risk")
        self.assertEqual(stations["stock-b"]["usable_old_until"], 64)

    def test_stable_station_reports_ready_time(self):
        station = entry(self.report, "edge-a")["stations"]["stock-a"]
        self.assertEqual(station["state"], "stable_new")
        self.assertEqual(station["ready_from"], 60)

    def test_overlap_answers_three_questions(self):
        overlap = entry(self.report, "edge-a")["overlap"]
        self.assertTrue(overlap["exists"])
        self.assertEqual(overlap["old_usable_from"], 60)
        self.assertEqual(overlap["new_ready_from"], 60)
        self.assertEqual(overlap["must_stop_relying_at"], 64)
        self.assertEqual(overlap["basis"], "revocation")

    def test_approval_basis_is_queryable(self):
        basis = entry(self.report, "edge-a")["approval_basis"]
        self.assertEqual([row["id"] for row in basis["gateway"]], ["staged-a"])
        self.assertEqual(basis["revocation"]["id"], "revoke-old")


class AsOfTests(unittest.TestCase):
    def test_before_gateway_approval_nothing_is_signed(self):
        report = evaluate(load(), as_of=50)
        edge_a = entry(report, "edge-a")
        self.assertEqual(edge_a["status"], "blocked")
        self.assertIn("gateway_not_approved", edge_a["missing_evidence"])

    def test_after_approval_but_before_effect_is_pending(self):
        report = evaluate(load(), as_of=55)
        edge_a = entry(report, "edge-a")
        self.assertEqual(edge_a["status"], "overlap_active")
        self.assertIn("gateway_accepted_not_effective",
                      edge_a["missing_evidence"])

    def test_after_both_sides_effective_entry_proceeds(self):
        report = evaluate(load(), as_of=60)
        self.assertEqual(entry(report, "edge-a")["status"], "stable_new")

    def test_observation_not_yet_received_is_hidden(self):
        report = evaluate(load(), as_of=60)
        self.assertEqual(entry(report, "edge-b")["old_chain"]["observations"], [])


class ValidationTests(unittest.TestCase):
    def _records(self, directory, pki, clients, gateways):
        path = Path(directory)
        (path / "pki.json").write_text(json.dumps(pki))
        (path / "clients.json").write_text(json.dumps(clients))
        (path / "gateways.json").write_text(json.dumps(gateways))
        return path

    def test_duplicate_revocation_for_chain_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._records(
                directory,
                [{"id": "a", "service": "s", "trusted_root": "r", "expires": 10},
                 {"id": "b", "service": "s", "trusted_root": "q", "expires": 20},
                 {"id": "rv1", "chain": "a", "effective": 5, "received": 6},
                 {"id": "rv2", "chain": "a", "effective": 7, "received": 8}],
                [{"id": "c", "group": "g", "root": ["r"], "confirmed_at": 1,
                  "entry": "e"}],
                [{"id": "g", "entry": "e", "chains": ["a", "b"],
                  "approved_at": 1}])
            with self.assertRaises(ValueError):
                load_records(path)

    def test_revocation_unknown_chain_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._records(
                directory,
                [{"id": "a", "service": "s", "trusted_root": "r", "expires": 10},
                 {"id": "b", "service": "s", "trusted_root": "q", "expires": 20},
                 {"id": "rv", "chain": "missing", "effective": 5, "received": 6}],
                [{"id": "c", "group": "g", "root": ["r"], "confirmed_at": 1,
                  "entry": "e"}],
                [{"id": "g", "entry": "e", "chains": ["a"], "approved_at": 1}])
            with self.assertRaises(ValueError):
                load_records(path)

    def test_notice_after_chain_expiry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._records(
                directory,
                [{"id": "a", "service": "s", "trusted_root": "r", "expires": 10},
                 {"id": "b", "service": "s", "trusted_root": "q", "expires": 20},
                 {"id": "rv", "chain": "a", "effective": 12, "received": 13}],
                [{"id": "c", "group": "g", "root": ["r"], "confirmed_at": 1,
                  "entry": "e"}],
                [{"id": "g", "entry": "e", "chains": ["a"], "approved_at": 1}])
            with self.assertRaises(ValueError):
                load_records(path)

    def test_unknown_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._records(
                directory,
                [{"id": "a", "service": "s", "trusted_root": "r", "expires": 10}],
                [{"id": "c", "group": "g", "root": ["nope"], "confirmed_at": 1,
                  "entry": "e"}],
                [])
            with self.assertRaises(ValueError):
                load_records(path)

    def test_staged_record_cannot_claim_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._records(
                directory,
                [{"id": "a", "service": "s", "trusted_root": "r", "expires": 10},
                 {"id": "b", "service": "s", "trusted_root": "q", "expires": 20}],
                [{"id": "c", "group": "g", "root": ["r"], "confirmed_at": 1,
                  "entry": "e"}],
                [{"id": "g", "entry": "e", "chains": ["a", "b"],
                  "approved_at": 1, "effective": 2}])
            with self.assertRaises(ValueError):
                load_records(path)


class SharedCertificateTests(unittest.TestCase):
    """同一服务多个入口共用一张链时，一处证据不能替另一处签认。"""

    def _load(self, directory, gateways):
        path = Path(directory)
        pki = [{"id": "old", "service": "s", "trusted_root": "r1", "expires": 100},
               {"id": "new", "service": "s", "trusted_root": "r2", "expires": 200},
               {"id": "rv", "chain": "old", "effective": 80, "received": 81}]
        clients = [
            {"id": "c1", "group": "g1", "root": ["r1", "r2"],
             "confirmed_at": 10, "entry": "e1"},
            {"id": "c2", "group": "g2", "root": ["r1", "r2"],
             "confirmed_at": 10, "entry": "e2"},
        ]
        (path / "pki.json").write_text(json.dumps(pki))
        (path / "clients.json").write_text(json.dumps(clients))
        (path / "gateways.json").write_text(json.dumps(gateways))
        return load_records(path)

    def test_effective_on_one_entry_does_not_cover_the_other(self):
        with tempfile.TemporaryDirectory() as directory:
            records = self._load(directory, [
                {"id": "stage1", "entry": "e1", "chains": ["old", "new"],
                 "approved_at": 20},
                {"id": "apply1", "entry": "e1", "revision": "r1", "effective": 30},
                {"id": "stage2", "entry": "e2", "chains": ["old", "new"],
                 "approved_at": 20},
            ])
            report = evaluate(records, as_of=40)
            self.assertEqual(entry(report, "e1")["status"], "stable_new")
            edge2 = entry(report, "e2")
            self.assertEqual(edge2["status"], "overlap_active")
            self.assertEqual(edge2["new_chain"]["gateway_gap"],
                             "accepted_not_effective")

    def test_approval_after_revocation_cannot_restore_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            records = self._load(directory, [
                {"id": "stage1", "entry": "e1", "chains": ["old", "new"],
                 "approved_at": 20},
                {"id": "apply1", "entry": "e1", "revision": "r1", "effective": 30},
            ])
            # 记录最晚时点 81，撤销通知已到达；旧链回退必须关闭。
            report = evaluate(records, as_of=81)
            old = entry(report, "e1")["old_chain"]
            self.assertEqual(old["stop"], 80)
            self.assertFalse(old["fallback_allowed"])
            self.assertTrue(old["revocation_overrides_approval"])


class ReportCliTests(unittest.TestCase):
    def test_brief_and_json_agree(self):
        import subprocess
        import sys
        script = Path(__file__).with_name("rotation_report.py")
        brief = subprocess.run([sys.executable, str(script)], capture_output=True,
                               text=True, check=True).stdout
        self.assertIn("partial", brief)
        self.assertIn("edge-a", brief)
        payload = subprocess.run([sys.executable, str(script), "--json"],
                                 capture_output=True, text=True, check=True).stdout
        parsed = json.loads(payload)
        self.assertEqual(parsed["services"][0]["stable_entries"], ["edge-a"])

    def test_client_filter_keeps_only_that_station(self):
        import subprocess
        import sys
        script = Path(__file__).with_name("rotation_report.py")
        payload = subprocess.run(
            [sys.executable, str(script), "--client", "stock-a", "--json"],
            capture_output=True, text=True, check=True).stdout
        parsed = json.loads(payload)
        entries = parsed["services"][0]["entries"]
        self.assertEqual([e["entry"] for e in entries], ["edge-a"])
        self.assertEqual(set(entries[0]["stations"]), {"stock-a"})
        # 收窄之后服务结论随剩下的入口重算，而不是沿用全局的 partial。
        self.assertEqual(parsed["services"][0]["status"], "proceed")

    def test_unknown_filter_is_rejected(self):
        import subprocess
        import sys
        script = Path(__file__).with_name("rotation_report.py")
        for flag, value in (("--entry", "nosuch"), ("--client", "nosuch")):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, str(script), flag, value],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("没有匹配", result.stderr)


if __name__ == "__main__":
    unittest.main()
