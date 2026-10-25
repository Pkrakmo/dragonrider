import unittest

from verify_srsc_read_helper_callers import EXPECTED_CALLERS, EXPECTED_SHA256
from verify_srsc_read_helper_ghidra_refs import verify_report


def report(addresses=None, *, sha256=EXPECTED_SHA256, ref_type="UNCONDITIONAL_CALL",
           truncated=False, declared=None):
    addresses = sorted(EXPECTED_CALLERS if addresses is None else addresses)
    rows = "\n".join(
        f"INFO TraceBoundedReadHelperRefs.java>   {address:08x} {ref_type} 0 (GhidraScript)"
        for address in addresses
    )
    count = len(addresses) if declared is None else declared
    truncation = "\nINFO TraceBoundedReadHelperRefs.java> TRUNCATED at 128 references" if truncated else ""
    return (
        "INFO TraceBoundedReadHelperRefs.java> edition=US retail; "
        f"sha256={sha256}; Ghidra=12.1.4; "
        "method=analyzed disposable import; read-only reference-manager query; "
        "confidence=database-dependent (GhidraScript)\n"
        "INFO TraceBoundedReadHelperRefs.java> REFERENCES_TO 0045f2d0\n"
        f"{rows}{truncation}\n"
        f"INFO TraceBoundedReadHelperRefs.java> COUNT {count} (GhidraScript)\n"
    )


class VerifySrscReadHelperGhidraRefsTests(unittest.TestCase):
    def test_accepts_exact_pinned_direct_call_set(self):
        result = verify_report(report())
        self.assertEqual(result["references"], 103)
        self.assertTrue(result["matched_objdump_addresses"])

    def test_rejects_missing_or_duplicate_reference(self):
        addresses = sorted(EXPECTED_CALLERS)
        with self.assertRaisesRegex(ValueError, "sets differ"):
            verify_report(report(addresses[:-1]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_report(report(addresses + [addresses[0]]))

    def test_rejects_wrong_hash_or_non_call_reference(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_report(report(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "non-call"):
            verify_report(report(ref_type="DATA"))

    def test_rejects_truncation_and_count_mismatch(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            verify_report(report(truncated=True))
        with self.assertRaisesRegex(ValueError, "count"):
            verify_report(report(declared=102))


if __name__ == "__main__":
    unittest.main()
