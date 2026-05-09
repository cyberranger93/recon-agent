import unittest

from recon_agent.report import generate_report


class ReportTests(unittest.TestCase):
    def test_generate_report_renders_ranked_findings(self):
        report = generate_report(
            "example.com",
            ["api.example.com"],
            [{"url": "https://api.example.com"}],
            [
                {
                    "template-id": "exposed-panel",
                    "info": {"severity": "high", "name": "Exposed Admin Panel", "tags": ["panel"]},
                    "host": "https://api.example.com",
                    "matched-at": "https://api.example.com/admin",
                    "_impact": "Could expose privileged administration functions.",
                }
            ],
        )

        self.assertIn("# Recon Report: `example.com`", report)
        self.assertIn("[HIGH] Exposed Admin Panel", report)
        self.assertIn("Could expose privileged administration functions.", report)


if __name__ == "__main__":
    unittest.main()
