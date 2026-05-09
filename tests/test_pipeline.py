import unittest

from recon_agent.pipeline import build_nuclei_command


class PipelineTests(unittest.TestCase):
    def test_build_nuclei_command_uses_file_path(self):
        command = build_nuclei_command("targets.txt", "medium,high")

        self.assertEqual(command[0], "nuclei")
        self.assertIn("-l", command)
        self.assertEqual(command[-1], "targets.txt")
        self.assertNotIn("/dev/stdin", command)


if __name__ == "__main__":
    unittest.main()
