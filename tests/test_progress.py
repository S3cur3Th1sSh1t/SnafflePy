"""
The heartbeat must stay strictly cosmetic: on a TTY only, erased before every
real log line, and never a byte in a redirected stdout or the logfile.
"""
import io
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnaffler.concurrency import BlockingStaticTaskScheduler
from pysnaffler.context import ctx
from pysnaffler.progress import Heartbeat, _elapsed


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class ElapsedTests(unittest.TestCase):
    def test_formats_as_hours_minutes_seconds(self):
        self.assertEqual(_elapsed(0), "00:00:00")
        self.assertEqual(_elapsed(61.9), "00:01:01")
        self.assertEqual(_elapsed(3725), "01:02:05")


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.stream = FakeTty()
        self.beat = Heartbeat(self.stream, threading.Lock())
        self.beat._started = 0.0
        self._saved = (ctx.ShareTaskScheduler, ctx.TreeTaskScheduler,
                       ctx.FileTaskScheduler)

    def tearDown(self):
        (ctx.ShareTaskScheduler, ctx.TreeTaskScheduler,
         ctx.FileTaskScheduler) = self._saved

    def install_schedulers(self):
        ctx.ShareTaskScheduler = BlockingStaticTaskScheduler(0, 0, "share")
        ctx.TreeTaskScheduler = BlockingStaticTaskScheduler(0, 0, "tree")
        ctx.FileTaskScheduler = BlockingStaticTaskScheduler(0, 0, "file")

    def test_draws_nothing_before_the_schedulers_exist(self):
        ctx.ShareTaskScheduler = None
        self.assertIsNone(self.beat._compose())

    def test_line_reports_queue_depth_and_findings(self):
        self.install_schedulers()
        for _ in range(3):
            ctx.FileTaskScheduler.new(lambda: None)
        self.beat.found = 7

        line = self.beat._compose()
        self.assertIn("snafflin'", line)
        self.assertIn("files 0/3", line)
        self.assertIn("found 7", line)

    def test_erase_is_a_no_op_until_something_was_drawn(self):
        self.beat.erase()
        self.assertEqual(self.stream.getvalue(), "")

    def test_draw_then_erase_leaves_the_line_clear(self):
        self.install_schedulers()
        self.beat._draw(self.beat._compose())
        self.assertTrue(self.beat._shown)
        self.assertIn("snafflin'", self.stream.getvalue())

        self.beat.erase()
        self.assertFalse(self.beat._shown)
        self.assertTrue(self.stream.getvalue().endswith("\r\x1b[K"))

    def test_line_is_kept_inside_the_terminal(self):
        self.install_schedulers()
        os.environ["COLUMNS"] = "40"
        try:
            self.beat._draw("x" * 200)
        finally:
            del os.environ["COLUMNS"]
        drawn = self.stream.getvalue().replace("\r\x1b[K", "")
        self.assertLessEqual(len(drawn), 39)

    def test_stop_without_start_does_not_raise(self):
        self.beat.stop()


class RunnerWiringTests(unittest.TestCase):
    """configure() decides whether a run gets a heartbeat at all."""

    def configure_with(self, stream, **overrides):
        from pysnaffler.options import Options
        from pysnaffler.runner import SnaffleRunner

        options = Options()
        for key, value in overrides.items():
            setattr(options, key, value)

        runner = SnaffleRunner()
        saved = sys.stdout
        sys.stdout = stream
        try:
            runner.configure(options)
        finally:
            sys.stdout = saved
        self.addCleanup(runner.close)
        return runner

    def test_no_heartbeat_when_stdout_is_redirected(self):
        """A piped run must not get a single control byte."""
        runner = self.configure_with(io.StringIO())
        self.assertIsNone(runner._heartbeat)

    def test_no_heartbeat_when_console_logging_is_off(self):
        runner = self.configure_with(FakeTty(), LogToConsole=False)
        self.assertIsNone(runner._heartbeat)

    def test_heartbeat_on_an_interactive_console(self):
        runner = self.configure_with(FakeTty())
        self.assertIsNotNone(runner._heartbeat)

    def test_log_writes_erase_the_line_first(self):
        from pysnaffler.runner import INFO

        stream = FakeTty()
        runner = self.configure_with(stream)
        runner._heartbeat._started = 0.0
        runner._heartbeat._shown = True   # pretend a tick already drew it

        stream.truncate(0)
        stream.seek(0)
        runner._write(INFO, "[Info] a real log line")
        self.assertTrue(stream.getvalue().startswith("\r\x1b[K"))


if __name__ == "__main__":
    unittest.main()
