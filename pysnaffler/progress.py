"""
A transient console heartbeat, so a running scan doesn't look hung.

SnaffCon.status_update() only fires every -e minutes (5 by default), and between
ticks the console is silent unless a file happens to hit a rule. This draws a
single line in place on a TTY and erases it before every real log line, so
nothing it writes ever reaches a redirected stdout, the logfile or the reports:
the log stream stays byte-identical to upstream Snaffler's.
"""
import itertools
import shutil
import threading
import time

from .context import ctx

_FRAMES = "|/-\\"

# \r to column 0, then erase to end of line.
_CLEAR = "\r\x1b[K"


def _elapsed(seconds):
    hours, rem = divmod(int(seconds), 3600)
    minutes, secs = divmod(rem, 60)
    return "%02d:%02d:%02d" % (hours, minutes, secs)


class Heartbeat:
    """One status line, redrawn in place on its own thread."""

    def __init__(self, stream, lock, interval=0.25):
        self._stream = stream
        self._lock = lock
        self._interval = interval
        self._frames = itertools.cycle(_FRAMES)
        self._stop = threading.Event()
        self._thread = None
        self._shown = False
        self._started = None
        self.found = 0

    def start(self):
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="heartbeat")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        with self._lock:
            self.erase()

    def erase(self):
        """Wipe the line. The caller must hold the runner's output lock."""
        if not self._shown:
            return
        self._shown = False
        try:
            self._stream.write(_CLEAR)
            self._stream.flush()
        except (OSError, ValueError):
            pass

    # -- internals -----------------------------------------------------------
    def _loop(self):
        while not self._stop.wait(self._interval):
            # Snapshot the schedulers before taking the output lock: the pump
            # thread takes the output lock and never a scheduler's, so keeping
            # the two orders apart means they can never deadlock.
            text = self._compose()
            if text is None:
                continue
            with self._lock:
                if self._stop.is_set():
                    return
                self._draw(text)

    def _compose(self):
        share, tree, files = (ctx.ShareTaskScheduler, ctx.TreeTaskScheduler,
                              ctx.FileTaskScheduler)
        if share is None or tree is None or files is None:
            return None   # SnaffCon hasn't built them yet

        # recalculate_counters() hands back a shared mutable object, so read the
        # fields out of it immediately rather than holding on to it.
        counters = share.recalculate_counters()
        hosts_done, hosts_total = counters.CompletedTasks, counters.TotalTasksQueued
        counters = tree.recalculate_counters()
        dirs_done, dirs_total = counters.CompletedTasks, counters.TotalTasksQueued
        counters = files.recalculate_counters()
        files_done, files_total = counters.CompletedTasks, counters.TotalTasksQueued

        return ("  snafflin' %s | hosts %d/%d | dirs %d/%d | files %d/%d | "
                "found %d %s" % (_elapsed(time.monotonic() - self._started),
                                 hosts_done, hosts_total, dirs_done, dirs_total,
                                 files_done, files_total, self.found,
                                 next(self._frames)))

    def _draw(self, text):
        # A line that wraps leaves the cursor on the next row, where \r can no
        # longer reach the start of it, so keep it inside the terminal.
        width = shutil.get_terminal_size((80, 24)).columns
        try:
            self._stream.write(_CLEAR + text[:max(0, width - 1)])
            self._stream.flush()
        except (OSError, ValueError):
            return
        self._shown = True
