"""
Port of SnaffCore/Concurrency - BlockingMq and the bounded, dynamically
rebalanced task schedulers.

The C# scheduler lets SnaffCon.StatusUpdate() move worker capacity between the
share/tree/file pools while the scan is running, so _max_parallelism has to
stay mutable here too.
"""
import queue
import threading
from collections import deque
from datetime import datetime
from enum import IntEnum


class SnafflerMessageType(IntEnum):
    Error = 0
    ShareResult = 1
    DirResult = 2
    FileResult = 3
    Finish = 4
    Info = 5
    Degub = 6
    Trace = 7
    Fatal = 8


class SnafflerMessage:
    __slots__ = ("DateTime", "Message", "Type", "FileResult", "ShareResult", "DirResult")

    def __init__(self, type, message=None, file_result=None, share_result=None,
                 dir_result=None, dt=None):
        self.DateTime = dt or datetime.now()
        self.Message = message
        self.Type = type
        self.FileResult = file_result
        self.ShareResult = share_result
        self.DirResult = dir_result


class BlockingMq:
    """Singleton message queue, same lifecycle as the C# (MakeMq/GetMq)."""

    _instance = None

    def __init__(self):
        self.Q = queue.Queue()

    @classmethod
    def make_mq(cls):
        cls._instance = BlockingMq()
        return cls._instance

    @classmethod
    def get_mq(cls):
        if cls._instance is None:
            cls._instance = BlockingMq()
        return cls._instance

    def _put(self, type, **kwargs):
        self.Q.put(SnafflerMessage(type, **kwargs))

    def terminate(self):
        self._put(SnafflerMessageType.Fatal, message="Terminate was called")

    def trace(self, message):
        self._put(SnafflerMessageType.Trace, message=message)

    def degub(self, message):
        self._put(SnafflerMessageType.Degub, message=message)

    def info(self, message):
        self._put(SnafflerMessageType.Info, message=message)

    def error(self, message):
        self._put(SnafflerMessageType.Error, message=message)

    def file_result(self, file_result):
        self._put(SnafflerMessageType.FileResult, file_result=file_result)

    def dir_result(self, dir_result):
        self._put(SnafflerMessageType.DirResult, dir_result=dir_result)

    def share_result(self, share_result):
        self._put(SnafflerMessageType.ShareResult, share_result=share_result)

    def finish(self):
        self._put(SnafflerMessageType.Finish)

    def consume(self):
        """GetConsumingEnumerable()."""
        while True:
            yield self.Q.get()

    def drain(self):
        while True:
            try:
                yield self.Q.get_nowait()
            except queue.Empty:
                return


class TaskCounters:
    __slots__ = ("TotalTasksQueued", "CurrentTasksQueued", "CurrentTasksRunning",
                 "CurrentTasksRemaining", "CompletedTasks", "MaxParallelism")

    def __init__(self):
        self.TotalTasksQueued = 0
        self.CurrentTasksQueued = 0
        self.CurrentTasksRunning = 0
        self.CurrentTasksRemaining = 0
        self.CompletedTasks = 0
        self.MaxParallelism = 0


class BlockingStaticTaskScheduler:
    """Bounded work queue with a concurrency limit that can change at runtime.

    new() blocks the calling thread while the backlog is at max_backlog, which
    is what stops the tree walkers from running the file queue away with them.
    """

    def __init__(self, threads, max_backlog, name="scheduler"):
        self._max_parallelism = max(0, int(threads))
        self._max_backlog = int(max_backlog)
        self._name = name
        self._tasks = deque()
        self._cond = threading.Condition()
        self._running = 0
        self._total_queued = 0
        self._workers = []
        self._shutdown = False
        self._counters = TaskCounters()

    # -- capacity knobs used by the status-update rebalancer -----------------
    @property
    def max_parallelism(self):
        return self._max_parallelism

    @max_parallelism.setter
    def max_parallelism(self, value):
        with self._cond:
            self._max_parallelism = max(0, int(value))
            self._cond.notify_all()
        self._ensure_workers()

    def _ensure_workers(self):
        with self._cond:
            needed = self._max_parallelism - len(self._workers)
            if needed <= 0 or self._shutdown:
                return
            for _ in range(needed):
                t = threading.Thread(target=self._worker, daemon=True,
                                     name="%s-%d" % (self._name, len(self._workers)))
                self._workers.append(t)
                t.start()

    def _worker(self):
        while True:
            with self._cond:
                while True:
                    if self._shutdown:
                        return
                    # honour the (possibly reduced) parallelism limit
                    if self._tasks and self._running < self._max_parallelism:
                        break
                    self._cond.wait(0.25)
                action = self._tasks.popleft()
                self._running += 1
                # a slot just freed up in the backlog
                self._cond.notify_all()
            try:
                action()
            except Exception:
                pass
            finally:
                with self._cond:
                    self._running -= 1
                    self._cond.notify_all()

    def new(self, action):
        """Queue work, blocking while the backlog is full (0 == unbounded)."""
        with self._cond:
            if self._max_backlog != 0:
                while (len(self._tasks) >= self._max_backlog and not self._shutdown):
                    self._cond.wait(0.1)
            self._tasks.append(action)
            self._total_queued += 1
            self._cond.notify_all()
        self._ensure_workers()

    def recalculate_counters(self):
        with self._cond:
            c = self._counters
            c.CurrentTasksQueued = len(self._tasks)
            c.CurrentTasksRunning = self._running
            c.TotalTasksQueued = self._total_queued
            c.CurrentTasksRemaining = c.CurrentTasksQueued + c.CurrentTasksRunning
            c.CompletedTasks = c.TotalTasksQueued - c.CurrentTasksRemaining
            c.MaxParallelism = self._max_parallelism
            return c

    def get_task_counters(self):
        return self._counters

    def done(self):
        c = self.recalculate_counters()
        return (c.CurrentTasksQueued + c.CurrentTasksRunning) == 0

    def shutdown(self):
        with self._cond:
            self._shutdown = True
            self._cond.notify_all()
