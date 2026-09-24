"""
Port of Snaffler/Snaffler.cs + SnaffleRunner.Run() - the entry point.
"""
import os
import sys
import threading

from . import cli
from .concurrency import BlockingMq
from .context import ctx
from .core import SnaffCon
from .fs.local import LocalFileSystem
from .fs.routing import RoutingFileSystem
from .fs.smb import Credentials, SmbConnectionPool, SmbFileSystem
from .report import ResultCollector
from .runner import SnaffleRunner


def build_filesystem(options):
    """Wire up SMB and/or local access for whatever targets we were given."""
    needs_smb = True
    if options.PathTargets and options.ComputerTargets is None:
        # only local paths were asked for, so don't bother authenticating
        needs_smb = any(p.startswith("\\\\") for p in options.PathTargets)

    smb_fs = None
    if needs_smb:
        creds = Credentials(
            username=options.Username, password=options.Password,
            domain=options.Domain, lmhash=options.LmHash, nthash=options.NtHash,
            aes_key=options.AesKey, do_kerberos=options.DoKerberos,
            dc_ip=options.DcIp, port=options.SmbPort, timeout=options.SmbTimeout)

        per_host = options.MaxConnectionsPerHost
        if per_host <= 0:
            # enough for the tree and file workers that might hit one host at once
            per_host = max(2, min(16, options.MaxThreads // 4))

        pool = SmbConnectionPool(creds, max_per_host=per_host)
        ctx.SmbPool = pool
        smb_fs = SmbFileSystem(pool)

    return RoutingFileSystem(smb_fs=smb_fs, local_fs=LocalFileSystem())


def run(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    runner = SnaffleRunner()
    runner.print_banner()

    BlockingMq.make_mq()
    mq = BlockingMq.get_mq()

    try:
        options = cli.parse(argv)
        if options is None:
            return 0

        runner.configure(options)

        if options.Snaffle and options.SnafflePath and len(options.SnafflePath) > 4:
            os.makedirs(options.SnafflePath, exist_ok=True)

        ctx.MyOptions = options
        ctx.FileSystem = build_filesystem(options)

        collector = None
        if options.HtmlReportPath or options.JsonReportPath:
            command_line = "snaffler.py " + " ".join(argv)
            collector = ResultCollector(options, command_line)
            ctx.Collector = collector

        controller = SnaffCon(options)

        worker = threading.Thread(target=_execute, args=(controller, mq), daemon=True)
        worker.start()

        while True:
            if runner.handle_output():
                break

        if collector is not None:
            from datetime import datetime
            collector.end_time = datetime.now()
            if options.JsonReportPath:
                collector.write_json(options.JsonReportPath)
                print("Wrote JSON report to " + options.JsonReportPath)
            if options.HtmlReportPath:
                collector.write_html(options.HtmlReportPath)
                print("Wrote HTML report to " + options.HtmlReportPath)

        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(exc)
        dump_queue(mq)
        return 1
    finally:
        runner.close()
        try:
            if ctx.FileSystem is not None:
                ctx.FileSystem.close()
        except Exception:
            pass


def _execute(controller, mq):
    try:
        controller.execute()
    except Exception as exc:
        mq.error(str(exc))
        mq.terminate()


def dump_queue(mq):
    for message in mq.drain():
        if message.Message:
            print(message.Message)


def main():
    sys.exit(run())


if __name__ == "__main__":
    main()
