"""
#Author Mohamed F. Razzk
# Monitoring Files and Classes
C-Date :07/02/2022
"""

import os
import psutil
import signal
from subprocess import check_output


def get_pid(name):
    # return int(check_output(["pidof",name]))
    return int(check_output(["pidof", "-s", name]))


def ProcessMonitor():
    processlist = list()
    for process in psutil.process_iter():
        if len(process.cmdline()) > 0:
            if (process.cmdline())[0] not in processlist and process.cmdline()[0][0] == '/' and os.path.isfile(
                    process.cmdline()[0]):
                processlist.append((process.cmdline())[0])

    return processlist


def KillProcTree(pname, sig=signal.SIGTERM, include_parent=True,
                 timeout=None, on_terminate=None):

    pid = get_pid(pname)

    assert pid != os.getpid(), "won't kill myself"
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    if include_parent:
        children.append(parent)
    for p in children:
        try:
            p.send_signal(sig)
        except psutil.NoSuchProcess:
            pass
    gone, alive = psutil.wait_procs(children, timeout=timeout,
                                    callback=on_terminate)
    return gone, alive

#
# if __name__ == "__main__":
#     p = ProcessMonitor()
#
#     for idx, val in enumerate(p):
#         print(get_pid(val), val)
#         # print(psutil.Process(get_pid(val)).kill())
#         # print(psutil.Process(83835).kill())
