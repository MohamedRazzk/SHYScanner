"""
#Author Mohamed F. Razzk
# Scanner Class Have all function
C-Date :05/02/2022
"""

from prg import *
from hdbo import HashDb
from heucheck import HeurScan, heurchecking
from mon import ProcessMonitor
import watchdog.events
import watchdog.observers
from yarascan import YaraRules
import time
import fnmatch
from mon import KillProcTree

malwarebase = "malbase/sigbase.md5"  # defualt malware base signature
yarabase = 'yararules'  # defualt yararules Folder
src_pathz = r"/home"


class Handler(watchdog.events.PatternMatchingEventHandler):

    def __init__(self, RemoveOption):
        # Set the patterns for PatternMatchingEventHandler
        watchdog.events.PatternMatchingEventHandler.__init__(self, patterns=['*'],
                                                             ignore_directories=True, case_sensitive=False,
                                                             )
        self.signaturedb = HashDb(malwarebase, None)
        self.yararules = YaraRules(yarabase)
        self.RemoveOption = RemoveOption

    def on_created(self, event):
        if not '.cache' in event.src_path:
            if not '.config' in event.src_path:
                if not '/.' in event.src_path:
                    print("\x1b[0;33;40m" + "##################### File Monitor Scan ################## " + '\x1b[0m')
                    sigcheck = SignatureCheck(event.src_path, self.signaturedb)
                    huercheck = HuerstCheck(event.src_path)
                    yarcheck = YaraCheck(event.src_path, self.yararules)
                    printfunc(event.src_path, sigcheck, huercheck, yarcheck)
                    if self.RemoveOption:
                        if sigcheck or huercheck or yarcheck:
                            os.remove(event.src_path)


def diff(list1, list2):
    return list(set(list1).symmetric_difference(set(list2)))


def printfunc(file, Sig=None, Heur=None, Yara=None):
    print(file + ' --->', end=" ")
    inficted = '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m'
    clean = '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m'
    for i, v in locals().items():
        if v is True:
            print('\x1b[6;30;41m' + i + ':\x1b[0m' + inficted, end=" ")
        elif v is False:
            print('\x1b[2;30;42m' + i + ':\x1b[0m' + clean, end=" ")
    print()


def recscan(dirpath, exet):
    listOfFiles = list()
    for (dirpath, dirnames, filenames) in os.walk(dirpath):
        listOfFiles += [os.path.join(dirpath, file) for file in fnmatch.filter(filenames, exet)]

    return listOfFiles


def SignatureCheck(file, signaturedb):
    if signaturedb.HashMatch(GenerateMD5(file)):
        return True
    else:
        return False


def SigScan(dirs, sigbase):
    # file_info_dicts = RecScan(dirs)
    # signaturedb = HashDb(sigbase, None)
    # print("\x1b[0;32;40m" + "#####################  Signature Scan ################## " + '\x1b[0m')
    # if dirs == "file":
    #
    #     if signaturedb.HashMatch(GenerateMD5(file)):
    #         print('\x1b[2;30;41m' + os.path.abspath(
    #             file) + '\x1b[0m' + " ---> " + '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m')
    #     else:
    #         print('\x1b[2;30;42m' + os.path.abspath(
    #             file) + '\x1b[0m' + " ---> " + '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m')
    # else:
    #     for filename, d in sorted(iter(file_info_dicts.items())):
    #         if d['file'] and not d['md5']:
    #             if signaturedb.HashMatch(GenerateMD5(filename)):
    #                 print(
    #                     '\x1b[2;30;41m' + os.path.abspath(
    #                         filename) + '\x1b[0m' + " ---> " + '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m')
    #             else:
    #                 print('\x1b[2;30;42m' + os.path.abspath(
    #                     filename) + '\x1b[0m' + " ---> " + '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m')

    signaturedb = HashDb(sigbase, None)

    if os.path.isfile(dirs):
        printfunc(dirs, SignatureCheck(dirs, signaturedb))

    elif os.path.isdir(dirs):
        filelist = recscan(dirs, '*')
        for file in filelist:
            printfunc(file, SignatureCheck(file, signaturedb))


def HuerstCheck(file):
    if heurchecking(file):
        return HeurScan(file)


def Hscan(dirs):
    if os.path.isfile(dirs):
        printfunc(dirs, None, HuerstCheck(dirs))

    elif os.path.isdir(dirs):
        filelist = recscan(dirs, '*')
        for file in filelist:
            printfunc(file, None, HuerstCheck(file))


def YaraCheck(file, rules):
    matches = rules.match(file)

    if len(matches) > 0:
        return True
    else:
        return False


def Yscan(dirs, yarafolder):
    yararules = YaraRules(yarafolder)

    if os.path.isfile(dirs):
        printfunc(dirs, None, None, YaraCheck(dirs, yararules))

    elif os.path.isdir(dirs):
        filelist = recscan(dirs, '*')

        for file in filelist:
            printfunc(file, None, None, YaraCheck(file, yararules))


def ProcScanner(file, KillOption):
    print("\x1b[0;31;40m" + "##################### Process Monitor Scan ################## " + '\x1b[0m')
    signaturedb = HashDb(malwarebase, None)
    yararules = YaraRules(yarabase)

    for base in file:
        sigcheck = SignatureCheck(base, signaturedb)
        huercheck = HuerstCheck(base)
        yarcheck = YaraCheck(base, yararules)
        printfunc(base, sigcheck, huercheck, yarcheck)
        if KillOption:
            if sigcheck or huercheck or yarcheck:
                KillProcTree(base)


def FileScanner(RemoveOption):
    event_handler = Handler(RemoveOption)
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path=src_pathz, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


def ProcScan_F(KillOption):
    prev = ProcessMonitor()
    ProcScanner(ProcessMonitor(), KillOption)
    while True:
        current = ProcessMonitor()
        diff_list = diff(sorted(prev), sorted(current))

        if not any(item in diff_list for item in prev):

            if len(diff_list) == 0:
                # print("no diffrance")
                time.sleep(1)
            else:
                ProcScanner(diff_list, KillOption)
                prev = current
                time.sleep(1)
        else:
            prev = current


def FileScan_F(RemoveOption):
    FileScanner(RemoveOption)


def FullScan(dirs, FullOption):
    signaturedb = HashDb(malwarebase, None)
    yararules = YaraRules(yarabase)

    if os.path.isfile(dirs):
        sigcheck = SignatureCheck(dirs, signaturedb)
        huercheck = HuerstCheck(dirs)
        yarcheck = YaraCheck(dirs, yararules)
        printfunc(dirs, sigcheck, huercheck, yarcheck)
        if FullOption:
            if sigcheck or huercheck or yarcheck:
                os.remove(dirs)

    elif os.path.isdir(dirs):
        filelist = recscan(dirs, '*')

        for file in filelist:
            sigcheck = SignatureCheck(file, signaturedb)
            huercheck = HuerstCheck(file)
            yarcheck = YaraCheck(file, yararules)
            printfunc(file, sigcheck, huercheck, yarcheck)
            if FullOption:
                if sigcheck or huercheck or yarcheck:
                    os.remove(file)
