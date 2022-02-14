"""
#Author Mohamed F. Razzk
C-Date :05/02/2022
"""
from prg import *
from scnner import SigScan
from scnner import ProcScan_F
from scnner import FileScan_F
from scnner import Yscan
from scnner import Hscan
from scnner import FullScan
from ntwrk import nscan
from netmon import yaracapscan
import concurrent.futures


def main():
    operation, dirs, options = ArgParsing()
    if operation == 'scan':
        if not options.SignatureBase and not options.YaraRules and not options.hu:
            FullScan(dirs, options.full, options.quarantine)

        elif options.SignatureBase and not options.YaraRules and not options.hu:
            SigScan(dirs, options.SignatureBase)
            pass
        elif options.YaraRules and not options.SignatureBase and not options.hu:
            pass
            Yscan(dirs, options.YaraRules)

        elif options.hu and not options.SignatureBase and not options.YaraRules:
            Hscan(dirs)
            pass

    elif operation == 'start':
        with concurrent.futures.ProcessPoolExecutor() as executer:
            if options.full:
                options.killer = True
                options.remove = True
            executer.submit(ProcScan_F, options.killer)
            executer.submit(FileScan_F, options.remove)

    elif operation == 'net':
        if options.monitor:
            yaracapscan()
        else:
            while True:
                nscan()
                print('\n')


if __name__ == "__main__":
    main()
