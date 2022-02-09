"""
#Author Mohamed F. Razzk
# applying yara rules to proccess
C-Date :07/02/2022
"""

import yara
import os
import fnmatch


# yarafolder = r'yararules'
# scanpath = '/home/razzk/PycharmProjects/SHYScanner/clean.txt'

def recscan(dirs, exet):
    listOfFiles = list()
    for (dirpath, dirnames, filenames) in os.walk(dirs):
        listOfFiles += [os.path.join(dirpath, file) for file in fnmatch.filter(filenames, exet)]

    return listOfFiles


def YaraRules(yarafolder):
    files = {}
    for x, i in enumerate(recscan(yarafolder, '*.yar')):
        files[str(x)] = str(i)

    return yara.compile(filepaths=files)

# def YaraScan(scanpath, yarafolder):
#     rules = YaraRules(yarafolder)
#     if os.path.isfile(scanpath):
#         matches = rules.match(scanpath)
#         if len(matches) > 0:
#             #print('\x1b[2;30;41m' + scanpath + '\x1b[0m' + " ---> " + '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m')
#             return True
#         else:
#             #print('\x1b[2;30;42m' + scanpath + '\x1b[0m' + " ---> " + '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m')
#             return False
#
#
#     elif os.path.isdir(scanpath):
#         listof = recscan(scanpath, '*')
#         for i in listof:
#             matches = rules.match(i)
#             if len(matches) > 0:
#                 print('\x1b[2;30;41m' + i + '\x1b[0m' + " ---> " + '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m')
#             else:
#                 print('\x1b[2;30;42m' + i + '\x1b[0m' + " ---> " + '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m')

# if __name__ == "__main__":
#     YaraScan()
