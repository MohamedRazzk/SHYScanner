"""
#Author Mohamed F. Razzk
#parcing , RecScan , MD5 Gen
C-Date :05/02/2022
"""
import hashlib
import optparse
import os
import os.path
import sys


def GenerateMD5(filename, block_size=2 ** 20):
    md5 = hashlib.md5()
    with open(filename, 'rb') as file:
        while True:
            data = file.read(block_size)
            if not data:
                break
            md5.update(data)

    return md5.hexdigest()


def ArgParsing():
    """Read command line arguments and determine operation and directories """

    # Define the options taken by the script
    parser = optparse.OptionParser(
        usage="\n\t%prog scan Directory \nOR\n\t%prog scan File\nOR\n\t%prog start",
    )
    parser.add_option(
        "-s", "--signature", dest="SignatureBase", type='string',
        default=False,
        help="scan Dir/File With Custom Hash Signature Base\n",
    )
    parser.add_option(
        "-y", "--yara", dest="YaraRules", type='string',
        default=False,
        help="scan Dir/File With Yara Rules\n",
    )
    parser.add_option("-e", "--heuristic", action="store_true", dest="hu", help="scan Executable File Heuristically\n")
    parser.add_option("-k", "--killer", action="store_true", dest="killer", help="kill malicious process in scanning "
                                                                                 "process\n")
    parser.add_option("-r", "--remove", action="store_true", dest="remove", help="remove file detected while program is"
                                                                                 "start monitor\n")
    parser.add_option("-f", "--full", action="store_true", dest="full", help="full monitoring detection and prevention"
                                                                             "kill mal-process and remove-file")
    # Parse options and read directory arguments from the command line
    (options, args) = parser.parse_args()

    if args[0] == 'start':
        return args[0], None, options

    if len(args) < 2:
        parser.print_help()
        sys.exit(1)

    # Check that the first argument is an operation to apply
    operation = args[0]
    if operation not in ('scan', 'start'):
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args[1]):
        print("\x1b[0;31;40m" + "Can't Recognize That File or Directory" + '\x1b[0m')
        parser.print_help()
        sys.exit(1)

    dirs = os.path.abspath(args[1])
    return operation, dirs, options


def RecScan(dirs):
    file_info_dicts = {}
    for dirp in dirs:
        for (dirpath, dirnames, filenames) in os.walk(dirp):
            for each_filename in filenames:
                full_file_path = os.path.join(dirpath, each_filename)
                is_md5_file = (full_file_path[-4:].lower() == '.md5')
                if is_md5_file:
                    key = full_file_path[:-4]
                else:
                    key = full_file_path

                d = file_info_dicts.setdefault(key, dict(file=False, md5=False))
                if is_md5_file:
                    d['md5'] = True
                else:
                    d['file'] = True

    files_found = 0
    md5_found = 0
    both_found = 0
    for file_name, d in iter(file_info_dicts.items()):
        if d['md5'] and d['file']:
            both_found += 1
        elif d['file']:
            files_found += 1
        elif d['md5']:
            md5_found += 1

    return file_info_dicts
