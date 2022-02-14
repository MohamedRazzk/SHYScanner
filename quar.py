import os
import fcntl
from array import array

quarntinedpath = 'malbase/quarantine.quar'

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x010


def quarData(execdata):
    if not os.path.exists(quarntinedpath):
        open(quarntinedpath, "w")

    with open(quarntinedpath) as file:
        quaritems = file.read().splitlines()
        if execdata in quaritems and os.path.exists(execdata):
            return True
        else:
            with open(quarntinedpath, 'a') as file:
                file.write(execdata+'\n')


def chattri(filename: str, value: bool):
    with open(filename, 'r') as f:
        arg = array('L', [0])
        fcntl.ioctl(f.fileno(), FS_IOC_GETFLAGS, arg, True)
        if value:
            arg[0] = arg[0] | FS_IMMUTABLE_FL
        else:
            arg[0] = arg[0] & ~ FS_IMMUTABLE_FL
        fcntl.ioctl(f.fileno(), FS_IOC_SETFLAGS, arg, True)


def quar(filepath):

    if not quarData(filepath):
        os.chown(filepath, 0, 0)
        os.chmod(filepath, 000)
        chattri(filepath, True)


# if __name__ == "__main__":
#     quar(filepath)
