"""
#Author Mohamed F. Razzk
# executable heuristic check
C-Date :06/02/2022
"""
import os
import csv

from prg import GenerateMD5


def heurchecking(file):
    name, extension = os.path.splitext(file)
    exts = ['.sh', '.exe', '.msi', '.dep', '']
    if extension in exts:
        return True
    else:
        return False


def GetExcutableData(scandir):
    ExecData = []
    if heurchecking(scandir):
        # else:
        #     exts = ['*.sh', '*.exe', '*.msi', '*.dep']
        #     files = [f for ext in exts
        #              for f in glob.glob(os.path.join(start_dir, '**', ext), recursive=True)]

        # HeurisData = []
        # for p in files:
        #     ExecSize = os.path.getsize(p)
        #     ExecModi = os.path.getmtime(p)
        #     Md5hash = GenerateMD5(p)
        #     ExecData = [p, ExecSize, ExecModi, Md5hash]
        #     HeurisData.append(ExecData)
        ExecSize = os.path.getsize(scandir)
        ExecModi = os.path.getmtime(scandir)
        Md5hash = GenerateMD5(scandir)
        ExecData = [scandir, ExecSize, ExecModi, Md5hash]
    return ExecData


def SavExecutbleData(execdata):
    if not os.path.exists("malbase/Heuristic.dat"):
        open("malbase/Heuristic.dat", "w")

    with open("malbase/Heuristic.dat") as file:
        heurlist = file.read().splitlines()
        orginalheur = []
        for each in heurlist:
            items = each.split(',')
            orginalheur.append(items)

    with open(r"malbase/Heuristic.dat", 'a') as file:
        writer = csv.writer(file)

        flag = False
        for o in orginalheur:
            if execdata[0] == o[0]:
                flag = True
        if flag == False:
            writer.writerow(execdata)


def Heurchanges(scandir):
    with open("malbase/Heuristic.dat") as file:
        heurlist = file.read().splitlines()
    orginalheur = []
    for each in heurlist:
        items = each.split(',')
        orginalheur.append(items)

    currheur = GetExcutableData(scandir)

    for o in orginalheur:
        if currheur[0] == o[0]:
            # name matched
            if (str(currheur[1]) != str(o[1])) or str(currheur[2]) != str(o[2] or str(currheur[3]) != str(o[3])):
                return True
            else:
                return False


def HeurScan(scandir):
    SavExecutbleData(GetExcutableData(scandir))
    return Heurchanges(scandir)

# if __name__ == "__main__":
#     HeurScan('/home/razzk/PycharmProjects/SHYScanner/venv')
