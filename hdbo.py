"""
#Author Mohamed F. Razzk
# signature data base control for check matching and update signature
C-Date :05/02/2022
"""


class HashDb:

    def __init__(self, dbname, version):
        self.dbname = dbname
        self.version = version
        DbData = open(self.dbname, "r")
        self.readfile = DbData.read()

    def HashMatch(self, HashValue):

        if HashValue in self.readfile:
            return True
        else:
            return False

    def HashApen(self, HashValue):
        DbData = open(self.dbname, "a")
        DbData.write(HashValue)
        DbData.close()
