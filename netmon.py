"""
#Author Mohamed F. Razzk
# applying yara rules to proccess
C-Date :12/02/2022
"""

from scapy.all import *
from binascii import hexlify
from yarascan import YaraRules

inficted = '\x1b[6;30;41m' + 'Infected ✗ ' + '\x1b[0m'
clean = '\x1b[2;30;42m' + 'Clean ✔ ' + '\x1b[0m'

yarapcap = 'yarapcap'
yararules = YaraRules(yarapcap)


def analyzier(packet):
    hexpacket = hexlify(bytes(packet))
    matches = yararules.match(data=hexpacket)
    if len(matches) > 0:
        print(packet.summary() + '  ' + inficted)
    else:
        print(packet.summary() + '  ' + clean)

    # s= packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")
    # print(s)

    # capture = StringIO()
    # save_stdout = sys.stdout
    # sys.stdout = capture
    # packet.show()
    # sys.stdout = save_stdout
    # print(packet.summary())
    # s = packet.sprintf("{Raw:%Raw.load%}\n")
    # print(bytes(s))
    # #print(bytes(packet.sprintf("{Raw:%Raw.load%}\n")))
    # #print(capture.getvalue())

    # if http_packet.find('GET'):
    #     return GET_print(packet)

def yaracapscan():
    sniff(prn=analyzier)
