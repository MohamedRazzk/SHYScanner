"""
#Author Mohamed F. Razzk
# applying yara rules to proccess
C-Date :12/02/2022
"""
from nmap import PortScanner


class Network(object):
    def __init__(self):
        self.ip = input('Please input network IP: ')

        resp = input("""\nPlease Enter Scan Type :
                             1:Hosts Scan
                             2:SYN ACK Scan
                             3:UDP Scan
                             4:Comprehensive Scan
                             5:Vulnerabilities Scan
Scan Type: """)

        self.resp_dict = {'1': '-sn', '2': '-v -sS', '3': '-v -sU', '4': '-v -sS -sV -sC -A -O',
                          '5': '-Pn -sV --script=vulners'}

        if resp not in self.resp_dict.keys():
            print("Wrong Operation Selected ")
            exit(1)
        self.operation = (self.resp_dict[resp])

    def get_devices(self):

        if self.operation == '-sn':
            prefix = input('Please input network Prefix[i.e /24] or Range: -100: ')
            network_to_scan = self.ip + prefix
        else:
            network_to_scan = self.ip

        # print(self.ip)
        # print(self.operation)

        p_scanner = PortScanner()

        print('Scanning {}...'.format(network_to_scan))
        p_scanner.scan(hosts=network_to_scan, arguments=self.operation)
        # device_list = [(device, p_scanner[device]) for device in p_scanner.all_hosts()]
        device_list = [p_scanner[device] for device in p_scanner.all_hosts()]
        return device_list


def nscan():
    network = Network()
    devices = network.get_devices()
    # print(devices)

    for device in devices:
        # print(device)
        print('\n')
        for instance in device:
            if instance in ['tcp', 'udp']:
                print("\x1b[0;35;20m" + "######### {} Port ###########".format(instance.upper()) + '\x1b[0m')
                for devsli in device[instance]:
                    if 'script' in device[instance][devsli]:
                        new = device[instance][devsli]['script']
                        del device[instance][devsli]['script']
                        print(
                            "\x1b[0;31;40m" + 'Port: {} ----> {} '.format(devsli, device[instance][devsli]) + '\x1b[0m')
                        for i in new:
                            print(new[i])
                        print()

                    else:
                        print('Port: {} ----> {} '.format(devsli, device[instance][devsli]))
                print("\x1b[0;35;20m" + "######### {} Port ###########".format(instance.upper()) + '\x1b[0m')
            else:
                print('{} ----> {} '.format(instance.upper(), device[instance]))


# if __name__ == "__main__":
#     while True:
#         nscan()
#         print('\n')
#     # for devic in devices:
#     #     print(devic[1]['hostnames'])
#     #     print(devic[1]['addresses'])
#     #     print(devic[1]['vendor'])
#     #     print(devic[1]['status'])
#     #     print()
#     # # mapscanner()
