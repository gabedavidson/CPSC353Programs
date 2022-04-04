from DataCommsPrograms.NetworkBroadcastCalculator import NetBroadCalc, ForwardTableCalc


def main():
    network_address = "10.0.138.219"
    subnet_address = "255.255.192.0"
    calc = NetBroadCalc()
    calc.solve(network_address, subnet_address)
    # calc = ForwardTableCalc()
    # destinations = [
    #     '214.97.254.20',
    #     '214.97.254.12',
    #     '224.64.27.1',
    #     '224.70.128.65',
    #     '224.192.116.1',
    #     '196.107.49.46'
    # ]
    # addresses = [
    #     '224.0.0.0',
    #     '224.64.0.0',
    #     '224.64.0.0',
    #     '214.97.253.0',
    #     '214.97.254.8',
    #     '214.97.254.0',
    #     '0.0.0.0'
    # ]
    # table = {
    #     '255.0.0.0': 'eth1',
    #     '255.255.0.0': 'eth2',
    #     '255.192.0.0': 'eth3',
    #     '255.255.255.0': 'eth4',
    #     '255.255.255.248': 'eth5',
    #     '255.255.255.224': 'eth6',
    #     '0.0.0.0': 'eth3'
    # }
    # print(calc.solve(addresses, table, destinations, False, False))


if __name__ == "__main__":
    main()

# print(type("{0:b}".format(224)))
