import math as m


# calculates network, broadcast, and CIDR addresses
class NetBroadCalc:
    def __init__(self):
        self.octets = []
        self.limit = 0
        self.degree = 0
        self.pos = 0
        self.network_address = []
        self.broadcast_address = []
        self.cidr_address = []

    def clean(self):
        self.octets.clear()
        self.limit = 0
        self.degree = 0
        self.pos = 0
        self.network_address.clear()
        self.broadcast_address.clear()
        self.cidr_address.clear()

    def solve(self, address: str, subnet: str, _ret=False, _retb=False):
        # print("Address: " + address)
        # print("Subnet address: " + subnet + '\n')
        self.parse_octets(address, subnet)
        self.network_address = [x for x in self.octets]
        self.broadcast_address = [x for x in self.octets]
        self.solve_octet(subnet)
        if not _ret and not _retb:
            self.print_results()
        else:
            if _ret and not _retb:
                return self.format_address(self.network_address), self.format_address(self.cidr_address)
            elif not _ret and _retb:
                return self.format_address(self.broadcast_address)
            elif _ret and _retb:
                return self.format_address(self.network_address), self.format_address(self.broadcast_address), self.format_address(self.cidr_address)

    def parse_octets(self, address: str, subnet: str):
        subnet_octets = subnet.split('.')
        add_octets = address.split('.')
        for i in range(len(subnet_octets)):
            if subnet_octets[i] == '255':
                self.octets.append(add_octets[i])
            else:
                try:
                    if int(subnet_octets[i]) > 255:
                        raise Exception("Value at", i, " must be <=255.")
                    else:
                        self.degree = self.get_degree(subnet_octets[i])
                        self.limit = int(add_octets[i])
                        self.pos = i
                        return
                except ValueError:
                    raise Exception("Error occurred while parsing octet")

    def solve_octet(self, sub):
        lower = [0, 127]
        upper = [128, 255]
        working_range = [0, 255]
        for i in range(self.degree):
            if self.get_range(lower, upper) == 0:
                lower, upper, working_range = self.update_range(lower)
            elif self.get_range(lower, upper) == 1:
                lower, upper, working_range = self.update_range(upper)
            else:
                raise Exception("Error occurred while solving octet.")
        network_value = working_range[0]
        broadcast_value = working_range[1]
        self.network_address.append(network_value)
        self.broadcast_address.append(broadcast_value)
        self.finish_network_octet()
        self.finish_broadcast_octet()
        self.finish_cidr_octet(sub)

    def finish_network_octet(self):
        if len(self.network_address) < 4:
            for i in range(4-len(self.network_address)):
                self.network_address.append('0')

    def finish_broadcast_octet(self):
        if len(self.broadcast_address) < 4:
            for i in range(4-len(self.broadcast_address)):
                self.broadcast_address.append('255')

    def finish_cidr_octet(self, sub):
        self.cidr_address = [x for x in self.network_address]
        self.cidr_address.append(self.get_cidr_attr(sub))

    def get_cidr_attr(self, sub):
        count = 0
        for num in sub.split('.'):
            if num != 0:
                count += self.get_degree(num)
        return count

    @staticmethod
    def to_8b_binary(num):
        try:
            working = int(num)
            curr_bin = "{0:b}".format(working)
            if len(curr_bin) < 8:
                curr_bin.zfill(8 - len(curr_bin))
            elif len(curr_bin) > 8:
                return curr_bin[:8]
            return curr_bin
        except ValueError:
            return '00000000'

    def get_degree(self, bin_num):
        return self.to_8b_binary(bin_num).count('1')

    def get_range(self, lower, upper):
        if self.limit <= lower[1]:
            return 0
        elif self.limit <= upper[1]:
            return 1
        else:
            return -1

    @staticmethod
    def update_range(curr_range):
        return [curr_range[0], m.floor((curr_range[0] + curr_range[1]) / 2)], [m.ceil((curr_range[0] + curr_range[1]) / 2), curr_range[1]], [curr_range[0], curr_range[1]]

    def print_results(self):
        print("Network:", self.format_address(self.network_address))
        print("Broadcast:", self.format_address(self.broadcast_address))
        print("CIDR:", self.format_address(self.cidr_address))

    @staticmethod
    def format_address(ip):
        address = ""
        for i in range(len(ip)):
            address += str(ip[i])
            if len(ip) != 5:
                if i != (len(ip) - 1):
                    address += '.'
            else:
                if i != len(ip) - 2:
                    address += '.'
                else:
                    address += '/'
        if len(ip) == 5:
            address = address[:-1]
        return address


# Calculates forwarding table
class ForwardTableCalc:
    def __init__(self):
        self.nbc = NetBroadCalc()
        self.addresses = []
        self.genmasks = []
        self.interfaces = []
        self.broadcast_addresses = []
        self.destinations = {}

    def solve(self, addresses: list[str], table, destinations=None, _ret=False, _reti=False):
        """
        :param addresses: list –> list of addresses to work on
        :param table:
            :list –> list of lines in table where each item in the list is a dictionary
            :dict –> dict of genmask : interface key value pairs
        :param destinations:
            :None –> no destinations
            :list –> list of destination addresses to qualify interfaces for
        :param _ret: bool –> should return
            –> if destinations is None then returns broadcast values only
        :param _reti: bool –> should return only intercepts
        :return: ...
        """
        if isinstance(table, list):
            self.parse_complete(table)
        elif isinstance(table, dict):
            self.parse_partial(table)
        else:
            raise Exception("Non-admittable type as ForwardTableCalc.Solve() parameter.")

        for i in range(len(addresses)):
            self.addresses.append(addresses[i])
        for i in range(len(self.addresses)):
            self.addresses.append(addresses[i])
            self.broadcast_addresses.append(self.nbc.solve(self.addresses[i], self.genmasks[i], False, True))
            self.nbc.clean()
        if destinations is None and _ret and not _reti:
            return self.broadcast_addresses

        for destination in destinations:
            print(destination)
            self.destinations[destination] = self.find_interface(destination)

        if _ret and _reti:
            return self.broadcast_addresses, self.destinations
        elif _ret and not _reti:
            return self.broadcast_addresses
        elif not _ret and _reti:
            return self.destinations
        elif not _ret and not _reti:
            if destinations is None:
                self.print_results()
            else:
                self.print_results()

    def find_interface(self, dest: str):
        print('finding interface')
        possible_interfaces = []
        for i in range(len(self.broadcast_addresses)):
            print(i)
            if self.fits_in_range(dest, self.addresses[i], self.broadcast_addresses[i]):
                print('fits')
                possible_interfaces.append(i)
            if len(possible_interfaces) == 1:
                break
        if len(possible_interfaces) == 1:
            print('found one suitable interface')
            print('–––––––', possible_interfaces[0])
            return self.interfaces[possible_interfaces[0]]
        print('found >1 suitable interfaces')
        return self.interfaces[self.find_most_fit(possible_interfaces)]

    def find_most_fit(self, interfaces: list[int]):
        most_degree = 0
        best_fit = 0
        for index in interfaces:
            degree = 0
            for octet in self.genmasks[index].split('.'):
                degree += self.nbc.get_degree(octet)
            if degree > most_degree:
                most_degree = degree
                best_fit = index
        return best_fit

    @staticmethod
    def fits_in_range(dest, add, broad):
        print(dest, add, broad)
        for i in range(4):
            print('----', i)
            if int(dest.split('.')[i]) >= int(add.split('.')[i]):
                if int(dest.split('.')[i]) <= int(broad.split('.')[i]):
                    continue
                else:
                    print('interface not found')
                    return False
            else:
                print('interface not found')
                return False
        print('interface found')
        return True

    def parse_partial(self, table: dict):
        # table –> genmask : interface
        for genmask, interface in table.items():
            self.genmasks.append(genmask)
            self.interfaces.append(interface)

    def parse_complete(self, table: list[dict]):
        # table –> [{key : val, ...}, ...]
        for item in table:
            for key, val in item.items():
                if key.lower() == "genmask":
                    self.genmasks.append(val)
                elif key.lower() == "iface":
                    self.interfaces.append(val)

    def print_results(self, interfaces=False):
        self.print_addresses()
        if interfaces:
            self.print_dest_interfaces()

    def print_addresses(self):
        for i in range(len(self.broadcast_addresses)):
            print(self.addresses[i], "–––>", self.broadcast_addresses[i])

    def print_dest_interfaces(self):
        for dest, interface in self.destinations.items():
            print(dest, "–––>", interface)

