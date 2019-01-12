#!/usr/bin/env python3
# https://github.com/digineo/ansible-ipcalc
#
# save this file in $ansible/filter_plugins/
#
# example usage in a jinja2 template:
# {% set network = "172.16.0.1/24" | ipcalc %}
#
# {{ "192.168.0.1" | ipadd(3) }} == "192.168.0.4"
# {{ "fe80::" | ipadd("::3") }} == "fe80::3"
#

import ipcalc


class FilterModule(object):
    def filters(self):
        return {
            "ipcalc": self.ipcalc,
            "ipadd":  self.ipadd,
            "getoctet": self.getoctet,
            "getquad": self.getquad,
            "getmacid": self.getmacid,
            "makefastdport": self.makefastdport,
            "makemeshbssid": self.makemeshbssid,
        }

    def ipcalc(self, value):
        net = ipcalc.Network(value)
        result = {
            'version': net.version(),
            'netmask': str(net.netmask()),
            'subnet': net.subnet(),
            'size': net.size(),
        }

        if net.version() == 6:
            result['network'] = net.network().to_compressed()
            result['host_min'] = net.host_first().to_compressed()
            result['host_max'] = net.host_last().to_compressed()
        if net.version() == 4:
            result['network'] = str(net.network())
            result['host_min'] = str(net.host_first())
            result['host_max'] = str(net.host_last())
            result['broadcast'] = str(net.broadcast())

        return result

    # Add two addresses
    # works for IPv4 and IPv6
    def ipadd(self, one, another):
        version = 6 if (':' in one) else 4
        addr = ipcalc.IP(ipcalc.IP(one).ip +
                         ipcalc.IP(another).ip, version=version)
        if addr.version() == 6:
            return addr.to_compressed()
        else:
            return str(addr)

    def getoctet(self, value, num, expand=False):
        addr = ipcalc.IP(value)

        if addr.version() == 4 and 0 < num < 5:
            return str(addr).split('.')[num - 1]
        if addr.version() == 6 and 0 < num < 9:
            quad = str(addr).split(':')[num - 1]
            if quad == '0000':
                return 0
            if not expand:
                return quad.lstrip('0')
            else:
                return quad

        return

    def getquad(self, value, num):
        return self.getoctet(value, num)

    def getmacid(self, value, num):
        octet = int(self.getoctet(value, num))
        if octet > 99:
            return "%02x" % octet
        else:
            return octet

    def makefastdport(self, subnet):
        net = ipcalc.Network(subnet)
        if net.version() != 4:
            raise Exception("Function requires IPv4 Subnet as input")

        octet = int(self.getoctet(subnet, 2))

        return (net.subnet() - 1) * 1000 + octet

    def makemeshbssid(self, prefix, meshcompat, areacode):
        # Example:
        # Prefix: 02:ca:fe
        # Meshcompat: 15
        # Areacode: 214
        # 02:ca:fe:15:02:14
        bssid = prefix
        if prefix[len(prefix)-1] != ':':
            bssid += ':'
        bssid += str(meshcompat).zfill(2) + ':'

        areacode = str(areacode)
        if len(areacode) < 2:
            raise Exception("Areacode is invalid")
        elif len(areacode) == 2:
            bssid += '00:' + areacode[0:2]
        elif len(areacode) == 3:
            bssid += '0' + areacode[0] + ':' + areacode[1:3]
        elif len(areacode) == 4:
            bssid += areacode[0:2] + ':' + areacode[2:4]

        return bssid
