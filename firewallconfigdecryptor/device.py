class Firewall(object):
    def __init__(self, name):
        self.name = name
        self.interface_list = dict()

    def UpdateInterfaceACLs(self, acls_used):
        for acl_name in acls_used.keys():
            for interface in acls_used[acl_name]:
                if self.interface_list.has_key(interface.interface_name):
                    self.interface_list[interface.interface_name].acl[interface.acl_direction] = acl_name

    @property
    def interfaces(self):
        return self.interface_list

    @interfaces.setter
    def interfaces(self, interfaces):
        self.interface_list = interfaces

class Gateway(object):
    def __init__(self, gateway_ipaddress, connected_network_addresses):
        self.gateway_ipaddress = gateway_ipaddress
        self.connected_network_addresses = connected_network_addresses

    @property
    def ipaddress(self):
        return self.gateway_ipaddress

    @property
    def network_addresses(self):
        return self.connected_network_addresses

class FirewallInterface(object):
    def __init__(self, type=None, name=None, description=None, ip_address=None, security_level=-1):
        self.type=type
        self.name = name
        self.description = description
        self.ip_address= ip_address
        self.security_level = security_level
        self.acl_lookup = dict()

    @property
    def acl(self):
        return self.acl_lookup

    @acl.setter
    def acl(self, acl_name, direction):
        self.acl_lookup[direction] = acl_name

