def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

ServiceProtocol = enum(ip=0, icmp=1, tcp=6, udp=17, eigrp=88)

GraphAttribute = enum(Type='type', Service='service',  Label='label', SubnetIpAddress='subnetip', SubnetMask='mask', IpAddress='ipaddress', VlanId='vlanid', HostIds='hostids', SwitchIds='switchids', RouterIds='routerids', InterfaceIds='interfaceids' ,ServerIds='serverids' )
SecurityElement = enum(Conduit="conduit", Zone="zone")
RuleEffect = enum(Permit=1, Deny=2)
RuleOperation = enum(Exclude=1, Intersect=2)
RuleInteractionType = enum(PartialOverlap=1, Conflict=2, Shadow=3, Generalisation=4)