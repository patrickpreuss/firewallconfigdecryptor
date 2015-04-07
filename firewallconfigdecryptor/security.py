import ipaddr
from enums import ServiceProtocol

class InterfaceACL:
    def __init__(self, interface_name=None, acl_direction=None, acl_name=None):
        self.acl_name = acl_name
        self.acl_direction = acl_direction
        self.interface_name =interface_name
        self.entries_post_intra_acl_filtering = None
        self.intra_acl_interactions = None
        self.entries_post_inter_acl_filtering = None
        self.inter_acl_interactions = None

class ACL:
    def __init__(self, acl_name=None, entry_list=None):
        self.name = acl_name
        self.entry_list = entry_list
        self.entries_post_intra_acl_filtering = None
        self.entries_post_inter_acl_filtering = None
        self.intra_acl_interactions = None
        self.inter_acl_interactions = None

    @property
    def Entries(self):
        return self.entry_list

    @Entries.setter
    def Entries(self, entry_list):
        self.entry_list = entry_list

    @property
    def EntriesPostIntraACLFiltering(self):
        return self.entries_post_intra_acl_filtering

    @property
    def EntriesPostInterACLFiltering(self):
        return self.entries_post_inter_acl_filtering

    @EntriesPostIntraACLFiltering.setter
    def EntriesPostIntraACLFiltering(self, entries_list):
        self.entries_post_intra_acl_filtering = entries_list

    @EntriesPostInterACLFiltering.setter
    def EntriesPostInterACLFiltering(self, entries_list):
        self.entries_post_inter_acl_filtering = entries_list

    @property
    def IntraACLInteractions(self):
        return self.intra_acl_interactions

    @IntraACLInteractions.setter
    def IntraACLInteractions(self, entries_list):
        self.intra_acl_interactions = entries_list

    @property
    def InterACLInteractions(self):
        return self.inter_acl_interactions

    @InterACLInteractions.setter
    def InterACLInteractions(self, entries_list):
        self.inter_acl_interactions = entries_list

class SecurityZone:
    def __init__(self,zone_id,ipaddress_list,primary_firewall_name):
        self.zone_id = zone_id
        self.ipaddress_list = ipaddress_list
        self.sub_elements = dict()
        self.gateways = []
        self.primary_firewall_name = primary_firewall_name
        self.excluded_elements = dict()

    def ContainsSubnetOrIpaddress(self,subnet_or_ip):
        included = False
        if isinstance(subnet_or_ip, list):
            # All elements of list must be included
            inclusive=False
            if len(subnet_or_ip) ==0: return False
            for ip1 in subnet_or_ip:
                for ip2 in self.ipaddress_list:
                    if ip2.__contains__(ip1):
                        inclusive=True
                        break
                if not inclusive: return False
            return True
        else:
            for ip in self.ipaddress_list:
                if subnet_or_ip !=None:
                    if ip.__contains__(subnet_or_ip):
                        included = True
                        break
        return included

    def AddSubElement(self,element,confirmed):
        # Check whether element has been confidently excluded previously
        if self.excluded_elements.has_key(element):
            if self.excluded_elements[element]:
                # Confidently excluded..cannot add
                return
            else:
                # Not confidently excluded..how confident are we including it?
                if confirmed:
                    # Remove exclusion
                    self.RemoveExcludedSubElement(element)
        # Include element
        if not self.sub_elements.has_key(element):
           self.sub_elements[element]=confirmed
        else:
            if confirmed:
               self.sub_elements[element]=confirmed

    def ContainsSubElement(self, element):
        return self.sub_elements.has_key(element)

    def RemoveSubElement(self,element):
        if self.sub_elements.has_key(element):
            self.sub_elements.__delitem__(element)

    def RemoveExcludedSubElement(self,element):
        if self.excluded_elements.has_key(element):
            self.excluded_elements.__delitem__(element)

    def AddExludedSubElement(self, element, confirmed):
        # Check whether element has been confidently included previously
        if self.sub_elements.has_key(element):
            if self.sub_elements[element]:
                # Confidently included..cannot exclude
                return
            else:
                # Not confidently included..how confident are we excluding it?
                if confirmed:
                    # Remove inclusion
                    self.RemoveSubElement(element)
        # Remove from sub-element list first
        #if confirmed:
        #    self.RemoveSubElement(element)
        # Add to exclusion list
        if not self.excluded_elements.__contains__(element):
            self.excluded_elements[element]= confirmed
        else:
            if confirmed:
                self.excluded_elements[element] = confirmed

    def AddGateway(self, gateway):
        if not self.gateways.__contains__(gateway):
            self.gateways.append(gateway)

    @property
    def Gateways(self):
        return self.gateways

    @property
    def GatewayNames(self):
        names=[]
        for gateway in self.gateways:
            names.append("gw %s"%gateway.ipaddress)
        return names

class SecurityConduit:

    def __init__(self, conduit_id, attached_zones):
            self.conduit_id=conduit_id
            self.attached_zones = attached_zones
            self.interfaces = None
            self.firewall_architecture = None

    def SetFirewallArchitecture(self, architecture):
        self.firewall_architecture = architecture

    def GetFirewallArchitecture(self):
        return self.firewall_architecture

    def GetInterfaces(self):
        return self.interfaces

    def SetInterfaces(self, interfaces):
        self.interfaces = interfaces

    def GetAttachedZones(self):
        return self.attached_zones

    def GetId(self):
        return self.conduit_id;

class ConduitFirewallArchitecture:

    def __init__(self):
        self.parallelFirewallPaths = []

    def AddParallelFirewallPath(self, path):
        if(not self.parallelFirewallPaths.__contains__(path)):
            self.parallelFirewallPaths.append(path)

    def GetParallelFirewallPaths(self):
        return self.parallelFirewallPaths

    def GetBoundaryFirewallsForZone(self, zone):
        pass

class ACE:
    def __init__(self, rule_action, protocol, source, source_port_filter, dest, dest_port_filter, icmp_type, rule_core=None):
        self.rule_action = rule_action
        self.protocol = protocol
        self.source = source
        self.source_port_filter = source_port_filter
        self.dest = dest
        self.dest_port_filter = dest_port_filter
        self.rule_core = rule_core
        self.icmp_type=icmp_type

    @property
    def RuleCore(self):
        return self.rule_core

    @property
    def Action(self):
        return self.rule_action

    @property
    def Protocol(self):
        return self.protocol

    @property
    def Source(self):
        return self.source

    @property
    def Dest(self):
        return self.dest

    @property
    def SourcePortFilter(self):
        return self.source_port_filter

    @property
    def DestPortFilter(self):
        return self.dest_port_filter

class AtomicACE:
    def __init__(self, rule_action, protocols, source_ip, source_ports, dest_ip, dest_ports, icmp_type, entry):
        self.rule_action = rule_action
        self.protocols = protocols
        self.source_ip = source_ip
        self.source_ports = source_ports
        self.dest_ip = dest_ip
        self.dest_ports = dest_ports
        self.entry=entry
        self.icmp_type=icmp_type
        self.interaction_type=None

        self.first_source_port = None
        self.first_dest_port = None
        if self.source_ports != None and len(self.source_ports)>0:
            self.first_source_port = self.source_ports[0]
        if self.dest_ports != None and len(self.dest_ports)>0:
            self.first_dest_port = self.dest_ports[0]

    @property
    def Action(self):
        return self.rule_action

    @property
    def Protocols(self):
        return self.protocols

    @property
    def SourceIp(self):
        return self.source_ip

    @property
    def DestIp(self):
        return self.dest_ip

    @property
    def SourcePort(self):
        return self.first_source_port

    @property
    def DestPort(self):
        return self.first_dest_port

    @property
    def SourcePortFilter(self):
        return self.source_ports

    @property
    def DestPortFilter(self):
        return self.dest_ports

    def Overlaps(self, acl_rule):
        if acl_rule != None:
            if ((acl_rule.Protocols == self.Protocols and acl_rule.Action == self.Action) or
               (acl_rule.Protocols.__contains__(ServiceProtocol.ip) or self.Protocols.__contains__(ServiceProtocol.ip) and acl_rule.Action==self.Action)) :

                #Temp eigrp overlaps are heavy!!
                '''
                if acl_rule.Protocols.__contains__(ServiceProtocol.eigrp) or self.Protocols.__contains__(ServiceProtocol.eigrp):
                    print("eigrp overlaps")
                    return False'''

                # intersections of the following properties must be non null
                #..source ips
                #..source ports
                #..dest ips
                #..dest ports
                # debug
                #print('acl_rule: %s %s %s %s %s %s'%(acl_rule.Action,acl_rule.Protocols,acl_rule.SourceIp,acl_rule.SourcePortFilter,acl_rule.DestIp,acl_rule.DestPortFilter))
                #print('other_rule: %s %s %s %s %s %s'%(self.Action,self.Protocols,self.SourceIp,self.SourcePortFilter,self.DestIp,self.DestPortFilter))
                if(self.IsIpaddressOverlap(acl_rule.SourceIp, self.SourceIp)and
                   self.IsPortOverlap(acl_rule.SourcePortFilter, self.SourcePortFilter) and
                   self.IsIpaddressOverlap(acl_rule.DestIp, self.DestIp) and
                   self.IsPortOverlap(acl_rule.DestPortFilter, self.DestPortFilter) and
                   acl_rule.icmp_type==self.icmp_type):
                   #print("Overlap detected1: source_ip- %s~%s dest_ip- %s~%s source_port- %s~%s dest_port- %s~%s"%(acl_rule.SourceIp,self.SourceIp,acl_rule.SourcePortFilter,self.SourcePortFilter, acl_rule.DestIp, self.DestIp, acl_rule.DestPortFilter, self.DestPortFilter))
                   return True

                elif (self.IsIpaddressOverlap(acl_rule.SourceIp, self.SourceIp)and
                      self.IsIpaddressOverlap(acl_rule.DestIp, self.DestIp) and
                      ((acl_rule.Protocols.__contains__(ServiceProtocol.ip) or self.Protocols.__contains__(ServiceProtocol.ip)) and acl_rule.Action==self.Action)):
                   #print("Overlap detected2: source_ip- %s~%s dest_ip- %s~%s source_port- %s~%s dest_port- %s~%s"%(acl_rule.SourceIp,self.SourceIp,acl_rule.SourcePortFilter,self.SourcePortFilter, acl_rule.DestIp, self.DestIp, acl_rule.DestPortFilter, self.DestPortFilter))
                   return True

        #print("No Overlap.")
        return False

    def Conflicts(self, acl_rule):
        if acl_rule != None:
            if ((acl_rule.Protocols == self.Protocols and acl_rule.Action != self.Action) or
                (acl_rule.Protocols.__contains__(ServiceProtocol.ip) or self.Protocols.__contains__(ServiceProtocol.ip) and acl_rule.Action!=self.Action)) :

                #Temp eigrp overlaps are heavy!!
                '''
                if acl_rule.Protocols.__contains__(ServiceProtocol.eigrp) or self.Protocols.__contains__(ServiceProtocol.eigrp):
                    print("eigrp conflicts")
                    return False'''

                # intersections of the following properties must be non null
                #..source ips
                #..source ports
                #..dest ips
                #..dest ports
                if(self.IsIpaddressOverlap(acl_rule.SourceIp, self.SourceIp)and
                   self.IsPortOverlap(acl_rule.SourcePortFilter, self.SourcePortFilter) and
                   self.IsIpaddressOverlap(acl_rule.DestIp, self.DestIp) and
                   self.IsPortOverlap(acl_rule.DestPortFilter, self.DestPortFilter)and
                   acl_rule.icmp_type==self.icmp_type):
                   return True

        return False

    def IsShadowedBy(self, acl_rule):

        if acl_rule != None:
            if ((acl_rule.protocols == self.protocols) or
                 acl_rule.Protocols.__contains__(ServiceProtocol.ip)):
                if (self.IsIpSubset(acl_rule.SourceIp, self.SourceIp) and
                    self.IsPortSubset(acl_rule.SourcePortFilter, self.SourcePortFilter) and
                    self.IsIpSubset(acl_rule.DestIp, self.DestIp) and
                    self.IsPortSubset(acl_rule.DestPortFilter, self.DestPortFilter)):
                    return True

        return False

    def IsIpaddressOverlap(self, subnet1, subnet2):

        if subnet1 == None or subnet2==None: return False

        temp1=subnet1
        temp2=subnet2

        if isinstance(subnet1, ipaddr.IPv4Address):
            temp1 = ipaddr.IPv4Network(subnet1)
        if isinstance(subnet2, ipaddr.IPv4Address):
            temp2 = ipaddr.IPv4Network(subnet2)

        return temp1.overlaps(temp2)

    def IsPortOverlap(self, ports1, ports2):
        #TODO: add-in range checking
        #if ports1 != None and ports2 !=None:
            return ports1 == ports2
        #return False

    def IsIpSubset(self, subnet1, subnet2):
        # Checks whether subnet2 is contained wholly within subnet1
        subnet1_address=subnet1
        subnet2_address=subnet2

        if isinstance(subnet1, ipaddr.IPv4Address):
            subnet1_address=ipaddr.IPv4Network(subnet1)
        if isinstance(subnet2, ipaddr.IPv4Address):
            subnet2_address=ipaddr.IPv4Network(subnet2)

        return subnet1_address.__contains__(subnet2_address)

    def IsPortSubset(self, ports1, ports2):
        #TODO: add-in range checking
        return ports1 == ports2

class LowlevelACE:
    def __init__(self, action, ip_protocols, source_ip_range, source_port_range, dest_ip_range, dest_port_range, icmp_type, entry_string):
        # action - 1(permit), 2(deny)
        # ip_protocols - [(start,end)] 0(ip), 1(icmp),...... 255(reserved) these are the standard ip protocol numbers
        # source_ip_range, dest_ip_range - [(start,end)]  ipv4 addresses
        # source_port_range, dest_port_range - [(start,end)] 0-65535
        # icmp_type - 0(echo_reply), 3(dest-unreachable)....255 (reserved)
        self.action = action
        self.ip_protocols = ip_protocols
        self.source_ip_range=source_ip_range
        self.source_port_range=source_port_range
        self.dest_ip_range=dest_ip_range
        self.dest_port_range=dest_port_range
        self.icmp_type=icmp_type
        self.entry_string = entry_string

    @property
    def Action(self):
        return self.action

    @property
    def Protocols(self):
        return self.ip_protocols

    @property
    def SourceIpRange(self):
        return self.source_ip_range

    @property
    def SourcePortRange(self):
        return self.source_port_range

    @property
    def DestIpRange(self):
        return self.dest_ip_range

    @property
    def DestPortRange(self):
        return self.dest_port_range

    @property
    def IcmpType(self):
        return self.icmp_type

    @property
    def RuleEntry(self):
        return self.entry_string

class RuleInteraction:
    def __init__(self, rule):
        self.current_rule = rule
        self.type = None
        self.net_effect = None

    @property
    def Rule(self):
        return self.current_rule

    @property
    def Type(self):
        return self.type

    @property
    def NetEffect(self):
        return self.net_effect

    @NetEffect.setter
    def NetEffect(self, value):
        self.net_effect = value

    @Type.setter
    def Type(self, value):
        self.type = value





