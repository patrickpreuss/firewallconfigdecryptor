import re
import ipaddr
import properties
from security import ACE, AtomicACE, LowlevelACE
from enums import  RuleInteractionType, RuleOperation, ServiceProtocol, GraphAttribute, SecurityElement, RuleEffect
from exception import ParserException

def Singleton(cls):
    instances = {}
    def GetInstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return GetInstance

class Util:

    @staticmethod
    def HasDefaultSubnetZero(ipaddress_list):
        for ip in ipaddress_list:
            if ip == ipaddr.IPv4Network("0.0.0.0/0"):
                return True

    @staticmethod
    def GetNodeById(id, graph):
        for node in graph.nodes_iter():
            zoneId = graph.node[node].get(GraphAttribute.Label)
            if zoneId == id: return node
        return None

    @staticmethod
    def ConvertStringToIpaddress(ip_string):
        p = re.search('host',ip_string)
        if p:
            # host <ip> format
            return ipaddr.IPv4Network("%s/%s" % (ip_string.split(' ')[1],"255.255.255.255"))
        else:
            # <subnet> <mask> format
            # TODO: ASA needs this
            #return ipaddr.IPv4Network("%s/%s" %(ip_string.split(' ')[0], ip_string.split(' ')[1]))
            # TODO: Routers need this instead
            wc_mask_value = int(ipaddr.IPv4Address(ip_string.split(' ')[1]))
            subnet_mask_value = int(ipaddr.IPv4Address("255.255.255.255")) - wc_mask_value

            return ipaddr.IPv4Network("%s/%s"%(ip_string.split(' ')[0],str(ipaddr.IPv4Address(subnet_mask_value))))

    @staticmethod
    def GetMergePendingZones(zone_ip_list):
        zones_to_merge = []
        for zone1 in zone_ip_list:
            ip_list1 = zone_ip_list[zone1]
            for zone2 in zone_ip_list:
                if(zone1 != zone2):
                    ip_list2 = zone_ip_list[zone2]
                    if Util.SubnetOverlapsExist(ip_list1, ip_list2):
                        if not zones_to_merge.__contains__(zone1):
                            zones_to_merge.append(zone1)
                        if not zones_to_merge.__contains__(zone2):
                            zones_to_merge.append(zone2)
                        break
        '''
        # Cleanup
        final=[]
        for zone_tuple1 in zones_to_merge:
            zone1=zone_tuple1[0]
            zone2=zone_tuple1[1]
            for zone_tuple2 in zones_to_merge:
                if(zone_tuple1 != zone_tuple2):
                    zone3=zone_tuple2[0]
                    zone4=zone_tuple2[1]
                    if zone1==zone3 or zone1==zone4 or zone2==zone3 or zone2==zone4:
                        final.append((zone1,zone2,zone3,zone4))'''
        return zones_to_merge

    @staticmethod
    def SubnetOverlapsExist(ip_list1, ip_list2):
        for subnet1 in ip_list1:
            for subnet2 in ip_list2:
                if subnet1.overlaps(subnet2): return True
        return False

    @staticmethod
    def GetHostZone(host_ip, all_zones):
        fw_zone=None
        #Find the firewall zone
        for zone in all_zones:
            if zone.zone_id =='fwz':
                fw_zone =zone
                break
        for zone in all_zones:
            if zone.ContainsSubnetOrIpaddress(host_ip): return zone.zone_id
            elif fw_zone!=None:
                excluded=None
                #check whether zone+fw_zone includes the host_ip
                for ipaddress in fw_zone.ipaddress_list:
                    try:
                        excluded = ipaddr.IPv4Network(host_ip).address_exclude(ipaddress)
                        break
                    except ValueError, e:
                        # not contained
                        pass
                if zone.ContainsSubnetOrIpaddress(excluded): return zone.zone_id

        return ""

    @staticmethod
    def GetHostZoneIds(host_ip, all_zones):
        fw_zones=[]
        zone_ids=[]
        #Find the firewall zone
        for zone in all_zones:
            if zone.zone_id.__contains__('fwz'):
                fw_zones.append(zone)
        for zone in all_zones:
            if zone.ContainsSubnetOrIpaddress(host_ip):
                zone_ids.append(zone.zone_id)
                return zone_ids
            elif len(fw_zones) !=0:
                excluded=None

                for fw_zone in fw_zones:
                    #check whether zone+fw_zone includes the host_ip
                    for ipaddress in fw_zone.ipaddress_list:
                        try:
                            excluded = ipaddr.IPv4Network(host_ip).address_exclude(ipaddress)
                            break
                        except ValueError, e:
                            # not contained
                            pass

                    if zone.ContainsSubnetOrIpaddress(excluded):
                        zone_ids.append(fw_zone.zone_id)
                        zone_ids.append(zone.zone_id)
                        return zone_ids

        return ""

    @staticmethod
    def GetServiceName(protocol, service_port):
        tcp_service_lookup = dict({'5190': 'aol', '179': 'bgp','19': 'chargen','1494': 'citrix-ica',
                                   '514': 'cmd','2748': 'ctiqbe', '13': 'daytime','53': 'domain', '7': 'echo','512': 'exec',
                                   '79': 'finger','21': 'ftp', '20': 'ftp-data','70': 'gopher', '443': 'https','1720': 'h323',
                                   '101': 'hostname','113': 'ident', '143': 'imap4','194': 'irc', '750': 'kerberos-iv','543': 'klogin',
                                   '544': 'kshell','389': 'ldap', '636': 'ldaps','515': 'lpd', '513': 'login','1352': 'lotusnotes',
                                   '139': 'netbios-ssn','119': 'nntp', '20': 'ftp-data','70': 'gopher', '443': 'https','1720': 'h323',
                                   '5631': 'pcanywhere-data','496': 'pim-auto-rp', '109': 'pop2','110': 'pop3', '443': 'https','1720': 'h323', '139': 'netbios-ssn',
                                   '1723': 'pptp','25': 'smtp', '1521': 'sqlnet','22': 'ssh', '111': 'sun_rpc','23': 'telnet', '137':'netbios-ns', '138':'netbios-dgm',
                                   '69': 'tftp','540': 'uucp', '43': 'whois','80': 'www','49':'tacacs', '517':'talk', '445':'smb', '88':'kerberos', '135':'dce_rpc' })

        udp_service_lookup = dict({'512':'biff','68':'bootpc','67':'bootps','195':'dnsix','7':'echo','500':'isakmp', '750':'kerberos-iv','434':'mobile-ip','42':'nameserver',
                                   '137':'netbios-ns', '138':'netbios-dgm','123':'ntp','5632':'pcanywhere-status','1645':'radius','1646':'radius-acct','520':'rip','5510':'secureid-udp',
                                   '161':'snmp','162':'snmptrap','111':'sun_rpc ', '514':'syslog','49':'tacacs','517':'talk ', '37':'time','513':'who','177':'xdmcp ',
                                   '88':'kerberos', '135':'dce_rpc', '53':'domain', '389': 'ldap', '636': 'ldaps','139': 'netbios-ssn'})

        if str(service_port).isdigit():
            port_number = int(service_port)
            if port_number < 1024:
                if protocol =='tcp' and tcp_service_lookup.has_key(str(port_number)):
                    return tcp_service_lookup[str(port_number)]
                elif protocol=='udp' and udp_service_lookup.has_key(str(port_number)):
                    return udp_service_lookup[str(port_number)]
                else:
                    return service_port
            else:
                # Cannot translate dynamic ports
                return service_port
        else:
            # Must be service name already
            return service_port

    @staticmethod
    def IsZoneFreePath(path, zoneTopology):

            if not path:
                raise ValueError("path", properties.resources['value_null'])
            if not zoneTopology:
                raise ValueError("zoneTopology", properties.resources['value_null'])

            for node in path:
                if (zoneTopology.node[node].get(GraphAttribute.Type) == SecurityElement.Zone): return False
            return True

    @staticmethod
    def ConvertToFirewallPath(nodePath, zoneTopology):

        if not nodePath:
            raise ValueError("nodePath", properties.resources['value_null'])
        if not zoneTopology:
            raise ValueError("zoneTopology", properties.resources['value_null'])

        convertedPath = []
        for node in nodePath:
            convertedPath.append(zoneTopology.node[node].get(GraphAttribute.Label))
        return convertedPath

    @staticmethod
    def GetIpList(criteria, zones):
        # Evaluate criteria and extract ip address list
        ip_list = []
        if criteria!=None:
            if criteria != 'any':
                ipaddresses = Util.ConvertStringToIpaddress(criteria)
                if isinstance(ipaddresses, list):
                    for ip in ipaddresses:
                        if not ip_list.__contains__(ip):
                            ip_list.append(ip)
                elif not ip_list.__contains__(ipaddresses):
                    ip_list.append(ipaddresses)
            else:
                for zone in zones:
                    for ip in zone.ipaddress_list:
                        if not ip_list.__contains__(ip):
                            ip_list.append(ip)

        return ip_list

    @staticmethod
    def ConvertToSubrulesList(ace, source_ip_list, dest_ip_list):

        if not ace:
            raise ValueError("ace", properties.resources['value_null'])
        if not source_ip_list:
            raise ValueError("source_ip_list", properties.resources['value_null'])
        if not dest_ip_list:
            raise ValueError("dest_ip_list", properties.resources['value_null'])

        subrules = []

        # Consider the cross-product of source and dest criteria to generate possible rule combinations
        for source_ip in source_ip_list:
            for dest_ip in dest_ip_list:

                #TODO: use subrules with numeric fields for improved performance
                #subrule_test = LowlevelACE(ace.Action, [Util.GetProtocol(ace.Protocol)], [source_ip], [Util.GetPorts(ace.source_port_filter)],[dest_ip],[Util.GetPorts(ace.dest_port_filter)], ace.icmp_type, ace.rule_core )
                subrule = AtomicACE(ace.Action, [Util.GetProtocol(ace.Protocol)], source_ip, Util.GetPorts(ace.source_port_filter), dest_ip, Util.GetPorts(ace.dest_port_filter), ace.icmp_type, ace.rule_core)
                if not subrules.__contains__(subrule): subrules.append(subrule)

        return subrules

    @staticmethod
    def GetProtocol(protocol_desc):

        if not protocol_desc:
            raise ParserException("protocol_desc", properties.resources['value_null'])

        if protocol_desc == ServiceProtocol.reverse_mapping[ServiceProtocol.tcp]:
            return ServiceProtocol.tcp
        elif protocol_desc == ServiceProtocol.reverse_mapping[ServiceProtocol.udp]:
            return ServiceProtocol.udp
        elif protocol_desc == ServiceProtocol.reverse_mapping[ServiceProtocol.icmp]:
            return ServiceProtocol.icmp
        elif protocol_desc == ServiceProtocol.reverse_mapping[ServiceProtocol.ip]:
            return ServiceProtocol.ip
        elif protocol_desc == ServiceProtocol.reverse_mapping[ServiceProtocol.eigrp]:
            return ServiceProtocol.eigrp
        else:
            # Unhandled protocol type
            raise ParserException('protocol_desc', properties.resources['arguments_invalid'])

    @staticmethod
    def GetPorts(port_filter_criteria):

        if not port_filter_criteria: return None

        ports = []

        items = port_filter_criteria.split(' ')
        # TODO: handle port ranges
        ports.append(items[1])
        return ports

    @staticmethod
    def GetCiscoACE(access_control_entry):

        port_operators = ['eq', 'gt', 'lt', 'neq', 'range']
        icmp_types=['unreachable', 'echo', 'echo-reply', 'source-quench']

        # Extract rule action (permit/deny)
        action_permit = re.search('permit',access_control_entry)
        action_deny = re.search('deny',access_control_entry)
        action_inactive=re.search('inactive',access_control_entry)
        p = re.search(' \(',access_control_entry)

        # work data
        index =0
        end = 0
        rule_core_start=0
        rule_core_end=0
        ip_tuples =[]
        rule_core=None
        source = None
        dest = None
        source_port_filter = None
        dest_port_filter=None
        rule_effect = None
        icmp_type=None

        if action_inactive:
            # Entry is disabled..ignore
            pass

        elif action_permit or action_deny:
            if action_permit:
                rule_core_start=action_permit.start()
                end = action_permit.end()
                rule_effect = RuleEffect.Permit
            else:
                end = action_deny.end()
                rule_core_start=action_deny.start()
                rule_effect = RuleEffect.Deny
            if p: rule_core_end = p.start()
            # TODO: check if ASA still works with this (added for routers)
            else: rule_core_end = len(access_control_entry)
            rule_core=access_control_entry[rule_core_start:rule_core_end]
            rule_match_criteria = access_control_entry[end:].lstrip().split(' ')
            protocol = rule_match_criteria[index]

            # Cisco ACLs support tcp, udp, icmp and ip based ACEs
            if protocol == 'tcp' or protocol == 'udp' or protocol=='icmp' or protocol=='ip' or protocol=='eigrp':
                index +=1
                # Extract source
                temp = rule_match_criteria[index]
                if temp == 'any':
                    source = 'any'
                else:
                    # Must be source source_wc format
                    index +=1
                    source = "%s %s" % (temp, rule_match_criteria[index])
                index +=1
                if protocol == 'tcp' or protocol == 'udp':
                    # Extract source ports
                    source_port_operator = rule_match_criteria[index]
                    if source_port_operator in port_operators:
                       index +=1
                       source_port_filter = "%s %s"% (source_port_operator, rule_match_criteria[index])
                       index +=1
                temp = rule_match_criteria[index]
                # Extract dest
                if temp == 'any':
                    dest = 'any'
                else:
                    # Must be dest dest_wc format
                    index +=1
                    dest = "%s %s" % (temp, rule_match_criteria[index])
                index +=1
                # Extract dest ports
                if protocol == 'tcp' or protocol == 'udp':
                    if index < len(rule_match_criteria):
                        dest_port_operator = rule_match_criteria[index]
                        if dest_port_operator in port_operators:
                           index +=1
                           dest_port_filter = "%s %s"%(dest_port_operator, rule_match_criteria[index])
                elif protocol=="icmp":
                    if index < len(rule_match_criteria):
                        icmp_type= rule_match_criteria[index]
                        if not icmp_type in icmp_types:
                            icmp_type=None


            # Replace www with http (Cisco allows www)
            if source_port_filter!= None and source_port_filter.__contains__('www'):
                source_port_filter = source_port_filter.replace('www','http')
            if dest_port_filter!= None and dest_port_filter.__contains__('www'):
                dest_port_filter = dest_port_filter.replace('www','http')
            return ACE(rule_effect, protocol, source,source_port_filter, dest, dest_port_filter, icmp_type, rule_core)

        return None

    @staticmethod
    def RemoveProtocolsFromRange(protocols, range):
        return [i for i in range if i not in protocols]

    @staticmethod
    def GetNetRule(rule1, rule2, operation, final_action):

        if not rule1:
            raise ParserException("rule1", properties.resources['value_null'])
        if not rule2:
            raise ParserException("rule2", properties.resources['value_null'])
        if not operation:
            raise ParserException("operation", properties.resources['value_null'])

        #..calculate cross_product of rules
        rule1_combinations = []

        for rule1_source_host in Util.GetHostIpaddresses(rule1.source_ip):
            for rule1_dest_host in Util.GetHostIpaddresses(rule1.dest_ip):
                rule1_combinations.append((rule1_source_host,rule1_dest_host))
        rule2_combinations = []
        # rule2 can be a single rule or a list of rules
        rule2_protocols=None
        if isinstance(rule2, list):
            for rule2_item in rule2:
                rule2_protocols=rule2_item.Protocols
                for rule2_source_host in Util.GetHostIpaddresses(rule2_item.source_ip):
                    for rule2_dest_host in Util.GetHostIpaddresses(rule2_item.dest_ip):
                        rule2_combinations.append((rule2_source_host,rule2_dest_host))
        else:
            rule2_protocols=rule2.Protocols
            for rule2_source_host in Util.GetHostIpaddresses(rule2.source_ip):
                for rule2_dest_host in Util.GetHostIpaddresses(rule2.dest_ip):
                    rule2_combinations.append((rule2_source_host,rule2_dest_host))

        if operation == RuleOperation.Exclude:
            result=[]
            if rule1.Protocols==rule2_protocols:
                # take rule1-rule2
                #..i.e. cross_product(rule1.source_ip, rule1.dest_ip) - cross_product(rule2.source_ip, rule2.dest_ip)
                # i.e. exclude rule2_combinations from rule1_combinations
                for combination_to_remove in rule2_combinations:
                    if rule1_combinations.__contains__(combination_to_remove):
                        rule1_combinations.remove(combination_to_remove)
                # Create rules for remaining combinations
                for combination in rule1_combinations:
                    atomic_ace = AtomicACE(final_action, rule1.Protocols, combination[0], rule1.SourcePortFilter, combination[1], rule1.DestPortFilter, rule1.icmp_type, rule1.entry)
                    result.append(atomic_ace)
            elif (rule1.Protocols.__contains__(ServiceProtocol.ip) or rule2_protocols.__contains__(ServiceProtocol.ip)):
                # TODO: take (ip - other_protocol): need finite list - resolve
                # for the time being return rule1 in whole
                # expand ip into its protocol composition
                overlap_rule=None
                non_overlap_rule=None
                if rule1.Protocols.__contains__(ServiceProtocol.ip):
                    overlap_rule = AtomicACE(rule1.Action, rule2_protocols, rule1.source_ip, rule1.SourcePortFilter, rule1.dest_ip, rule1.DestPortFilter, rule1.icmp_type, rule1.entry )
                    non_overlap_protocols= Util.RemoveProtocolsFromRange(rule2_protocols,range(1,255))
                    non_overlap_rule = AtomicACE(rule1.Action, non_overlap_protocols, rule1.source_ip, rule1.SourcePortFilter, rule1.dest_ip, rule1.DestPortFilter, rule1.icmp_type, rule1.entry )
                    net_overlap = Util.GetNetRule(overlap_rule, rule2, operation, rule1.Action)
                    if net_overlap!=None:
                        if isinstance(net_overlap, list):
                            [result.append(overlap) for overlap in net_overlap]
                        else:
                            result.append(net_overlap)
                    if non_overlap_rule!=None:
                        result.append(non_overlap_rule)

                elif rule2_protocols.__contains__(ServiceProtocol.ip):
                    overlap_rule = AtomicACE(rule2.Action, rule1.Protocols, rule2.source_ip, rule2.SourcePortFilter, rule2.dest_ip, rule2.DestPortFilter, rule2.icmp_type, rule2.entry )
                    non_overlap_protocols= Util.RemoveProtocolsFromRange(rule1.Protocols,range(1,255))
                    non_overlap_rule = AtomicACE(rule2.Action, non_overlap_protocols, rule2.source_ip, rule2.SourcePortFilter, rule2.dest_ip, rule2.DestPortFilter, rule2.icmp_type, rule2.entry )
                    net_overlap = Util.GetNetRule(overlap_rule, rule1, operation, rule2.Action)
                    if net_overlap!=None:
                        if isinstance(net_overlap, list):
                            [result.append(overlap) for overlap in net_overlap]
                        else:
                            result.append(net_overlap)
                    if non_overlap_rule!=None:
                        result.append(non_overlap_rule)
            return result

        elif operation == RuleOperation.Intersect:
            # include only the common tuples in rule2_combinations and rule1_combinations
            common_combinations=[]
            for combination in rule2_combinations:
                if rule1_combinations.__contains__(combination):
                    common_combinations.append(combination)

            # Get resultant protocol
            final_protocols= rule1.Protocols
            if rule1.Protocols != rule2.Protocols and (rule1.Protocols.__contains__(ServiceProtocol.ip) or rule2.Protocols.__contains__(ServiceProtocol.ip)):
                # Pick child protocol that is NOT based on ip
                if not rule2.Protocols.__contains__(ServiceProtocol.ip): final_protocols=rule2.Protocols

            # Create rules for common combinations
            result=[]
            for combination in common_combinations:
                atomic_ace = AtomicACE(final_action, final_protocols, combination[0], rule1.SourcePortFilter, combination[1], rule1.DestPortFilter, rule1.icmp_type, rule1.entry)
                result.append(atomic_ace)
            return result
        else:
            # Unhandled operation type
            raise ParserException('operation', properties.resources['arguments_invalid'])

    @staticmethod
    def GetHostIpaddresses(ipv4_network):
        hosts=[]
        if isinstance(ipv4_network, ipaddr.IPv4Address):
            return [ipv4_network]
        elif ipv4_network.prefixlen == 32:
            # ip is host address
            return [ipv4_network.network]
        else:
            # TODO: need to do this differently..when we do address splits, the subnets created are not real subnets, infact they can be hosts
            hosts.append(ipv4_network.network)
            for host in ipv4_network.iterhosts(): hosts.append(host)
            return hosts

    @staticmethod
    def GetFirewallHostname(file_contents):
        for line in file_contents:
            p = re.search('hostname', line)
            if p:
                return line.split(' ')[1]
        return None

    @staticmethod
    def IsIpaddressListMatch(iplist_1, iplist_2):
        for ip1 in iplist_1:
            possible_match = False
            for ip2 in iplist_2:
                if ip2.__contains__(ip1):
                    possible_match = True
                    break
            if not possible_match: return False
        return True




