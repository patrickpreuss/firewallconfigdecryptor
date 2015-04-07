from exception import ParserException
from device import Firewall, Gateway, FirewallInterface
from security import ACL, InterfaceACL, SecurityZone, SecurityConduit, ConduitFirewallArchitecture, RuleInteraction
from enums import RuleOperation, RuleInteractionType, GraphAttribute, SecurityElement, ServiceProtocol, RuleEffect
from utilities import Util, Singleton
from security import AtomicACE
import matplotlib.pyplot as plt
import networkx as nx
import log
import properties
import re
import os
import ipaddr
import shutil

@Singleton
class CiscoConfigParser(object):

    def __init__(self):
        self.config_files = dict()
        self.file_contents = dict()
        self.delimited = dict()
        self.firewalls=dict()
        self.acl_details = dict()
        self.acls_used = dict()
        self.acl_anomalies = dict()

    def ExtractFirewallInterfaces(self, file_contents, acls_used):
            '''
            Example format:
            interface Ethernet0/0
             nameif sample
             security-level 20
             ip address 10.0.0.8 255.255.255.0
             ospf cost 15
            !
            '''
            # Search for occurrences of 'interface' at beginning of line
            extracted_interfaces = dict()
            int_start = -1
            int_end = -1
            int_section_start = -1
            int_section_end = -1
            count = 0
            for line in file_contents:
                p = re.search('^interface',line)
                q = re.search('^!',line)
                if p:
                    if(int_start == -1):
                        int_start = count
                    int_section_start = count
                elif int_section_start>0 and q:
                    int_section_end = count
                    int_section_start =0
                count = count+1
            int_end = int_section_end
            # Check interface definitions present
            if not (int_start >=0 and int_end > int_start): return None
            # Extract interfaces
            int_definitions = []
            int_definition = None
            for num in range(int_start,int_end+1):
                config_line = file_contents[num]
                if re.search('^interface',config_line):
                    if int_definition != None: int_definitions.append(int_definition)
                    int_definition = config_line
                else :
                    int_definition = int_definition + "~" + config_line
            # Append last
            if int_definition != None: int_definitions.append(int_definition)
            for int_definition in int_definitions:
                interface = self.ExtractInterface(int_definition, acls_used)
                if interface !=None:
                    extracted_interfaces[interface.name.replace(' ','')] = interface
            return extracted_interfaces

    def ExtractACLsAssigned(self, file_contents):
        '''
        Example format:
        access-group ACL_name in interface int_name
        '''
        acls_used = dict()
        applied_interfaces =[]
        acl_name= None
        acl_dir = None
        int_name = None
        lookup_table=dict()
        # This doesnt look right check
        #for line in file_contents:
        for line in file_contents:
            #for line in file_contents[host]:
                p = re.search('^access-group', line)
                if p:
                    remain = line[p.end():].lstrip()
                    acl_name = remain.split(' ')[0]
                    acl_dir = remain.split(' ')[1]
                    q = re.search('interface',remain)
                    if q:
                        rest = remain[q.end():].lstrip()
                        int_name = rest.split(' ')[0]
                    if not acls_used.has_key(acl_name):
                        applied_interfaces= []
                    else:
                       applied_interfaces = acls_used[acl_name]

                    if (not lookup_table.has_key((int_name))) or (not lookup_table[int_name].__contains__(acl_dir)):
                        applied_interfaces.append(InterfaceACL(int_name, acl_dir, acl_name))
                        acls_used[acl_name] = applied_interfaces

                    if not lookup_table.has_key(int_name):
                        lookup_table[int_name]= []
                    lookup_table[int_name].append(acl_dir)

        if len(acls_used) == 0 : return None
        else: return acls_used

    def ExtractInterface(self,interface_definition, acls_used):
        t = re.search('interface',interface_definition)
        p = re.search('nameif',interface_definition)
        q = re.search('ip address',interface_definition)
        r = re.search('security-level',interface_definition)
        v = re.search('description',interface_definition)
        x = re.search('ip access-group',interface_definition)
        type=None
        name = None
        description = None
        ip_address = None
        applied_interfaces = None
        sec_level=-1
        if t:
            remain = interface_definition[t.end():]
            s = re.search("~",remain)
            type = remain[0:s.start()]
        if p:
            remain = interface_definition[p.end():]
            s = re.search("~",remain)
            name = remain[0:s.start()]
        if q:
            remain = interface_definition[q.end():]
            s = re.search("~",remain)
            ip_address = remain[0:s.start()]
        if r:
            remain = interface_definition[r.end():]
            s = re.search("~",remain)
            sec_level = remain[0:s.start()]
        if v:
            remain = interface_definition[v.end():]
            s = re.search("~",remain)
            description = remain[0:s.start()]
        if x:
            remain = interface_definition[x.end():].lstrip()
            acl_name = remain.split(' ')[0]
            acl_dir = remain.split(' ')[1].replace('~','')
            if not acls_used.has_key(acl_name):
                applied_interfaces= []
            else:
               applied_interfaces = acls_used[acl_name]

        # No need to process interfaces with a non-assigned ipaddress
        if ip_address==None or len(ip_address)==0: return None

        subnet = ip_address.split(' ')[1].replace('\r','')
        mask = ip_address.split(' ')[2].replace('\r','')
        address = ipaddr.IPNetwork('%s/%s'%(subnet,mask))
        if name== None and description!= None:
            name=description.replace(' ','')
        if applied_interfaces!=None:
            applied_interfaces.append(InterfaceACL(name, acl_dir, acl_name))
            acls_used[acl_name] = applied_interfaces
        return FirewallInterface(type, name, description, address,sec_level)

    def GetACLDetails(self, acls_in_use, file_contents):
        '''
        Example format:
            access-list acl-name <entry>
        '''

        prev_acl_name = None
        new_acl_name= None
        entry_list = []
        acl=dict()

        prev_acl_name_2 = None
        new_acl_name_2 =None
        entry_list_2 =[]
        acl_2=dict()

        low_level_ruleset_missing=True

        for line in file_contents:
            p = re.search('^access-list', line)
            r = re.search('^  access-list', line)
            if p:
                # Output of 'show run'- HL rule potentially containing object groups
                remain = line[p.end():].lstrip()
                # TODO: this is required for ASA
                # if not ('line' in remain): continue
                new_acl_name = remain.split(' ')[0].replace(';','')
                if prev_acl_name != new_acl_name:
                    entry_list = []
                    prev_acl_name = new_acl_name
                q= re.search(new_acl_name,line)
                entry_list.append(line[q.end():].lstrip().replace(';',''))
                acl[new_acl_name] = entry_list
            if r:
                # output of 'show access-lists' - Low-level rules
                remain = line[r.end():].lstrip()
                if not ('line' in remain): continue
                low_level_ruleset_missing=False
                new_acl_name_2 = remain.split(' ')[0].replace(';','')
                if prev_acl_name_2 != new_acl_name_2:
                    entry_list_2 = []
                    prev_acl_name_2 = new_acl_name_2
                q= re.search(new_acl_name_2,line)
                entry_list_2.append(line[q.end():].lstrip().replace(';',''))
                acl_2[new_acl_name_2] = entry_list_2

        # Replace high-level ACL entries with their equivalent low-level rule-sets
        final_acl = dict()
        for acl_name in acl.keys():
            final_entry_list = []
            for entry in acl[acl_name]:
                p = re.search('line', entry)
                if p:
                    remain = entry[p.end():].lstrip()
                    line_number = remain.split(' ')[0]
                    low_level_rule_set= None
                    if acl_2.has_key(acl_name):
                        low_level_rule_set = self.GetLowLevelRulesetEquivalent("line %s " % line_number, acl_2[acl_name])
                    if low_level_rule_set ==None:
                        final_entry_list.append(entry)
                    else:
                        for low_level_rule in low_level_rule_set:
                            final_entry_list.append(low_level_rule)
                else:
                    final_entry_list.append(entry)
            final_acl[acl_name] = final_entry_list

        # Check whether low-level rules need to be extracted from object-group based HL rules
        if low_level_ruleset_missing:
            # Extract object groups
            self.GetObjectGroupItems(file_contents)
            for acl_name in final_acl.keys():
                final_entry_list = []
                for entry in final_acl[acl_name]:
                    groups=[]
                    p = re.search('object-group ',entry)
                    if p:
                        remain=entry[p.end():]
                        group_name=remain.split(' ')[0]
                        groups.append(group_name)

                        q=re.search('object-group ',remain)
                        if q:
                            remain=remain[q.end():]
                            group_name=remain.split(' ')[0]
                            groups.append(group_name)

                    if len(groups)>0:
                        item1 = groups[0].replace(' ','')
                        item2=None
                        if len(groups)>1:
                            item2 = groups[1].replace(' ','')

                        if not self.group_items_lookup.has_key(item1):continue
                        if item2!=None and not self.group_items_lookup.has_key(item1):continue

                        low_level_entries=[]
                        if item1!=None and item2!=None:
                            for group_item1 in self.group_items_lookup[item1]:
                                for group_item2 in self.group_items_lookup[item2]:
                                    temp = entry.replace('object-group %s'%item1, group_item1)
                                    temp = temp.replace('object-group %s'%item2, group_item2)
                                    if not low_level_entries.__contains__(temp):
                                        low_level_entries.append(temp)
                        else:
                            for group_item1 in self.group_items_lookup[item1]:
                                temp = entry.replace('object-group %s'%item1, group_item1)
                                if not low_level_entries.__contains__(temp):
                                    low_level_entries.append(temp)

                        [final_entry_list.append(low_level_entry) for low_level_entry in low_level_entries]

                    else:
                        final_entry_list.append(entry)

                final_acl[acl_name] = final_entry_list

        # Check all ACLs in use have been defined
        for acl_name in acls_in_use.keys():
            if not final_acl.has_key(acl_name):
                raise ParserException(acl_name,properties.resources['acl_definition_missing'])

        #TODO: replace hostnames in ACL entries with their ipaddresses
        # Build hostname lookup table
        self.hostname_lookup = dict()
        for line in file_contents:
            p = re.search('^name ',line)
            if p:
                ipaddress = line.split(' ')[1]
                hostname = line.split(' ')[2]
                self.hostname_lookup[hostname] = ipaddress

        for acl_name in final_acl.keys():
            entries = final_acl[acl_name]
            resolved_entries = []
            for entry in entries:
                p = re.search("host", entry)
                if p:
                    # lookup and replace source host
                    remain = entry[p.end():]
                    hostname = remain.split(' ')[1]
                    if self.hostname_lookup.has_key(hostname):
                        ipaddress = self.hostname_lookup[hostname]
                        entry = entry.replace(hostname, ipaddress)
                    # lookup and replace dest source
                    q = re.search("host", remain)
                    if q:
                        # lookup and replace dest host
                        remain2 = remain[q.end():]
                        hostname = remain2.split(' ')[1]
                        if self.hostname_lookup.has_key(hostname):
                            ipaddress = self.hostname_lookup[hostname]
                            entry = entry.replace(hostname, ipaddress)
                resolved_entries.append(entry)
            final_acl[acl_name] = resolved_entries

        # Return details of the ACLs in use
        acl_collection = dict()
        for acl_name in final_acl.keys():
            # Only include ACLs in use
            if acls_in_use.has_key(acl_name):
                acl_collection[acl_name] = ACL(acl_name,final_acl[acl_name])

        return acl_collection

    def GetObjectGroupItems(self, file_contents):

        count=0
        self.group_items_lookup=dict()
        while count<len(file_contents):
            p = re.search('^object-group',file_contents[count])
            if p:
                name=file_contents[count].split(' ')[2]
                if not self.group_items_lookup.has_key(name):
                    self.group_items_lookup[name]=[]
                # Get all group items
                count+=1
                group_items=[]
                while count<len(file_contents):
                    q = re.search('^object-group', file_contents[count])
                    if q:
                        break
                    elif ('description' in file_contents[count]):
                        count+=1
                        pass
                    elif'network-object'in file_contents[count]:
                        elements = file_contents[count].split(' ')
                        ip_address="%s %s"%(elements[2],elements[3])
                        group_items.append(ip_address)
                        self.group_items_lookup[name]=group_items
                        count+=1
                    else:
                        break

            else:
                count+=1

        return self.group_items_lookup

    def GetLowLevelRulesetEquivalent(self, line_desc, low_level_acl):
        rule_set =[]
        for entry in low_level_acl:
            p = re.search(line_desc, entry)
            if p:
                rule_set.append(entry)
        if len(rule_set) ==0: return None
        else : return rule_set

    def ProcessImplicitRules(self, firewalls, file_contents, gen_zones, graphml_file_path):

        self.implicitly_allowed_services_ip = dict()
        self.implicitly_allowed_services_tcp= dict()
        self.implicitly_allowed_services_udp= dict()
        self.implicitly_allowed_services_icmp= dict()

        # Check how same sec-level traffic is enabled
        enable_same_security_traffic = False
        # same-security-traffic permit intra-interface
        for host in file_contents:
            for line in file_contents[host]:
                p = re.search('same-security-traffic permit', line)
                if p:
                    if 'inter-interface' in line:
                        enable_same_security_traffic =True
                        break

        ip_tuples =[]

        # Create generic IP overlay based on security level only (i.e. considering interfaces without ACLs)
        for host in firewalls:
            firewall = firewalls[host]
            for interface1 in firewall.interfaces.values():
                # Select an interface without an inbound ACL
                if (not interface1.acl.has_key('in')) or interface1.acl['in'] == None:
                    source_ip_list=[]
                    dest_ip_list=[]
                    # This can implicitly initiate traffic to another interface without an outbound ACL
                    for interface2 in firewall.interfaces.values():
                        # Select other interface without an outbound ACL
                        if (interface1 != interface2) and ((not interface2.acl.has_key('out')) or interface2.acl['out'] == None):
                            # Ok to permit ip traffic from high-security zone to low-security zone
                            if (int(interface1.security_level) > int(interface2.security_level) or
                                int(interface1.security_level) == int(interface2.security_level) and enable_same_security_traffic):
                                high_security_zone = gen_zones[host][interface1.type]
                                low_security_zone = gen_zones[host][interface2.type]

                                for ip in high_security_zone.ipaddress_list:
                                    source_ip_list.append(ip)
                                for ip in low_security_zone.ipaddress_list:
                                    dest_ip_list.append(ip)

                                for source_ip in source_ip_list:
                                    for dest_ip in dest_ip_list:
                                        if not self.implicitly_allowed_services_ip.has_key("ip"):
                                            ip_tuples.append((source_ip,dest_ip))
                                            self.implicitly_allowed_services_ip["ip"] = ip_tuples
                                        else:
                                            if not self.implicitly_allowed_services_ip["ip"].__contains__((source_ip,dest_ip)):
                                                self.implicitly_allowed_services_ip["ip"].append((source_ip,dest_ip))

            '''
            # TODO:Broadcasts forwarded
            for host in file_contents:
                for line in file_contents[host]:
                    p = re.search('^ip forward-protocol ', line)
                    if p:
                        # udp [port] | nd | sdns
                        filter= line.replace('ip forward-protocol ','').split(' ')
                        protocol = filter[0]
                        port=None
                        if len(filter)>1:
                            port=filter[1]'''


            #...TCP
            #.....ssh, http, TODO: Add ftp, icmp later (not used in our case study)
            for host in file_contents:
                firewall = firewalls[host]
                for line in file_contents[host]:
                    p = re.search('^ssh ', line)
                    r = re.search('^http ', line)
                    z = re.search('^telnet ', line)
                    if p:
                        q= len(line[p.end():].split(' '))
                        if q>=3:
                            source = line[p.end():].split(' ')[0]
                            # check if hostname
                            if self.hostname_lookup.has_key(source):
                                source = self.hostname_lookup[source]
                            source_ip = Util.ConvertStringToIpaddress("%s %s"%(source, line[p.end():].split(' ')[1]))

                            dest_int = line[p.end():].split(' ')[2]
                            dest_ip = None
                            # convert interface name to IP
                            if firewall.interfaces.has_key(dest_int):
                                #we're only interested in individual (interface) ip not entire subnet
                                dest_ip =ipaddr.IPv4Network("%s/%s"% (firewall.interfaces[dest_int].ip_address.ip, '255.255.255.255'))

                            if not self.implicitly_allowed_services_tcp.has_key('ssh'):
                                self.implicitly_allowed_services_tcp['ssh'] = []
                            self.implicitly_allowed_services_tcp['ssh'].append((source_ip,dest_ip))
                    elif r:
                        q= len(line[r.end():].split(' '))
                        if q>=3:
                            source = line[r.end():].split(' ')[0]
                            # check if hostname
                            if self.hostname_lookup.has_key(source):
                                source = self.hostname_lookup[source]
                            source_ip = Util.ConvertStringToIpaddress("%s %s"%(source, line[r.end():].split(' ')[1]))

                            dest_int = line[r.end():].split(' ')[2]
                            dest_ip = None
                            # convert interface name to IP
                            if firewall.interfaces.has_key(dest_int):
                                #we're only interested in individual (interface) ip not entire subnet
                                dest_ip =ipaddr.IPv4Network("%s/%s"% (firewall.interfaces[dest_int].ip_address.ip, '255.255.255.255'))

                            if not self.implicitly_allowed_services_tcp.has_key('http'):
                                self.implicitly_allowed_services_tcp['http'] = []
                            self.implicitly_allowed_services_tcp['http'].append((source_ip,dest_ip))

                    elif z:
                        q= len(line[z.end():].split(' '))
                        if q>=3:
                            source = line[z.end():].split(' ')[0]
                            # check if hostname
                            if self.hostname_lookup.has_key(source):
                                source = self.hostname_lookup[source]
                            try:
                                source_ip = Util.ConvertStringToIpaddress("%s %s"%(source, line[z.end():].split(' ')[1]))
                            except BaseException,e:
                                continue

                            dest_int = line[z.end():].split(' ')[2]
                            dest_ip = None
                            # convert interface name to IP
                            if firewall.interfaces.has_key(dest_int):
                                #we're only interested in individual (interface) ip not entire subnet
                                dest_ip =ipaddr.IPv4Network("%s/%s"% (firewall.interfaces[dest_int].ip_address.ip, '255.255.255.255'))

                            if not self.implicitly_allowed_services_tcp.has_key('telnet'):
                                self.implicitly_allowed_services_tcp['telnet'] = []
                            self.implicitly_allowed_services_tcp['telnet'].append((source_ip,dest_ip))


            # UDP
            #..syslog
            source_ip=None
            server_ip=None
            for host in file_contents:
                firewall = firewalls[host]
                for line in file_contents[host]:
                    p = re.search('^logging ', line)

                    if p:
                        q= len(line[p.end():].split(' '))
                        if q>=1:
                            try:
                                server_ip = ipaddr.IPv4Network("%s/32"%line[p.end():].split(' ')[0])
                            except BaseException, e:
                                if 'source-interface' in line[p.end():].split(' ')[0]:
                                    try:
                                        # get interface ip from firewall object
                                        source_interface_type=line[p.end():].split(' ')[1]
                                        # lookup ipaddress by firewall and interface-type
                                        for interface in firewalls[host].interfaces:
                                            if firewalls[host].interfaces[interface].type.replace(' ','')==source_interface_type:
                                                source_ip=ipaddr.IPv4Network(("%s/32")%(firewalls[host].interfaces[interface].ip_address.ip))
                                                break
                                    except BaseException, e:
                                        pass
                                pass


            if source_ip != None and server_ip!=None:
                if not self.implicitly_allowed_services_udp.has_key('syslog'):
                    self.implicitly_allowed_services_udp['syslog'] = []
                if not self.implicitly_allowed_services_udp['syslog'].__contains__((source_ip,server_ip)):
                    self.implicitly_allowed_services_udp['syslog'].append((source_ip,server_ip))

            # Default output protocol
            default_output_protocols=['telnet']
            # From version 11.1 onwards default has been 'none' (prior was 'all')
            default_input_protocols=['none']
            for host in file_contents:
                count=0
                physical_access_method=dict()
                remote_access_method=dict()
                vty_input_protocols = []
                vty_output_protocols = []

                while count<len(file_contents[host]):
                    line=file_contents[host][count]
                    p = re.search("^line con ", line)
                    q = re.search("^line aux ",line)
                    r = re.search("^line vty ",line)

                    if p:
                        s= len(line[p.end():].split(' '))
                        if not physical_access_method.has_key('console0'):
                            physical_access_method['console0']=dict()
                        # look for transport output command
                        count+=1
                        protocols = None
                        while count<len(file_contents[host]):
                            line = file_contents[host][count]
                            if 'line' in line:
                                count-=1
                                break
                            elif 'transport output ' in line:
                                protocols = line.split('transport output ')[1].split(' ')
                                if protocols!=None:
                                    for protocol in protocols:
                                        physical_access_method['console0']['out']=protocols
                            count+=1
                        if protocols==None:
                            # Set defaults
                            physical_access_method['console0']['out']=default_output_protocols
                    if q:
                        t= len(line[q.end():].split(' '))
                        if not physical_access_method.has_key('aux0'):
                            physical_access_method['aux0']=dict()
                        # look for transport output command
                        count+=1
                        protocols = None
                        while count<len(file_contents[host]):
                            line = file_contents[host][count]
                            if 'line' in line:
                                count-=1
                                break
                            elif 'transport output ' in line:
                                protocols = line.split('transport output ')[1].split(' ')
                                if protocols!=None:
                                    for protocol in protocols:
                                        physical_access_method['aux0']['out']=protocols
                            count+=1
                        if protocols==None:
                            # Set defaults
                            physical_access_method['aux0']['out']=default_output_protocols

                    if r:
                        u= len(line[r.end():].split(' '))
                        if not remote_access_method.has_key('vty'):
                            remote_access_method['vty']=dict()
                        # look for transport commands
                        count+=1
                        while count<len(file_contents[host]):
                            line = file_contents[host][count]
                            if 'line' in line:
                                count-=1
                                break
                            elif 'transport input ' in line:
                                input_protocols = line.split('transport input ')[1].split(' ')
                                if input_protocols!=None:
                                  [vty_input_protocols.append(protocol) for protocol in input_protocols if not vty_input_protocols.__contains__(protocol)]
                                  remote_access_method['vty']['in']=vty_input_protocols
                            elif 'transport output ' in line:
                                output_protocols = line.split('transport output ')[1].split(' ')
                                if output_protocols!=None:
                                    [vty_output_protocols.append(protocol) for protocol in output_protocols if not vty_output_protocols.__contains__(protocol)]
                                    #[vty_output_protocols.append(protocol) for protocol in output_protocols]
                                    remote_access_method['vty']['out']=vty_output_protocols
                            count+=1
                        if len(vty_input_protocols)==0:
                            # Set defaults
                            remote_access_method['vty']['in']=default_input_protocols
                        if len(vty_output_protocols)==0:
                            # Set defaults
                            remote_access_method['vty']['out']=default_output_protocols

                    else:
                        count+=1

                if physical_access_method.has_key('console0') and physical_access_method['console0'].has_key('out'):
                   for protocol in physical_access_method['console0']['out']:
                       if protocol=='none': break
                       if not self.implicitly_allowed_services_tcp.has_key(protocol):
                            self.implicitly_allowed_services_tcp[protocol] = []
                       # currently handles ssh, telnet only
                       #TODO: add later - acercon, lat, mop, nasi, pad, rlogin, udptn, v120: see reference for how to handle
                       for ipaddress in gen_zones[host]['management_data_interface'].ipaddress_list:
                           source_ip=ipaddr.IPv4Network('%s/32'%ipaddress.ip)
                           # dest can be any other zone
                           for interfaces in gen_zones.values():
                                for zone in interfaces.values():
                                    dest_ip=None
                                    if not zone.ContainsSubnetOrIpaddress(source_ip):
                                        dest_ip = zone.ipaddress_list[0]
                                        if not self.implicitly_allowed_services_tcp[protocol].__contains__((source_ip,dest_ip)):
                                            self.implicitly_allowed_services_tcp[protocol].append((source_ip,dest_ip))

                if physical_access_method.has_key('aux0') and physical_access_method['aux0'].has_key('out'):
                   for protocol in physical_access_method['aux0']['out']:
                       if protocol=='none': break
                       if not self.implicitly_allowed_services_tcp.has_key(protocol):
                            self.implicitly_allowed_services_tcp[protocol] = []
                       # currently handles ssh, telnet only
                       #TODO: add later - acercon, lat, mop, nasi, pad, rlogin, udptn, v120: see reference for how to handle
                       for ipaddress in gen_zones[host]['management_data_interface'].ipaddress_list:
                           source_ip=ipaddr.IPv4Network('%s/32'%ipaddress.ip)
                           # dest can be any other zone
                           for interfaces in gen_zones.values():
                                for zone in interfaces.values():
                                    dest_ip=None
                                    if not zone.ContainsSubnetOrIpaddress(source_ip):
                                        dest_ip = zone.ipaddress_list[0]
                                        if not self.implicitly_allowed_services_tcp[protocol].__contains__((source_ip,dest_ip)):
                                            self.implicitly_allowed_services_tcp[protocol].append((source_ip,dest_ip))

                if remote_access_method.has_key('vty') and remote_access_method['vty'].has_key('out'):
                   for protocol in remote_access_method['vty']['out']:
                       if protocol=='none': break
                       if not self.implicitly_allowed_services_tcp.has_key(protocol):
                            self.implicitly_allowed_services_tcp[protocol] = []
                       # currently handles ssh, telnet only
                       #TODO: add later - acercon, lat, mop, nasi, pad, rlogin, udptn, v120: see reference for how to handle
                       for ipaddress in gen_zones[host]['management_data_interface'].ipaddress_list:
                           source_ip=ipaddr.IPv4Network('%s/32'%ipaddress.ip)
                           # dest can be any other zone
                           # TODO access-class may be used with an ACL to restrict dest hosts
                           for interfaces in gen_zones.values():
                                for zone in interfaces.values():
                                    dest_ip=None
                                    if not zone.ContainsSubnetOrIpaddress(source_ip):
                                        dest_ip = zone.ipaddress_list[0]
                                        if not self.implicitly_allowed_services_tcp[protocol].__contains__((source_ip,dest_ip)):
                                            self.implicitly_allowed_services_tcp[protocol].append((source_ip,dest_ip))

                   for protocol in remote_access_method['vty']['in']:
                       if protocol=='none': break
                       if not self.implicitly_allowed_services_tcp.has_key(protocol):
                            self.implicitly_allowed_services_tcp[protocol] = []
                       # currently handles ssh, telnet only
                       #TODO: add later - acercon, lat, mop, nasi, pad, rlogin, udptn, v120: see reference for how to handle
                       for ipaddress in gen_zones[host]['management_data_interface'].ipaddress_list:
                           dest_ip=ipaddr.IPv4Network('%s/32'%ipaddress.ip)
                           # source can be any other zone
                           #TODO access-class may be used with an ACL to restrict source hosts
                           for interfaces in gen_zones.values():
                                for zone in interfaces.values():
                                    source_ip=None
                                    if not zone.ContainsSubnetOrIpaddress(dest_ip):
                                        source_ip = zone.ipaddress_list[0]
                                        if not self.implicitly_allowed_services_tcp[protocol].__contains__((source_ip,dest_ip)):
                                            self.implicitly_allowed_services_tcp[protocol].append((source_ip,dest_ip))

    def ProcessStaticRoutes(self,firewalls, all_zones, file_contents):
        interface_gateways = dict()
        self.potential_route_errors = []
        self.unallocated_gateways =[]
        # Extract any gateways from static routes
        for host in file_contents:
            for line in file_contents[host]:
                # TODO: check ^route (space) still works with asa
                p = re.search('^route ',line)
                q = re.search('^ip route ', line)
                if p:
                    interface_name= line.split(' ')[1]
                    network= ipaddr.IPv4Network("%s/%s" % (line.split(' ')[2],line.split(' ')[3]))
                    gateway_ip=ipaddr.IPv4Address(line.split(' ')[4])
                    # Pragmatic choice of network directly connected to gateway (we don't have real gateway configs to verify)
                    gateway = Gateway(gateway_ip, [network])
                    if not interface_gateways.has_key(gateway.ipaddress):
                       interface_gateways[gateway.ipaddress] = gateway

                    else:
                        # Multiple routes for same gateway
                        #..check non-redundant route
                        is_redundant=False
                        for existing_network in interface_gateways[gateway.ipaddress].network_addresses:
                            if (existing_network == ipaddr.IPv4Network('0.0.0.0/0.0.0.0') or
                                existing_network.__contains__(network)):
                                self.potential_route_errors = []
                                if (not self.potential_route_errors.__contains__(line)):
                                    self.potential_route_errors.append(line)
                                is_redundant= True
                                break
                        if not is_redundant:
                            interface_gateways[gateway.ipaddress].network_addresses.append(network) #add

                if q:
                    line=line.replace('ip route','')
                    network= ipaddr.IPv4Network("%s/%s" % (line.split(' ')[1],line.split(' ')[2]))
                    gateway_ip=ipaddr.IPv4Address(line.split(' ')[3])
                    # Pragmatic choice of network directly connected to gateway (we don't have real gateway configs to veify)
                    gateway = Gateway(gateway_ip, [network])
                    if not interface_gateways.has_key(gateway.ipaddress):
                       interface_gateways[gateway.ipaddress] = gateway

                    else:
                        # Multiple routes for same gateway
                        #..check non-redundant route
                        is_redundant=False
                        for existing_network in interface_gateways[gateway.ipaddress].network_addresses:
                            if (existing_network == ipaddr.IPv4Network('0.0.0.0/0.0.0.0') or
                                existing_network.__contains__(network)):
                                self.potential_route_errors = []
                                if (not self.potential_route_errors.__contains__(line)):
                                    self.potential_route_errors.append(line)
                                is_redundant= True
                                break
                        if not is_redundant:
                            interface_gateways[gateway.ipaddress].network_addresses.append(network) #append

            fw_zones=[]
            # Find the firewall zones
            for interfaces in all_zones.values():
                if interfaces.has_key('management_data_interface'):
                    fw_zones.append(interfaces['management_data_interface'])

            log.info("Linking Gateways to Zones..")
            # Link each gateway found to appropriate zone
            count=1
            for gateway in interface_gateways.values():
                existing_gateway=False
                for fw_zone in fw_zones:
                    if fw_zone.ipaddress_list.__contains__(gateway.ipaddress):
                        # Gateway is an existing firewall/router..no need to create new
                        existing_gateway=True
                        break
                if existing_gateway: continue

                gateway_allocated=False
                for interfaces in all_zones.values():
                    if gateway_allocated: break
                    for zone in interfaces.values():
                        if gateway_allocated: break
                        if zone.ContainsSubnetOrIpaddress(gateway.ipaddress):
                            # gateway can potentially have ACLs and behave as a firewall
                            #..so until we know more about it, treat it as a firewall and keep separate
                            zone.AddGateway(gateway)
                            gateway_allocated=True

                            gateway_name="gw %s"%gateway.ipaddress
                            if not all_zones.has_key(gateway_name):
                                all_zones[gateway_name]=dict()
                            # Gateway connected to respective zone via E0/0
                            all_zones[gateway_name]["Ethernet0/0"]= zone
                            # Firewall-Zone connected to gateway via mdi
                            all_zones[gateway_name]["management_data_interface"]=SecurityZone("fwz(%s)"%gateway_name,[ipaddr.IPv4Network("%s/%s"%(gateway.ipaddress,32))],gateway_name)
                            # Networks (i.e. Unknown-Zones) connected to gateway via E0/1
                            unknown_zone_id="UZ%s"%count
                            all_zones[gateway_name]["Ethernet0/1"]=SecurityZone(unknown_zone_id,gateway.network_addresses,gateway_name)
                            count+=1

                            # Update firewalls list
                            if not firewalls.has_key(gateway_name):
                               firewalls[gateway_name]= Firewall(gateway_name)
                            firewalls[gateway_name].interfaces["Ethernet0/0"]=FirewallInterface("Ethernet0/0","Ethernet0/0","gw_%s"%zone.zone_id,zone.ipaddress_list)
                            firewalls[gateway_name].interfaces["Ethernet0/1"]=FirewallInterface("Ethernet0/1","Ethernet0/1","gw_%s"%unknown_zone_id,gateway.network_addresses)
                            firewalls[gateway_name].interfaces["management_data_interface"]=FirewallInterface("management_data_interface","management_data_interface","management_data_interface",ipaddr.IPv4Network("%s/%s"%(gateway.ipaddress,32)))

                            replace_ip=None
                            excluded=None
                            for ip in zone.ipaddress_list:
                                if ip.__contains__(gateway.ipaddress):
                                    excluded=ip.address_exclude(ipaddr.IPv4Network("%s/32"%gateway.ipaddress))
                                    replace_ip=ip
                                    break
                            if replace_ip!=None: zone.ipaddress_list.remove(replace_ip)
                            for ip in excluded:
                                zone.ipaddress_list.append(ip)

                if (not gateway_allocated) and (not self.unallocated_gateways.__contains__(gateway.ipaddress)):
                    self.unallocated_gateways.append(gateway.ipaddress)


