from exception import ParserException
from device import Firewall, Gateway, FirewallInterface
from security import ACL, InterfaceACL, SecurityZone, SecurityConduit, ConduitFirewallArchitecture, RuleInteraction
from enums import RuleOperation, RuleInteractionType, GraphAttribute, SecurityElement, ServiceProtocol, RuleEffect
from parsers.platform.cisco import CiscoConfigParser
from utilities import Util
from security import AtomicACE
from properties import resources
import matplotlib.pyplot as plt
import networkx as nx
import log
import re
import os
import ipaddr
import shutil

class ConfigParser:

        def __init__(self):
            self.config_files = dict()
            self.file_contents = dict()
            self.delimited = dict()
            self.firewalls=dict()
            self.acl_details = dict()
            self.acls_used = dict()
            self.acl_anomalies = dict()

        def Parse(self, config_folder, output_folder=None):

            if not config_folder:
                raise ValueError('config_folder', resources['value_null'])

            # Set default to be a subfolder in the config directory
            if not output_folder:
                output_folder = os.path.join(os.path.dirname(config_folder),"parser_output") #"C:\parse_output"

            # Cleanup folders
            log.info("Cleaning output directory..")
            self.CleanupFolders(output_folder)

            # Retain for future use
            self.output_folder = output_folder

            # Load configs
            log.info("Reading firewall configuration(s)..")
            for file in os.listdir(config_folder):
                if file.endswith(".txt"):
                    config_file = open(os.path.join(config_folder, file),'r+')
                    file_contents = config_file.read()
                    hostname = Util.GetFirewallHostname(file_contents.split("\n"))
                    if hostname!= None:
                        self.config_files[hostname] =config_file
                        self.file_contents[hostname] =file_contents

            if len(self.file_contents)==0 :
                raise ParserException('config-file folder', resources['folder_empty'])

            for file in self.file_contents:
                self.delimited[file] = self.file_contents[file].split("\n")

            log.info("Processing firewall interface configurations..")
            for file in self.delimited:
                firewall = Firewall(file)
                # Lookup interfaces
                self.acls_used[file]=dict()
                firewall.interfaces = self.ExtractFirewallInterfaces(self.delimited[file], self.acls_used[file])
                if firewall.interfaces == None:
                    raise ParserException(resources['no_interfaces_defined'])

                log.info("Extracting ACL details..")
                if len(self.acls_used[file])==0:
                    # Lookup ACLs applied to these interfaces
                    self.acls_used[file] = self.ExtractACLsAssigned(self.delimited[file])
                self.firewalls[file] = firewall

            # TODO: add as warning instead
            # if self.acls_used == None:
            #   raise ParserException(resources['no_acls_assigned_to_interfaces'])

            # Lookup individual ACL details
            if self.acls_used != None and len(self.acls_used) >0:
                for file in self.acls_used:
                    self.acl_details[file]= self.GetACLDetails(self.acls_used[file], self.delimited[file])
                    # Update firewall ACL info
                    self.firewalls[file].UpdateInterfaceACLs(self.acls_used[file])

            # Create the network security models (i.e. zone-fw and zone-conduit)
            self.zone_firewall_topology = self.BuildSecurityModels(self.firewalls,self.acl_details, self.delimited)

            # Create service overlays
            self.BuildServiceModels(self.firewalls, self.acl_details, self.delimited)

        def ExtractFirewallInterfaces(self, file_contents, acls_used):

            return CiscoConfigParser().ExtractFirewallInterfaces(file_contents, acls_used)

        def ExtractACLsAssigned(self, file_contents):

            return CiscoConfigParser().ExtractACLsAssigned(file_contents)

        def ExtractInterface(self,interface_definition, acls_used):

            return CiscoConfigParser().ExtractInterface(interface_definition, acls_used)

        def GetACLDetails(self, acls_in_use, file_contents):

            acl_collection= CiscoConfigParser().GetACLDetails(acls_in_use, file_contents)
            self.hostname_lookup=CiscoConfigParser().hostname_lookup
            return acl_collection

        def GetObjectGroupItems(self, file_contents):

            self.group_items= CiscoConfigParser().GetObjectGroupItems(file_contents)

        def CleanupFolders(self, parent_folder):

            # Delete and re-create folder structure
            #//service-explicit
                #/tcp, /udp, /ip, /icmp
                    # /host, /zone
            #//service_implicit
                #/tcp, /udp, /ip, /icmp
            #//service_final
                #/tcp, /udp, /ip, /icmp

            explicit_services_folder='service_explicit'
            implicit_services_folder='service_implicit'
            services_final_folder='service_final'
            service_tcp_folder='tcp'
            service_udp_folder='udp'
            service_ip_folder='ip'
            service_icmp_folder='icmp'
            service_eigrp_folder='eigrp'
            host_folder='host'
            zone_folder='zone'

            if os.path.exists(parent_folder):
                shutil.rmtree(parent_folder)
            os.mkdir(parent_folder)
            os.mkdir("%s/%s"%(parent_folder,explicit_services_folder))
            os.mkdir("%s/%s"%(parent_folder,implicit_services_folder))
            os.mkdir("%s/%s"%(parent_folder,services_final_folder))

            os.mkdir("%s/%s/%s"%(parent_folder,explicit_services_folder,service_tcp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,explicit_services_folder,service_udp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,explicit_services_folder,service_ip_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,explicit_services_folder,service_icmp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,explicit_services_folder,service_eigrp_folder))

            os.mkdir("%s/%s/%s"%(parent_folder,implicit_services_folder,service_tcp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,implicit_services_folder,service_udp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,implicit_services_folder,service_ip_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,implicit_services_folder,service_icmp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,implicit_services_folder,service_eigrp_folder))

            os.mkdir("%s/%s/%s"%(parent_folder,services_final_folder,service_tcp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,services_final_folder,service_udp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,services_final_folder,service_ip_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,services_final_folder,service_icmp_folder))
            os.mkdir("%s/%s/%s"%(parent_folder,services_final_folder,service_eigrp_folder))

            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_tcp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_tcp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_udp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_udp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_ip_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_ip_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_icmp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_icmp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_eigrp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,explicit_services_folder,service_eigrp_folder,zone_folder))

            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_tcp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_tcp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_udp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_udp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_ip_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_ip_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_icmp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_icmp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_eigrp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,implicit_services_folder,service_eigrp_folder,zone_folder))

            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_tcp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_tcp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_udp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_udp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_ip_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_ip_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_icmp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_icmp_folder,zone_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_eigrp_folder,host_folder))
            os.mkdir("%s/%s/%s/%s"%(parent_folder,services_final_folder,service_eigrp_folder,zone_folder))

        def BuildSecurityModels(self, firewalls, acl_details, file_contents):
            # Work data
            gen_zones=dict()
            self.explicitly_allowed_services_tcp = dict()
            self.explicitly_allowed_services_udp = dict()
            self.explicitly_allowed_services_icmp = dict()
            self.explicitly_allowed_services_eigrp=dict()
            self.explicitly_allowed_services_ip = dict()
            self.implicitly_allowed_services_ip = dict()
            self.implicitly_allowed_services_tcp= dict()
            self.implicitly_allowed_services_udp= dict()
            self.implicitly_allowed_services_icmp= dict()
            self.final_allowed_services_ip = dict()
            self.final_allowed_services_tcp= dict()
            self.final_allowed_services_udp= dict()
            self.final_allowed_services_icmp= dict()
            self.unallocated = dict()
            self.potential_acl_errors=dict()

            try:

                # Start-off by assigning distinct zones for each FW interface (i.e. initial zfw model)
                log.info("Creating initial zone-firewall model..")
                zone_firewall_top = self.CreateInitialZoneFirewallModel(firewalls, gen_zones, self.output_folder)

                # TODO: Merge zones with overlapping ipaddress spaces
                self.zones_to_merge=[]
                #if acl_details != None and len(acl_details)>0:
                #    self.CheckMergeZones(firewall,acl_details,gen_zones)
                #print("Zone-merge check complete.")

                # Create intermediate zone-fw topology post zone merge
                log.info("Updating zone-firewall model..")
                self.CreateIntermediateZoneFirewallModel(firewalls, gen_zones, self.output_folder)

                # Process static routes
                log.info("Processing static routes..")
                self.ProcessStaticRoutes(firewalls, gen_zones, file_contents)

                # possible route errors
                if self.potential_route_errors != None and len(self.potential_route_errors)>0:
                    log.warning("Redundant routes detected")
                    for error in self.potential_route_errors:
                        log.error('%s'%(error))

                #..and gateways that cannot be allocated to existing zone boundaries
                if self.unallocated_gateways != None and len(self.unallocated_gateways)>0:
                    log.warning("Gateway addresses unallocatable to Zones detected")
                    for gateway in self.unallocated_gateways:
                        log.error('Gateway-%s'%(gateway.ipaddress))

                # Create final zone-firewall model
                log.info("Finalising zone-firewall model..")
                self.CreateFinalZoneFirewallModel(firewalls, gen_zones, self.output_folder,True)

                #  Allocate hosts per zone based on interface ACLs
                self.potential_acl_errors=dict()
                self.intra_acl_interaction_stats=dict()
                self.inter_acl_interaction_stats=dict()

                log.info("Processing ACLs..")
                for host in firewalls:
                    firewall = firewalls[host]
                    for interface in firewall.interfaces:
                        other_zones = []
                        acl_in = None
                        acl_out = None
                        attached_zone = gen_zones[host][firewall.interfaces[interface].type]
                        #for zone in gen_zones:
                        #    if zone!=attached_zone: other_zones.append(zone)
                        if firewall.interfaces[interface].acl.has_key('in'):
                            acl_in = firewall.interfaces[interface].acl['in']
                        if firewall.interfaces[interface].acl.has_key('out'):
                            acl_out = firewall.interfaces[interface].acl['out']

                        # acl_in, attached_zone, other_zones
                        # sources - potentially in attached_zone
                        # dests - potentially in other zones
                        if acl_in != None:
                            log.info("FIREWALL: %s ACL-IN: %s"%(host,acl_in))
                            self.ProcessInboundACL(firewall, interface, acl_in, acl_details, gen_zones)

                        if acl_out !=None:
                            log.info("FIREWALL: %s ACL-OUT: %s"%(host,acl_out))
                            self.ProcessOutboundACL(firewall, interface, acl_out, acl_details, gen_zones)

                        #TODO: process outbound ACLs (none found in our case study)
                log.info("ACL processing complete.")

                #..and acl interactions
                for host in acl_details:
                    for acl in acl_details[host]:
                        entry_list = acl_details[host][acl]
                        if entry_list.IntraACLInteractions !=None:
                            for entry in entry_list.IntraACLInteractions:
                                log.info("Intra-ACL interaction for ACL: %s entry: %s"%(acl,entry))


                for host in self.intra_acl_interaction_stats:
                    for acl in self.intra_acl_interaction_stats[host]:
                        if self.intra_acl_interaction_stats[host][acl].has_key("general"):
                            log.info("Intra-ACL interaction summary: ACL- %s Generalisations: %s"%(acl, self.intra_acl_interaction_stats[host][acl]['general']))
                        if self.intra_acl_interaction_stats[host][acl].has_key("shadow"):
                            log.info("Intra-ACL interaction summary: ACL- %s Shadows: %s"%(acl, self.intra_acl_interaction_stats[host][acl]['shadow']))
                        if self.intra_acl_interaction_stats[host][acl].has_key("conflict"):
                            log.info("Intra-ACL interaction summary: ACL- %s Conflicts: %s"%(acl, self.intra_acl_interaction_stats[host][acl]['conflict']))
                        if self.intra_acl_interaction_stats[host][acl].has_key("overlap"):
                            log.info("Intra-ACL interaction summary: ACL- %s Partial-Overlaps: %s"%(acl, self.intra_acl_interaction_stats[host][acl]['overlap']))


                #..and acl interactions
                #for host in acl_details:
                    #for acl in acl_details[host]:
                        #entry_list = acl_details[host][acl]
                        #for entry in entry_list.EntriesPostIntraACLFiltering:
                            #print("ACL: %s intra-ACL interaction Free Entry- Action: %s Protocols: %s SourceIp: %s SourcePort: %s DestIp: %s DestPort: %s"%(acl,entry.Action,entry.Protocols,entry.SourceIp, entry.SourcePort, entry.DestIp, entry.DestPort))


                # Check whether some acl_errors can now be removed using unknown_zones
                #self.CleanupErrors(gen_zones)

                # Check and warn on acl errors found
                if self.potential_acl_errors != None and len(self.potential_acl_errors)>0:
                    log.warning("Possible ACL errors detected:")
                    for host in self.potential_acl_errors:
                        for acl in self.potential_acl_errors[host]:
                            for ace in self.potential_acl_errors[host][acl]:
                                log.warning('Firewall-%s, ACL-%s, Entry-%s'%(host,acl,ace.rule_core))
                #..and ips that cannot be allocated to existing zones
                if self.unallocated != None and len(self.unallocated)>0:
                    log.warning("Zone-unallocated source or destination addresses detected")
                    for acl in self.unallocated:
                        for address in self.unallocated[acl]:
                            log.warning('ACL-%s, Address-%s'%(acl,address))

                # Create zone-breakdowns
                self.CreateZoneBreakdowns(gen_zones, self.output_folder)

                # Generate zone-conduit topology from zone-gateway topology by extracting conduits
                log.info("Creating Zone-Conduit model..")
                self.CreateZoneConduitModel(self.output_folder, gen_zones)

                # retain generated zones
                self.gen_zones = gen_zones

            except BaseException, e:
                raise ParserException(resources["build_security_models_failed"],e)

        def BuildServiceModels(self, firewalls, acl_details, file_contents):

            try:
                # Process implicit rules
                log.info("Processing Implicit rules..")
                self.ProcessImplicitRules(firewalls, file_contents, self.gen_zones, self.output_folder)

                # Do explicit rule filtering
                log.info("Processing rule interactions..")
                self.DoExplicitRuleFiltering(firewalls, acl_details)

                for host1 in self.inter_acl_interaction_stats:
                    for acl1 in self.inter_acl_interaction_stats[host1]:
                        for host2 in self.inter_acl_interaction_stats[host1][acl1]:
                            for acl2 in self.inter_acl_interaction_stats[host1][acl1][host2]:

                                if self.inter_acl_interaction_stats[host1][acl1][host2][acl2].has_key("general"):
                                    log.info("Inter-ACL interaction summary: ACL1- %s ACL2- %s Generalisations: %s"%(acl1,acl2, self.inter_acl_interaction_stats[host1][acl1][host2][acl2]['general']))
                                if self.inter_acl_interaction_stats[host1][acl1][host2][acl2].has_key("shadow"):
                                    log.info("Inter-ACL interaction summary: ACL1- %s ACL2- %s Shadows: %s"%(acl1,acl2, self.inter_acl_interaction_stats[host1][acl1][host2][acl2]['shadow']))
                                if self.inter_acl_interaction_stats[host1][acl1][host2][acl2].has_key("conflict"):
                                    log.info("Inter-ACL interaction summary: ACL1- %s ACL2- %s Conflicts: %s"%(acl1,acl2, self.inter_acl_interaction_stats[host1][acl1][host2][acl2]['conflict']))
                                if self.inter_acl_interaction_stats[host1][acl1][host2][acl2].has_key("overlap"):
                                    log.info("Inter-ACL interaction summary: ACL1- %s ACL2- %s Partial-Overlaps: %s"%(acl1,acl2, self.inter_acl_interaction_stats[host1][acl1][host2][acl2]['overlap']))


                # Create Explicit service overlays
                log.info("Creating Explicit service-flow views..")
                self.CreateExplicitServiceOverlays(self.output_folder)

                # Create Implicit service overlays
                log.info("Creating Implicit service-flow views..")
                self.CreateImplicitServiceOverlays(self.output_folder)

                # Create final Composite overlays
                #print("Synthesising service-flow views..")
                self.CreateFinalServiceOverlays(self.output_folder)

            except BaseException, e:
                raise ParserException(resources["build_service_models_failed"],e)

        def CreateInitialZoneFirewallModel(self, firewalls, gen_zones, graphml_file_path):

            # work data
            zone_firewall_top = nx.Graph()
            counter=1
            acl_in = ''
            acl_out =''

            firewall_interface_ips = []
            for host in firewalls:
                gen_zones[host] = dict()
                zone_firewall_top.add_node('fw(%s)'%host, type='firewall', label='fw(%s)'%host)
                firewall = firewalls[host]
                for interface in firewall.interfaces:
                    firewall_interface_ips.append(firewall.interfaces[interface].ip_address.ip)

            for host in firewalls:
                firewall = firewalls[host]
                for interface in firewall.interfaces:
                    # Create zone ip address list (i.e. remove firewall interface ips from interface subnet)
                    zone_ip_addresses = firewall.interfaces[interface].ip_address
                    for interface_ip in firewall_interface_ips:
                        if isinstance(zone_ip_addresses, list):
                            replaced_ip = None
                            replacement_ips = None
                            for ip_address in zone_ip_addresses:
                                if isinstance(ip_address, ipaddr.IPv4Network):
                                    if ip_address.__contains__(ipaddr.IPv4Network(interface_ip)):
                                        replaced_ip = ip_address
                                        replacement_ips = ip_address.address_exclude(ipaddr.IPv4Network(interface_ip))
                                        break;
                                elif ip_address==ipaddr.IPv4Address(interface_ip):
                                    replaced_ip = ip_address
                                    replacement_ips = None
                                    break;
                            if replacement_ips != None:
                                zone_ip_addresses.remove(replaced_ip)
                                for replacement_ip in replacement_ips:
                                    zone_ip_addresses.append(replacement_ip)
                        else:
                            if isinstance(zone_ip_addresses, ipaddr.IPv4Network):
                                if zone_ip_addresses.__contains__(ipaddr.IPv4Network(interface_ip)):
                                    zone_ip_addresses = zone_ip_addresses.address_exclude(ipaddr.IPv4Network(interface_ip))
                            else:
                                zone_ip_addresses=None

                    # Check if a zone already exists with this ip list
                    zone=None
                    for id in gen_zones:
                        for existing_zone in gen_zones[id].values():
                            if Util.IsIpaddressListMatch(zone_ip_addresses, existing_zone.ipaddress_list):
                                zone=existing_zone
                                zone_id=zone.zone_id
                                break

                    if zone==None:
                        # Create new
                        zone_id = "z%s"%counter
                        zone_firewall_top.add_node(zone_id, type='zone', ifname=firewall.interfaces[interface].name, label=zone_id)

                    if firewall.interfaces[interface].acl.has_key('in'): acl_in=firewall.interfaces[interface].acl['in']
                    if firewall.interfaces[interface].acl.has_key('out'): acl_out=firewall.interfaces[interface].acl['out']

                    zone_firewall_top.add_edge('fw(%s)'%host, zone_id, is_directed=False, label=firewall.interfaces[interface].type,
                                               acl_in=acl_in,
                                               acl_out=acl_out,
                                               subnet='')
                    gen_zones[host][firewall.interfaces[interface].type] = SecurityZone(zone_id,zone_ip_addresses,'fw(%s)'%host)
                    counter = counter+1

            if graphml_file_path:

                # Save zone-gateway topology to file
                nx.write_graphml(zone_firewall_top, os.path.join(graphml_file_path, "zone_fw_start.graphml"))
                #..and as pdf
                plt.clf()
                pos=nx.spectral_layout(zone_firewall_top) # an example of quick positioning
                nx.draw_networkx(zone_firewall_top, pos)
                plt.savefig(os.path.join(graphml_file_path, "zone_fw_start.pdf"))

            return zone_firewall_top

        def CreateIntermediateZoneFirewallModel(self, firewalls, gen_zones, graphml_file_path):

            acl_in = ''
            acl_out =''
            zone_firewall_top_interim = nx.MultiGraph()
            for host in firewalls:
                firewall_interface_ip_list=[]
                zone_firewall_top_interim.add_node('fw(%s)'%host, type='firewall', label='fw(%s)'%host)
                firewall=firewalls[host]
                for interface in firewall.interfaces:
                    if firewall.interfaces[interface].acl.has_key('in'): acl_in=firewall.interfaces[interface].acl['in']
                    if firewall.interfaces[interface].acl.has_key('out'): acl_out=firewall.interfaces[interface].acl['out']
                    firewall_interface_ip_list.append(ipaddr.IPv4Network(firewall.interfaces[interface].ip_address.ip))

                    zone_id =gen_zones[host][firewall.interfaces[interface].type].zone_id
                    zone_firewall_top_interim.add_node(zone_id, type='zone', ifname=firewall.interfaces[interface].name, label=zone_id)
                    zone_firewall_top_interim.add_edge('fw(%s)'%host, zone_id, is_directed=False, label=firewall.interfaces[interface].type,
                                               acl_in=acl_in,
                                               acl_out=acl_out)

                #..add firewall zone
                firewall.interfaces['management_data_interface']= FirewallInterface('management_data_interface', 'management_data_interface', None, None, 100)
                if(True):
                    zone_firewall_top_interim.add_node('fwz(%s)'%host, type='zone', label='fwz(%s)'%host)
                    zone_firewall_top_interim.add_edge('fw(%s)'%host, 'fwz(%s)'%host, is_directed=False, label='')
                    gen_zones[host]['management_data_interface'] = SecurityZone('fwz(%s)'%host,firewall_interface_ip_list,'fw(%s)'%host)

            if graphml_file_path:

                # Save zone-gateway topology to file
                nx.write_graphml(zone_firewall_top_interim, os.path.join(graphml_file_path, "zone_fw_interim.graphml"))
                #..and as pdf
                plt.clf()
                pos=nx.spectral_layout(zone_firewall_top_interim) # an example of quick positioning
                nx.draw_networkx(zone_firewall_top_interim, pos)
                plt.savefig(os.path.join(graphml_file_path, "zone_fw_interim.pdf"))

            return graphml_file_path

        def CleanupErrors(self, all_zones):
            log.warning('Cleaning up errors..')
            if all_zones != None and len(all_zones) >0:
                   for acl in self.potential_acl_errors:
                        error_entries=[]
                        for ace in self.potential_acl_errors[acl]:
                            #log.info("Potential errors: %s"%ace.Source)
                            if not (self.ZonesContain(ace.Source, all_zones) and
                                    self.ZonesContain(ace.Dest, all_zones)):
                                error_entries.append(ace)
                        self.potential_acl_errors[acl] = error_entries
                   for acl in self.unallocated:
                       unallocated_addresses=[]
                       for address in self.unallocated[acl]:
                           #print("cleaning unallocated: %s"%address)
                           if not self.ZonesContain(address, all_zones):
                               unallocated_addresses.append(address)
                       self.unallocated[acl] = unallocated_addresses

        def ZonesContain(self, address_entry, zones):
            ipaddress=None
            if address_entry!=None:
                parts = address_entry.split(' ')
                if parts!=None and len(parts)>=2:
                    if parts[0]=='host':
                        ipaddress=ipaddr.IPv4Network('%s/%s'%(parts[1],32))
                    else:
                        ipaddress=ipaddr.IPv4Network('%s/%s'%(parts[0],parts[1]))

            for id in zones:
                for existing_zone in zones[id].values():
                    if isinstance(existing_zone.ipaddress_list, list):
                        for address in existing_zone.ipaddress_list:
                            if address==ipaddr.IPv4Network("0.0.0.0/0.0.0.0"):
                                #log.info("ZonesContain(TRUE-default1): %s in zone: %s"%(address_entry, existing_zone.zone_id))
                                return True
                            elif isinstance(address, ipaddr.IPv4Network) and address.__contains__(ipaddress):
                                #log.info("ZonesContain(TRUE): %s in zone: %s"%(address_entry, existing_zone.zone_id))
                                return True
                            elif isinstance(address, ipaddr.IPv4Address) and address==ipaddress:
                                #log.info("ZonesContain(TRUE): %s in zone: %s"%(address_entry, existing_zone.zone_id))
                                return True

                    elif isinstance(existing_zone.ipaddress_list, ipaddr.IPv4Address):
                        if existing_zone.ipaddress_list==ipaddr.IPv4Address("0.0.0.0"):
                                #log.info("ZonesContain(TRUE-default2): %s in zone: %s"%(address_entry, existing_zone.zone_id))
                                return True
                        elif ipaddr.IPv4Network("%s/%s"%(existing_zone.ipaddress_list,32)).__contains__(ipaddress):
                            #log.info("ZonesContain(TRUE): %s in zone: %s"%(address_entry, existing_zone.zone_id))
                            return True
                    else:
                        log.err ("Invalid IPaddress list type")

            #log.info("ZonesContain(FALSE): %s"%(address_entry))
            return False

        def CreateFinalZoneFirewallModel(self, firewalls, gen_zones, graphml_file_path, add_dedicated_firewall_zone=False):
            # Generate final zone-fw topology
            acl_in = ''
            acl_out =''
            zone_firewall_top_end = nx.MultiGraph()
            self.unknown_zones=dict()

            fw_zones=[]
            # Find the firewall zones
            for interfaces in gen_zones.values():
                if interfaces.has_key('management_data_interface'):
                    fw_zones.append(interfaces['management_data_interface'])

            # tracks zones to be linked via carrier zone
            zones_to_replace_with_carrier=[]
            firewalls_to_link_with_abstract_zone=[]
            for host in firewalls:
                firewall=firewalls[host]
                for interface in firewall.interfaces:
                    zone_id = gen_zones[host][firewall.interfaces[interface].type].zone_id
                    if 'UZ' in zone_id and Util.HasDefaultSubnetZero(gen_zones[host][firewall.interfaces[interface].type].ipaddress_list):
                        if not zones_to_replace_with_carrier.__contains__((host,firewall.interfaces[interface].type)): zones_to_replace_with_carrier.append((host,firewall.interfaces[interface].type))
                    # debug dr NEW - check what the right condition should be to determine if interface connects to another fw directly
                    if zone_id =='' or zone_id=='firewall':
                        # interface connects to another fw directly
                        if not firewalls_to_link_with_abstract_zone.__contains__((host,firewall.interfaces[interface].type)): firewalls_to_link_with_abstract_zone.append((host,firewall.interfaces[interface].type))
                    # end debug dr

            # Link zones using carrier-zone
            if len(zones_to_replace_with_carrier) >1:
                # Create carrier zone
                carrier_zone=SecurityZone("CRZ", [ipaddr.IPv4Network("0.0.0.0/0")], 'test')
                # Replace applicable zones with the carrier zone
                for info in zones_to_replace_with_carrier:
                    gen_zones[info[0]][info[1]]=carrier_zone
                    
            # debug dr NEW - Link firewalls with Abstract zones
            count=1
            if len(firewalls_to_link_with_abstract_zone) > 1:
                # create abstract zone - TODO: what IP range do we use? (all IPs except firewall interface addresses?)
                abstract_zone=SecurityZone('AZ%s'%count,[ipaddr.IPv4Network("0.0.0.0/0")],"test")
                # link firewalls via it
                for info in firewalls_to_link_with_abstract_zone:
                    gen_zones[info[0]][info[1]]=abstract_zone
            # end debug dr

            # create zone-firewall model
            for host in firewalls:
                zone_firewall_top_end.add_node('fw(%s)'%host, type='firewall', label='fw(%s)'%host)
                firewall=firewalls[host]
                for interface in firewall.interfaces:
                    if firewall.interfaces[interface].acl.has_key('in'): acl_in=firewall.interfaces[interface].acl['in']
                    if firewall.interfaces[interface].acl.has_key('out'): acl_out=firewall.interfaces[interface].acl['out']
                    zone_id = gen_zones[host][firewall.interfaces[interface].type].zone_id
                    zone_firewall_top_end.add_node(zone_id, type='zone', ifname=firewall.interfaces[interface].name, label=zone_id)
                    zone_firewall_top_end.add_edge('fw(%s)'%host, zone_id, is_directed=False, label=firewall.interfaces[interface].type,
                                               acl_in=acl_in,
                                               acl_out=acl_out)
                    zone=gen_zones[host][firewall.interfaces[interface].type]
                    for element in gen_zones[host][firewall.interfaces[interface].type].ipaddress_list:
                        if (not zone.ContainsSubElement(element)):
                            if element.prefixlen ==32 and element.ip!=element.network:
                                # host
                                t="host %s"%element.ip
                                #print('zone:%s allocating:%s'%(t,zone.zone_id))
                                zone.AddSubElement("host %s"%element.ip, True)
                            else:
                                # subnet
                                l="%s/%s"%(element.network,element.prefixlen)
                                #print('zone:%s allocating:%s'%(l,zone.zone_id))
                                zone.AddSubElement("%s/%s"%(element.network,element.prefixlen),True)




                #gen_zones['test']=dict()
                #gen_zones['test']['test']=SecurityZone('car-z', ipaddr.IPv4Network("0.0.0.0/0"),'test')
                #zone_firewall_top_end.add_node('CRZ', type='zone', ifname='car-if', label='car-z')
                #zone_firewall_top_end.add_edge(zones_to_replace_with_carrier[0], 'car-z', is_directed=False, label='0',
                #                               acl_in='0',
                #                              acl_out='0')
                #zone_firewall_top_end.add_edge(zones_to_replace_with_carrier[1], 'car-z', is_directed=False, label='0',
                #                               acl_in='0',
                #                               acl_out='0')

            '''
            unknown_zone_id=1
            #..and add any gateways found
            for interfaces in gen_zones.values():
                for zone in interfaces.values():
                    #print("gateways found for zone: %s count: %s"%(zone.zone_id,len(zone.Gateways)))
                    for gateway in zone.Gateways:
                        # check if gateway is an existing firewall
                        existing_gateway=False
                        for fw_zone in fw_zones:
                            if fw_zone.ipaddress_list.__contains__(gateway.ipaddress):
                                # Existing gateway..no need to create new
                                #print("Existing gateway- %s"%gateway.ipaddress)
                                existing_gateway=True
                                break
                        if existing_gateway: continue

                        print("gateway- %s"%gateway.ipaddress)
                        gateway_name = "gw %s"%gateway.ipaddress
                        # Treat gateway as a firewall (worse case)
                        zone_firewall_top_end.add_node(gateway_name,type='firewall',label=gateway_name)
                        zone_firewall_top_end.add_edge(zone.zone_id,gateway_name,is_directed=False, label="Ethernet0/0", acl_in="", acl_out="")
                        # Add unknown zones attached to gateway
                        unknown_zone = SecurityZone("UZ%s"%unknown_zone_id, gateway.connected_network_addresses, gateway_name)
                        zone_firewall_top_end.add_node(unknown_zone.zone_id,type='zone',label=unknown_zone.zone_id)
                        zone_firewall_top_end.add_edge(unknown_zone.zone_id,gateway_name,is_directed=False, label="Ethernet0/1", acl_in="", acl_out="")
                        if not self.unknown_zones.has_key(gateway_name):
                            self.unknown_zones[gateway_name]= dict()
                        if not self.unknown_zones[gateway_name].has_key("Ethernet0/1"):
                            self.unknown_zones[gateway_name]["Ethernet0/1"] = []
                        self.unknown_zones[gateway_name]["Ethernet0/1"].append(unknown_zone)
                        unknown_zone_id = unknown_zone_id+1

                        #..add firewall zone
                        firewall.interfaces['management_data_interface']= FirewallInterface('management_data_interface', 'management_data_interface', None, 100)
                        if(True):
                            zone_firewall_top_interim.add_node('fwz(%s)'%host, type='zone', label='fwz(%s)'%host)
                            zone_firewall_top_interim.add_edge('fw(%s)'%host, 'fwz(%s)'%host, is_directed=False, label='')
                            gen_zones[host]['management_data_interface'] = SecurityZone('fwz(%s)'%host,firewall_interface_ip_list,'fw(%s)'%host)


            # Append unknown zones found to gen_zones
            for gw in self.unknown_zones:
                gateway = self.unknown_zones[gw]
                for interface in gateway:
                    unknown_zones=gateway[interface]
                    for zone in unknown_zones:
                        if not gen_zones.has_key(gw):
                            gen_zones[gw]=dict()
                        gen_zones[gw][interface] = zone'''


            if graphml_file_path:

                # Save zone-gateway topology to file
                nx.write_graphml(zone_firewall_top_end, os.path.join(graphml_file_path, "zone_fw_end.graphml"))
                #..and as pdf
                plt.clf()
                pos=nx.spectral_layout(zone_firewall_top_end) # an example of quick positioning
                nx.draw_networkx(zone_firewall_top_end, pos)
                plt.savefig(os.path.join(graphml_file_path, "zone_fw_end.pdf"))

                self.zone_firewall_top = zone_firewall_top_end

        def CreateZoneConduitModel(self, graphml_file_path, all_zones):

            # Generate zone-conduit topology from zone-firewall topology
            # Work data
            zones = []
            conduits= []
            conduitId = 1
            processedPairs = []

            # Find all possible non-loop paths between distinct pair of zones
            for node in self.zone_firewall_top.nodes_iter():
                if (self.zone_firewall_top.node[node].get(GraphAttribute.Type) == SecurityElement.Zone): zones.append(node)
            for zone1 in zones:
                for zone2 in zones:
                    zoneCombo = (zone1,zone2)
                    if(zone1!=zone2 and not processedPairs.__contains__(zoneCombo)):
                        allPaths = nx.all_simple_paths(self.zone_firewall_top, source=zone1, target=zone2)
                        # Filter out those paths containing zones as they are in-eligible
                        firewallOnlyPaths = []
                        for path in allPaths:
                            path.remove(zone1)
                            path.remove(zone2)
                            if Util.IsZoneFreePath(path, self.zone_firewall_top):
                                interface1=None
                                interface2=None
                                firewall = Util.ConvertToFirewallPath(path, self.zone_firewall_top)[0]
                                if self.zone_firewall_top.has_edge(path[0],zone1):
                                    interface1=self.zone_firewall_top.get_edge_data(path[0],zone1)[0][GraphAttribute.Label]
                                if self.zone_firewall_top.has_edge(path[0],zone2):
                                    interface2=self.zone_firewall_top.get_edge_data(path[0],zone2)[0][GraphAttribute.Label]
                                firewallOnlyPaths.append([interface1, firewall, interface2])

                        if len(firewallOnlyPaths) >0:
                            # Create new conduit
                            conduit = SecurityConduit("c" + str(conduitId), [self.zone_firewall_top.node[zone1].get(GraphAttribute.Label), self.zone_firewall_top.node[zone2].get(GraphAttribute.Label)])
                            # Construct conduit-firewall architecture
                            conduitArchitecture = ConduitFirewallArchitecture()

                            for path in firewallOnlyPaths:
                                conduitArchitecture.AddParallelFirewallPath(path)

                            conduit.SetFirewallArchitecture(conduitArchitecture)
                            conduits.append(conduit)
                            conduitId = conduitId + 1
                        processedPairs.append(zoneCombo)
                        processedPairs.append((zone2,zone1))

            # Create zone-conduit topology
            self.zone_conduit_top = nx.Graph()
            for conduit in conduits:

                parallelPaths = ""
                for firewallPath in conduit.GetFirewallArchitecture().GetParallelFirewallPaths():
                    # get the correct path orientation with respective to source and dest zones
                    firewallPath = self.GetFirewallPathOrientedForSourceZone(firewallPath, conduit.GetAttachedZones()[0], self.firewalls, all_zones)
                    parallelPaths = parallelPaths + '~[' + ','.join(firewallPath) + ']'

                self.zone_conduit_top.add_edge(conduit.GetAttachedZones()[0], conduit.GetAttachedZones()[1], is_directed=False, label=conduit.GetId(), type=SecurityElement.Conduit, firewallPaths=parallelPaths)
                self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.Label] = conduit.GetAttachedZones()[0]
                self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.Type] = SecurityElement.Zone
                self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.Label] = conduit.GetAttachedZones()[1]
                self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.Type] = SecurityElement.Zone

                zone0 = None
                zone1 = None
                for node in self.zone_firewall_top.nodes_iter():
                    if self.zone_firewall_top.node[node][GraphAttribute.Label] == conduit.GetAttachedZones()[0]:
                        zone0 = self.zone_firewall_top.node[node]
                    elif self.zone_firewall_top.node[node][GraphAttribute.Label] == conduit.GetAttachedZones()[1]:
                        zone1 = self.zone_firewall_top.node[node]

                # TODO: is it useful to save zone contents in graphml attributes?
                '''
                if zone0!=None:
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.HostIds] = zone0[GraphAttribute.HostIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.ServerIds] = zone0[GraphAttribute.ServerIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.SwitchIds] = zone0[GraphAttribute.SwitchIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.RouterIds] = zone0[GraphAttribute.RouterIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[0]][GraphAttribute.InterfaceIds] = zone0[GraphAttribute.InterfaceIds]

                if zone1!=None:
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.HostIds] = zone1[GraphAttribute.HostIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.ServerIds] = zone1[GraphAttribute.ServerIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.SwitchIds] = zone1[GraphAttribute.SwitchIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.RouterIds] = zone1[GraphAttribute.RouterIds]
                    self.zone_conduit_top.node[conduit.GetAttachedZones()[1]][GraphAttribute.InterfaceIds] = zone1[GraphAttribute.InterfaceIds]'''

            try:

                if graphml_file_path:

                    # Save zone-conduit topology to file
                    nx.write_graphml(self.zone_conduit_top, os.path.join(graphml_file_path, "zone_conduit.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spectral_layout(self.zone_conduit_top) # an example of quick positioning
                    nx.draw_networkx(self.zone_conduit_top, pos)
                    plt.savefig(os.path.join(graphml_file_path, "zone_conduit.pdf"))

            except BaseException, e:
                raise Exception.ParserException(resources["zone_conduit_topology_create_failed"],e)

        def GetFirewallPathOrientedForSourceZone(self, firewall_path, source_zone, firewalls, all_zones):
            if len(firewall_path)>=3:
                zone1=None
                zone2=None
                interface1_type=firewall_path[0]
                firewall_name=firewall_path[1].replace('fw(','').replace(')','')
                if firewalls.has_key(firewall_name):
                    for interface in firewalls[firewall_name].interfaces.values():
                        if interface.type==interface1_type:
                            if all_zones[firewall_name][interface1_type].zone_id==source_zone:
                                return firewall_path
                            else:
                                # Reverse orientation
                                reversed_path=[]
                                count=len(firewall_path)
                                while count>0:
                                    reversed_path.append(firewall_path[count-1])
                                    count-=1
                                return reversed_path
                return None

        def ProcessImplicitRules(self, firewalls, file_contents, gen_zones, graphml_file_path):

            CiscoConfigParser().ProcessImplicitRules(firewalls, file_contents, gen_zones, graphml_file_path)

            self.implicitly_allowed_services_ip = CiscoConfigParser().implicitly_allowed_services_ip
            self.implicitly_allowed_services_tcp= CiscoConfigParser().implicitly_allowed_services_tcp
            self.implicitly_allowed_services_udp= CiscoConfigParser().implicitly_allowed_services_udp
            self.implicitly_allowed_services_icmp= CiscoConfigParser().implicitly_allowed_services_icmp

        def GetNodeById(self, id, graph):

            if not id:
                raise ValueError("id", resources['value_null'])
            if not graph:
                raise ValueError("graph", resources['value_null'])

            for node in graph.nodes_iter():
                zoneId = graph.node[node].get(GraphAttribute.Label)
                if zoneId == id: return node
            return None

        def GetEdges(self, graph, node1, node2):
            edge_list=[]
            for e in graph.edges(data=True):
                if node1 in e and node2 in e:
                    edge_list.append(e)
            return edge_list

        def GetFirewallInterfaceNameByType(self, firewall, interface_type):
            for interface in firewall.interfaces.values():
                if interface.type==interface_type:
                    return interface.name.replace(' ','')
            return None

        def DoInterACLFiltering(self,firewalls, acl_details):

            all_zones_list= []
            for interfaces in self.gen_zones.values():
                for zone in interfaces.values():
                    all_zones_list.append(zone)

            self.potentially_interacting_acls=dict()

            # Work data
            acl_details_lookup=dict()

            for host in firewalls:
                firewall=firewalls[host]
                for interface in firewall.interfaces:
                    other_zones = []
                    acl_in = None
                    acl_out = None
                    if firewall.interfaces[interface].acl.has_key('in'):
                        acl_in = firewall.interfaces[interface].acl['in']
                    if firewall.interfaces[interface].acl.has_key('out'):
                        acl_out = firewall.interfaces[interface].acl['out']

                    if not acl_details.has_key(host): continue
                    if not acl_details[host].has_key(acl_in):continue

                    interaction_free_entries=[]
                    interactions=[]

                    if acl_in!=None:
                        for entry in acl_details[host][acl_in].EntriesPostIntraACLFiltering:

                            # Evaluate the traffic path involved with entry
                            source_zone=None
                            dest_zone=None

                            for zone in all_zones_list:
                                if entry.SourceIp!=None and zone.ContainsSubnetOrIpaddress(entry.SourceIp) and source_zone==None:
                                    source_zone=zone
                                elif entry.DestIp!=None and zone.ContainsSubnetOrIpaddress(entry.DestIp) and dest_zone==None:
                                    dest_zone=zone

                            if source_zone!=None and dest_zone!=None:
                                start = self.GetNodeById(source_zone.zone_id, self.zone_conduit_top)
                                end = self.GetNodeById(dest_zone.zone_id, self.zone_conduit_top)

                                # Identify path between zones
                                paths=None
                                try:
                                    paths = list(nx.all_simple_paths(self.zone_conduit_top, source=start, target=end, cutoff=6))

                                except BaseException, e:
                                    log.error(e)
                                    raise ParserException(resources['zone_paths_determination_failed'],
                                                                               "source=%s dest=%s" % (start, end),
                                                                                 e)

                                # Paths should not include any that requires relaying traffic through a firewall-zone
                                #..this is because FWZ only initiate or accept traffic to themselves
                                #..also a valid path should not have multiple conduits using same firewall (i.e. loops formed with firewall) ??
                                filtered_paths=[]
                                for path in paths:
                                    path_uses_fwz=False
                                    start=1
                                    end=len(path)-1
                                    for path_node in path[start:end]:
                                        if 'fwz' in path_node:
                                            path_uses_fwz=True
                                            break

                                    if not path_uses_fwz:
                                        filtered_paths.append(path)

                                # ...what ACLs lie in those path-> potentially interacting ACLs
                                final_valid_paths=dict()
                                for path in filtered_paths:
                                    count=0
                                    firewalls_in_path=[]
                                    # Identify conduits in path
                                   # log.info('Filtered firewall path: %s'%path)
                                    potentially_interacting_acls_temp=dict()
                                    is_path_valid=True
                                    for path_node in path:
                                        if count <= len(path)-2:
                                            inbound_firewall_interface=None
                                            outbound_firewall_interface=None
                                            conduit_fw=None

                                            edges= self.GetEdges(self.zone_conduit_top, path_node, path[count+1])
                                            conduit_firewall_path= edges[0][2]['firewallPaths'].split('~')[1].replace('[','').replace(']','')

                                            conduit_firewall_path = self.GetFirewallPathOrientedForSourceZone(conduit_firewall_path.split(','),path_node,firewalls,self.gen_zones)

                                            #if edges[0][0]==path_node:
                                            inbound_firewall_interface = conduit_firewall_path[0]
                                            outbound_firewall_interface = conduit_firewall_path[2]
                                            conduit_fw= conduit_firewall_path[1].replace('fw','').replace('(','').replace(')','')

                                            if not firewalls_in_path.__contains__(conduit_fw):
                                                firewalls_in_path.append(conduit_fw)
                                            else:
                                                # TODO: This may need to be included: Firewall already encountered once in path..so this is a loop forming path..discard
                                                # log.info("Firewall loop in path: %s (omitted)"%path)
                                                is_path_valid=False
                                                break

                                            inbound_name= self.GetFirewallInterfaceNameByType(firewalls[conduit_fw], inbound_firewall_interface)
                                            outbound_name= self.GetFirewallInterfaceNameByType(firewalls[conduit_fw], outbound_firewall_interface)

                                            #debug
                                            #log.info("conduit_fw: %s outbound_name: %s"%(conduit_fw,outbound_name))

                                            if firewalls[conduit_fw].interfaces[inbound_name].acl.has_key('in'):
                                                acl=firewalls[conduit_fw].interfaces[inbound_name].acl['in']
                                                # ACL cannot interact with itself
                                                if not (conduit_fw==host and acl==acl_in):
                                                    if not potentially_interacting_acls_temp.has_key((host,acl_in)):
                                                        potentially_interacting_acls_temp[(host,acl_in)]=[]
                                                    if not potentially_interacting_acls_temp[(host,acl_in)].__contains__((conduit_fw,acl)):
                                                        potentially_interacting_acls_temp[(host,acl_in)].append((conduit_fw,acl))
                                                    if not acl_details_lookup.has_key(acl_in):
                                                        acl_details_lookup[acl_in]=acl_details[host][acl_in].EntriesPostIntraACLFiltering
                                                    if not acl_details_lookup.has_key(acl):
                                                        acl_details_lookup[acl]=acl_details[conduit_fw][acl].EntriesPostIntraACLFiltering

                                            if firewalls[conduit_fw].interfaces[outbound_name].acl.has_key('out'):
                                                acl=firewalls[conduit_fw].interfaces[outbound_name].acl['out']
                                                if not potentially_interacting_acls_temp.has_key((host,acl_in)):
                                                        potentially_interacting_acls_temp[(host,acl_in)]=[]
                                                if not potentially_interacting_acls_temp[(host,acl_in)].__contains__((conduit_fw,acl)):
                                                    potentially_interacting_acls_temp[(host,acl_in)].append((conduit_fw,acl))
                                                if not acl_details_lookup.has_key(acl_in):
                                                    acl_details_lookup[acl_in]=acl_details[host][acl_in].EntriesPostIntraACLFiltering
                                                if not acl_details_lookup.has_key(acl):
                                                    acl_details_lookup[acl]=acl_details[conduit_fw][acl].EntriesPostIntraACLFiltering

                                            #TODO: check for acl-outs as well: not present in our case study
                                            count+=1

                                    if is_path_valid:
                                        for tuple1 in potentially_interacting_acls_temp:
                                            if not self.potentially_interacting_acls.has_key(tuple1):
                                                self.potentially_interacting_acls[tuple1]=[]
                                            for tuple2 in potentially_interacting_acls_temp[tuple1]:
                                                if not self.potentially_interacting_acls[tuple1].__contains__(tuple2):
                                                    self.potentially_interacting_acls[tuple1].append(tuple2)

                    '''
                    if acl_out!=None:
                        for entry in acl_details[host][acl_out].EntriesPostIntraACLFiltering:

                            # Evaluate the traffic path involved with entry
                            source_zone=None
                            dest_zone=None

                            for zone in all_zones_list:
                                if entry.SourceIp!=None and zone.ContainsSubnetOrIpaddress(entry.SourceIp) and source_zone==None:
                                    source_zone=zone
                                elif entry.DestIp!=None and zone.ContainsSubnetOrIpaddress(entry.DestIp) and dest_zone==None:
                                    dest_zone=zone

                            if source_zone!=None and dest_zone!=None:
                                start = self.GetNodeById(source_zone.zone_id, self.zone_conduit_top)
                                end = self.GetNodeById(dest_zone.zone_id, self.zone_conduit_top)

                                # Identify path between zones
                                paths=None
                                try:
                                    paths = list(nx.all_simple_paths(self.zone_conduit_top, source=start, target=end))

                                except BaseException, e:
                                    raise ParserException(resources['zone_paths_determination_failed'],
                                                                               "source=%s dest=%s" % (start, end),
                                                                                 e)

                                # Paths should not include any that requires relaying traffic through a firewall-zone
                                #..this is because FWZ only initiate or accept traffic to themselves
                                #..also a valid path should not have multiple conduits using same firewall (i.e. loops formed with firewall) ??
                                filtered_paths=[]
                                for path in paths:
                                    path_uses_fwz=False
                                    start=1
                                    end=len(path)-1
                                    for path_node in path[start:end]:
                                        if 'fwz' in path_node:
                                            path_uses_fwz=True
                                            break

                                    if not path_uses_fwz:
                                        filtered_paths.append(path)

                                # ...what ACLs lie in those path-> potentially interacting ACLs
                                final_valid_paths=dict()
                                for path in filtered_paths:
                                    count=0
                                    firewalls_in_path=[]
                                    # Identify conduits in path
                                   # print('Filtered firewall path: %s'%path)
                                    potentially_interacting_acls_temp=dict()
                                    is_path_valid=True
                                    for path_node in path:
                                        if count <= len(path)-2:
                                            inbound_firewall_interface=None
                                            outbound_firewall_interface=None
                                            conduit_fw=None

                                            edges= self.GetEdges(self.zone_conduit_top, path_node, path[count+1])
                                            conduit_firewall_path= edges[0][2]['firewallPaths'].split('~')[1].replace('[','').replace(']','')

                                            conduit_firewall_path = self.GetFirewallPathOrientedForSourceZone(conduit_firewall_path.split(','),path_node,firewalls,self.gen_zones)

                                            #if edges[0][0]==path_node:
                                            inbound_firewall_interface = conduit_firewall_path[0]
                                            outbound_firewall_interface = conduit_firewall_path[2]
                                            conduit_fw= conduit_firewall_path[1].replace('fw','').replace('(','').replace(')','')

                                            if not firewalls_in_path.__contains__(conduit_fw):
                                                firewalls_in_path.append(conduit_fw)
                                            else:
                                                # TODO: This may need to be included: Firewall already encountered once in path..so this is a loop forming path..discard
                                                # print("Firewall loop in path: %s (omitted)"%path)
                                                is_path_valid=False
                                                break

                                            inbound_name= self.GetFirewallInterfaceNameByType(firewalls[conduit_fw], inbound_firewall_interface)
                                            outbound_name= self.GetFirewallInterfaceNameByType(firewalls[conduit_fw], outbound_firewall_interface)

                                            #debug
                                            #print("outbound ACL- conduit_fw: %s outbound_name: %s"%(conduit_fw,outbound_name))

                                            if firewalls[conduit_fw].interfaces[inbound_name].acl.has_key('in'):
                                                acl=firewalls[conduit_fw].interfaces[inbound_name].acl['in']
                                                if not potentially_interacting_acls_temp.has_key((host,acl_out)):
                                                    potentially_interacting_acls_temp[(host,acl_out)]=[]
                                                if not potentially_interacting_acls_temp[(host,acl_out)].__contains__((conduit_fw,acl)):
                                                    potentially_interacting_acls_temp[(host,acl_out)].append((conduit_fw,acl))
                                                if not acl_details_lookup.has_key(acl_out):
                                                    acl_details_lookup[acl_out]=acl_details[host][acl_out].EntriesPostIntraACLFiltering
                                                if not acl_details_lookup.has_key(acl):
                                                    acl_details_lookup[acl]=acl_details[conduit_fw][acl].EntriesPostIntraACLFiltering

                                            if firewalls[conduit_fw].interfaces[outbound_name].acl.has_key('out'):
                                                acl=firewalls[conduit_fw].interfaces[outbound_name].acl['out']
                                                # ACL cannot interact with itself
                                                if not (conduit_fw==host and acl==acl_out):
                                                    if not potentially_interacting_acls_temp.has_key((host,acl_out)):
                                                            potentially_interacting_acls_temp[(host,acl_out)]=[]
                                                    if not potentially_interacting_acls_temp[(host,acl_out)].__contains__((conduit_fw,acl)):
                                                        potentially_interacting_acls_temp[(host,acl_out)].append((conduit_fw,acl))
                                                    if not acl_details_lookup.has_key(acl_out):
                                                        acl_details_lookup[acl_out]=acl_details[host][acl_out].EntriesPostIntraACLFiltering
                                                    if not acl_details_lookup.has_key(acl):
                                                        acl_details_lookup[acl]=acl_details[conduit_fw][acl].EntriesPostIntraACLFiltering

                                            #TODO: check for acl-outs as well: not present in our case study
                                            count+=1

                                    if is_path_valid:
                                        for tuple1 in potentially_interacting_acls_temp:
                                            if not self.potentially_interacting_acls.has_key(tuple1):
                                                self.potentially_interacting_acls[tuple1]=[]
                                            for tuple2 in potentially_interacting_acls_temp[tuple1]:
                                                if not self.potentially_interacting_acls[tuple1].__contains__(tuple2):
                                                    self.potentially_interacting_acls[tuple1].append(tuple2)'''

            self.interaction_free_acls = dict()
            acl_host=None
            for tuple1 in self.potentially_interacting_acls:

                acl_host=self.GetHostByACL(acl_details, tuple1[1])
                # set initial rule-set (pending filtering)
                acl1_interaction_free_ruleset=acl_details_lookup[tuple1[1]]
                interacting_acls=self.potentially_interacting_acls[tuple1]
                #log.info("inter-ACL interactions found for ACL: %s with %s others"%(acl1,len(interacting_acls)))
                for tuple2 in interacting_acls:
                    #acl2='103'
                    log.info('Evaluating inter-ACL interactions between: FIREWALL:%s ACL:%s and FIREWALL:%s ACL:%s..'%(tuple1[0], tuple1[1], tuple2[0], tuple2[1]))
                    acl1_acl2_interaction_free_ruleset=self.CheckInterACLInteractions(tuple1[0], tuple1[1], acl1_interaction_free_ruleset, tuple2[0], tuple2[1], acl_details_lookup[tuple2[1]], acl_details[acl_host][tuple1[1]])
                    acl1_interaction_free_ruleset=[]
                    for rule in acl1_acl2_interaction_free_ruleset: acl1_interaction_free_ruleset.append(rule)
                    #break

                self.interaction_free_acls[tuple1[1]]=acl1_interaction_free_ruleset
                acl_details[acl_host][tuple1[1]].EntriesPostInterACLFiltering = acl1_interaction_free_ruleset
                #break

            # If no inter-ACL interactions, final entry list is identical to post intra-ACL list
            for host in acl_details:
                for acl in acl_details[host]:
                    if acl_details[host][acl].EntriesPostInterACLFiltering == None:
                        acl_details[host][acl].EntriesPostInterACLFiltering = acl_details[host][acl].EntriesPostIntraACLFiltering

            # dump inter-ACL interactions
            for host in acl_details:
                for acl1 in acl_details[host]:
                    if acl_details[host][acl1].InterACLInteractions !=None:
                        for entry in acl_details[host][acl1].InterACLInteractions:
                            log.info("inter-ACL interaction - %s"%(entry))

            # dump net result
            '''
            for host in acl_details:
                for acl1 in acl_details[host]:
                    for entry in acl_details[host][acl1].EntriesPostInterACLFiltering:
                        print("ACL: %s Interaction Free Entry- Action: %s Protocols: %s SourceIp: %s SourcePort: %s DestIp: %s DestPort: %s"%(acl1,entry.Action,entry.Protocols,entry.SourceIp, entry.SourcePort, entry.DestIp, entry.DestPort))
            '''

        def GetHostByACL(self, acl_details, acl_name):
            for host in acl_details:
                if acl_details[host].has_key(acl_name): return host
            return None

        def CheckInterACLInteractions(self, acl1_host, acl1_name, acl1, acl2_host, acl2_name, acl2, acl_details):
            acl1_acl2_interaction_free_ruleset=[]
            inter_acl_interaction_entries=[]

            if not self.inter_acl_interaction_stats.has_key(acl1_host):
                self.inter_acl_interaction_stats[acl1_host]=dict()
            if not self.inter_acl_interaction_stats[acl1_host].has_key(acl1_name):
                self.inter_acl_interaction_stats[acl1_host][acl1_name]=dict()
            if not self.inter_acl_interaction_stats[acl1_host][acl1_name].has_key(acl2_host):
                self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host]=dict()
            if not self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host].has_key(acl2_name):
                self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]=dict()

            for acl1_entry in acl1:
                self.is_interacting=False
                self.interaction_type=None
                self.interacting_other_rule=None

                #if acl1_entry.entry=='permit ip host 172.19.6.7 host 172.27.9.18':
                    #print("test1")

                interaction_free_ruleset = self.CheckInterACLRuleInteractions(acl1_entry, acl2)
                if self.is_interacting:
                    if acl1_entry.entry != self.interacting_other_rule:
                        record = "FIREWALL: %s ACL: %s Entry- %s Interacts with FIREWALL: %s ACL: %s Entry- %s"%(acl1_host, acl1_name,acl1_entry.entry, acl2_host, acl2_name,self.interacting_other_rule)
                        if not inter_acl_interaction_entries.__contains__(record):
                            inter_acl_interaction_entries.append(record)
                        
                    if self.interaction_type == RuleInteractionType.Shadow:
                        if not  self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name].has_key('shadow'):
                             self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['shadow']=1
                        else:
                            self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['shadow'] +=1

                    elif self.interaction_type == RuleInteractionType.Conflict:
                        if not  self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name].has_key('conflict'):
                             self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['conflict']=1
                        else:
                            self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['conflict'] +=1

                    elif self.interaction_type == RuleInteractionType.PartialOverlap:
                        if not  self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name].has_key('overlap'):
                             self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['overlap']=1
                        else:
                            self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['overlap'] +=1

                    elif self.interaction_type == RuleInteractionType.Generalisation:
                        if not  self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name].has_key('general'):
                             self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['general']=1
                        else:
                            self.inter_acl_interaction_stats[acl1_host][acl1_name][acl2_host][acl2_name]['general'] +=1

                for rule in interaction_free_ruleset: acl1_acl2_interaction_free_ruleset.append(rule)

            acl_details.InterACLInteractions = inter_acl_interaction_entries
            return acl1_acl2_interaction_free_ruleset

        def DoExplicitRuleFiltering(self, firewalls, acl_details):

            # inter-ACL rule filtering
            self.DoInterACLFiltering(firewalls, acl_details)

            for host in firewalls:
                firewall=firewalls[host]
                for interface in firewall.interfaces:
                    other_zones = []
                    acl_in = None
                    acl_out = None
                    attached_zone = self.gen_zones[host][firewall.interfaces[interface].type]
                    for zone in self.gen_zones[host].values():
                        if zone.zone_id!=attached_zone.zone_id: other_zones.append(zone)
                    if firewall.interfaces[interface].acl.has_key('in'):
                        acl_in = firewall.interfaces[interface].acl['in']
                    if firewall.interfaces[interface].acl.has_key('out'):
                        acl_out = firewall.interfaces[interface].acl['out']

                    if not acl_details.has_key(host):continue
                    if not acl_details[host].has_key(acl_in):continue

                    #TODO: use EntriesPostInterACLFiltering instead
                    for entry in acl_details[host][acl_in].EntriesPostInterACLFiltering:
                        ip_tuples =[]
                        #log.info("DoExplicitRuleFiltering entry protocol number: %s"%entry.Protocols)
                        if entry.Protocols.__contains__(ServiceProtocol.tcp) and entry.Action == RuleEffect.Permit:
                            if entry.SourcePort != None:
                                if not self.explicitly_allowed_services_tcp.has_key(entry.SourcePort):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_tcp[entry.SourcePort] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_tcp[entry.SourcePort].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_tcp[entry.SourcePort].append((entry.SourceIp,entry.DestIp))

                            if entry.DestPort != None:
                                if not self.explicitly_allowed_services_tcp.has_key(entry.DestPort):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_tcp[entry.DestPort] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_tcp[entry.DestPort].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_tcp[entry.DestPort].append((entry.SourceIp,entry.DestIp))

                            if entry.SourcePort==None and entry.DestPort==None:
                                # generic tcp rule
                                if not self.explicitly_allowed_services_tcp.has_key("generic"):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_tcp["generic"] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_tcp["generic"].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_tcp["generic"].append((entry.SourceIp,entry.DestIp))

                        elif entry.Protocols.__contains__(ServiceProtocol.udp) and entry.Action == RuleEffect.Permit:
                            if entry.SourcePort != None:
                                if not self.explicitly_allowed_services_udp.has_key(entry.SourcePort):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_udp[entry.SourcePort] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_udp[entry.SourcePort].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_udp[entry.SourcePort].append((entry.SourceIp,entry.DestIp))

                            if entry.DestPort != None:
                                if not self.explicitly_allowed_services_udp.has_key(entry.DestPort):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_udp[entry.DestPort] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_udp[entry.DestPort].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_udp[entry.DestPort].append((entry.SourceIp,entry.DestIp))

                            if entry.SourcePort==None and entry.DestPort==None:
                                # generic tcp rule
                                if not self.explicitly_allowed_services_udp.has_key("generic"):
                                    ip_tuples.append((entry.SourceIp,entry.DestIp))
                                    self.explicitly_allowed_services_udp["generic"] = ip_tuples
                                else:
                                    if not self.explicitly_allowed_services_udp["generic"].__contains__((entry.SourceIp,entry.DestIp)):
                                        self.explicitly_allowed_services_udp["generic"].append((entry.SourceIp,entry.DestIp))

                        elif entry.Protocols.__contains__(ServiceProtocol.icmp) and entry.Action == RuleEffect.Permit:
                            if not self.explicitly_allowed_services_icmp.has_key("icmp"):
                                ip_tuples.append((entry.SourceIp,entry.DestIp))
                                self.explicitly_allowed_services_icmp["icmp"] = ip_tuples
                            else:
                                if not self.explicitly_allowed_services_icmp["icmp"].__contains__((entry.SourceIp,entry.DestIp)):
                                    self.explicitly_allowed_services_icmp["icmp"].append((entry.SourceIp,entry.DestIp))

                        elif entry.Protocols.__contains__(ServiceProtocol.eigrp) and entry.Action == RuleEffect.Permit:
                            # If dest==224.0.0.10 and rule applied inbound on a firewall interface =>
                            #.. it enables eigrp hellos from the firewall's eigrp neighbours
                            #.. so replace dest ip with corresponding firewall interface ip
                            dest_ip=entry.DestIp
                            #log.info("checking eigrp rule for dest: %s"%dest_ip)
                            if entry.DestIp!=None and entry.DestIp.ip.is_multicast: #Util.ConvertStringToIpaddress(entry.DestIp).ip.is_multicast:
                                #log.info("eigrp rule, ip is multicast")
                                dest_ip= firewall.interfaces[interface].ip_address.ip# "host %s"%str(firewall.interfaces[interface].ip_address.ip)
                                #log.info("dest_ip : %s"%dest_ip)
                            if not self.explicitly_allowed_services_eigrp.has_key("eigrp"):
                                ip_tuples.append((entry.SourceIp,dest_ip))
                                self.explicitly_allowed_services_eigrp["eigrp"] = ip_tuples
                            else:
                                if not self.explicitly_allowed_services_eigrp["eigrp"].__contains__((entry.SourceIp,dest_ip)):
                                    self.explicitly_allowed_services_eigrp["eigrp"].append((entry.SourceIp,dest_ip))

                        elif entry.Protocols.__contains__(ServiceProtocol.ip) and entry.Action == RuleEffect.Permit:
                            if not self.explicitly_allowed_services_ip.has_key("ip"):
                                ip_tuples.append((entry.SourceIp,entry.DestIp))
                                self.explicitly_allowed_services_ip["ip"] = ip_tuples
                            else:
                                if not self.explicitly_allowed_services_ip["ip"].__contains__((entry.SourceIp,entry.DestIp)):
                                    self.explicitly_allowed_services_ip["ip"].append((entry.SourceIp,entry.DestIp))

                        #else:
                            #log.info("DoExplicitRuleFiltering: entry found post inter-ACL filtering with other protocol number: %s"% entry.Protocols)

        def CreateExplicitServiceOverlays(self, graphml_file_path):

            # Create explicit tcp service overlays
            #..by host
            for service in self.explicitly_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_tcp[service]:
                    source = ""
                    dest = ""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))
                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))

                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/tcp/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%Util.GetServiceName('tcp',service)))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%Util.GetServiceName('tcp',service)))

            #..by zone
            # Get firewall zone
            fw_zones = []
            all_zones=[]
            all_zone_ids=[]
            for host in self.gen_zones:
                if self.gen_zones[host].has_key('management_data_interface'):
                    fw_zones.append(self.gen_zones[host]['management_data_interface'])
                for zone in self.gen_zones[host].values():
                    if not all_zone_ids.__contains__(zone.zone_id):
                        all_zones.append(zone)
                        all_zone_ids.append(zone.zone_id)

            # TODO: do this properly to form zone-hierarchy : Sort the all_zones_list
            all_zones = self.SortZones(all_zones)

            for service in self.explicitly_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for host_tuple in self.explicitly_allowed_services_tcp[service]:
                    zone_ids1 = Util.GetHostZoneIds(host_tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(host_tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/tcp/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%Util.GetServiceName('tcp',service)))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%Util.GetServiceName('tcp',service)))

            # Create explicit udp service overlays
            #..by host
            for service in self.explicitly_allowed_services_udp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_udp[service]:
                    source = ""
                    dest =""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))

                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")


                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/udp/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_udp_%s.graphml"%Util.GetServiceName('udp',service)))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_udp_%s.pdf"%Util.GetServiceName('udp',service)))

            #..by zone
            for service in self.explicitly_allowed_services_udp:
                service_overlay = nx.DiGraph()
                for host_tuple in self.explicitly_allowed_services_udp[service]:
                    zone_ids1 = Util.GetHostZoneIds(host_tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(host_tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/udp/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_udp_%s.graphml"%Util.GetServiceName('udp',service)))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_udp_%s.pdf"%Util.GetServiceName('udp',service)))

            # Create explicit icmp service overlays
            #..by host
            for service in self.explicitly_allowed_services_icmp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_icmp[service]:
                    source = ""
                    dest =""

                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))

                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/icmp/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_icmp.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_icmp.pdf"))

            #..by zone
            for service in self.explicitly_allowed_services_icmp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_icmp[service]:
                    zone_ids1 = Util.GetHostZoneIds(tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/icmp/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_icmp.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_icmp.pdf"))

            # Create explicit eigrp service overlays
            #..by host
            for service in self.explicitly_allowed_services_eigrp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_eigrp[service]:
                    source = ""
                    dest =""

                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))

                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/eigrp/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_eigrp.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_eigrp.pdf"))

            #..by zone
            for service in self.explicitly_allowed_services_eigrp:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_eigrp[service]:
                    zone_ids1 = Util.GetHostZoneIds(tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/eigrp/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_eigrp.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_eigrp.pdf"))

            # Create explicit ip service overlays
            #..by host
            for service in self.explicitly_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_ip[service]:
                    source = ""
                    dest =""

                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))

                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/ip/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

            #..by zone
            for service in self.explicitly_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for tuple in self.explicitly_allowed_services_ip[service]:
                    zone_ids1 = Util.GetHostZoneIds(tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_explicit/ip/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

        def CreateImplicitServiceOverlays(self, graphml_file_path):

            all_zones=[]
            zone_ids=[]
            for host in self.gen_zones:
                for zone in self.gen_zones[host].values():
                    if not zone_ids.__contains__(zone.zone_id):
                        all_zones.append(zone)
                        zone_ids.append(zone.zone_id)

            # TODO: do this properly to form zone-hierarchy : Sort the all_zones_list
            all_zones = self.SortZones(all_zones)

            # create implicitly allowed Tcp, Udp overlays
            for service in self.implicitly_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for tuple in self.implicitly_allowed_services_tcp[service]:
                    source = ""
                    dest =""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))
                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                    if graphml_file_path:

                        parentFolderPath1 = ('%s/service_implicit/tcp/host/'%graphml_file_path)

                        # Save zone-firewall topology to file
                        nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%Util.GetServiceName('tcp',service)))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(service_overlay) # an example of quick positioning
                        nx.draw_networkx(service_overlay, pos)
                        plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%Util.GetServiceName('tcp',service)))

            #..by zone
            for service in self.implicitly_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for host_tuple in self.implicitly_allowed_services_tcp[service]:
                    zone_ids1 = Util.GetHostZoneIds(host_tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(host_tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                        parentFolderPath1 = ('%s/service_implicit/tcp/zone/'%graphml_file_path)

                        # Save zone-firewall topology to file
                        nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%Util.GetServiceName('tcp',service)))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(service_overlay) # an example of quick positioning
                        nx.draw_networkx(service_overlay, pos)
                        plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%Util.GetServiceName('tcp',service)))

            # TODO: Add later - create implicit UDP overlay (no UDP services enabled implicitly in our case study)

            # Create implicit ip service overlay
            #..by host
            for service in self.implicitly_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for tuple in self.implicitly_allowed_services_ip[service]:
                    source = ""
                    dest =""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))
                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                    if graphml_file_path:

                        parentFolderPath1 = ('%s/service_implicit/ip/host/'%graphml_file_path)

                        # Save zone-firewall topology to file
                        nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(service_overlay) # an example of quick positioning
                        nx.draw_networkx(service_overlay, pos)
                        plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

            #..by zone
            for service in self.implicitly_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for host_tuple in self.implicitly_allowed_services_ip[service]:
                    zone_ids1 = Util.GetHostZoneIds(host_tuple[0], all_zones)
                    zone_ids2 = Util.GetHostZoneIds(host_tuple[1], all_zones)

                    for zone_id1 in zone_ids1:
                        for zone_id2 in zone_ids2:
                            if zone_id1 != zone_id2:
                                service_overlay.add_node(zone_id1, type='zone', label=zone_id1)
                                service_overlay.add_node(zone_id2, type='zone', label=zone_id2)
                                service_overlay.add_edge(zone_id1,zone_id2,is_directed=True,label="")

                if graphml_file_path:

                        parentFolderPath1 = ('%s/service_implicit/ip/zone/'%graphml_file_path)

                        # Save zone-firewall topology to file
                        nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(service_overlay) # an example of quick positioning
                        nx.draw_networkx(service_overlay, pos)
                        plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

        def CreateFinalServiceOverlays(self, graphml_file_path):

            all_zones=[]
            for host in self.gen_zones:
                for zone in self.gen_zones[host].values():
                    all_zones.append(zone)

            # Create final ip service overlay merging both implicit and explicit overlays
            for tuple_list in self.explicitly_allowed_services_ip.values():
                ip_tuples = []
                for tuple in tuple_list:
                    if not self.final_allowed_services_ip.has_key("ip"):
                        ip_tuples.append(tuple)
                        self.final_allowed_services_ip["ip"] = ip_tuples
                    else:
                        if not self.final_allowed_services_ip["ip"].__contains__(tuple):
                            self.final_allowed_services_ip["ip"].append(tuple)

            for tuple_list in self.implicitly_allowed_services_ip.values():
                ip_tuples = []
                for tuple in tuple_list:
                    if not self.final_allowed_services_ip.has_key("ip"):
                        ip_tuples.append(tuple)
                        self.final_allowed_services_ip["ip"] = ip_tuples
                    else:
                        if not self.final_allowed_services_ip["ip"].__contains__(tuple):
                            self.final_allowed_services_ip["ip"].append(tuple)

            # Create final tcp overlay graph
            for service in self.explicitly_allowed_services_tcp:
                ip_tuples = []
                for tuple in self.explicitly_allowed_services_tcp[service]:
                    if not self.final_allowed_services_tcp.has_key(service):
                        ip_tuples.append(tuple)
                        self.final_allowed_services_tcp[service] = ip_tuples
                    else:
                        if not self.final_allowed_services_tcp[service].__contains__(tuple):
                            self.final_allowed_services_tcp[service].append(tuple)

            for service in self.implicitly_allowed_services_tcp:
                ip_tuples = []
                for tuple in self.implicitly_allowed_services_tcp[service]:
                    if not self.final_allowed_services_tcp.has_key(service):
                        ip_tuples.append(tuple)
                        self.final_allowed_services_tcp[service] = ip_tuples
                    else:
                        if not self.final_allowed_services_tcp[service].__contains__(tuple):
                            self.final_allowed_services_tcp[service].append(tuple)

            # incorporate final ip overlay as well
            for service in self.final_allowed_services_ip:
                for tuple in self.final_allowed_services_ip[service]:
                    for service2 in self.final_allowed_services_tcp:
                        if not self.final_allowed_services_tcp[service2].__contains__(tuple):
                            self.final_allowed_services_tcp[service2].append(tuple)

            # save final ip service overlay
            #..by host

            for service in self.final_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for tuple in self.final_allowed_services_ip[service]:
                    source = ""
                    dest =""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))
                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                    if graphml_file_path:

                        parentFolderPath1 = ('%s/service_final/ip/host/'%graphml_file_path)

                        # Save zone-firewall topology to file
                        nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(service_overlay) # an example of quick positioning
                        nx.draw_networkx(service_overlay, pos)
                        plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

            #..by zone
            for service in self.final_allowed_services_ip:
                service_overlay = nx.DiGraph()
                for host_tuple in self.final_allowed_services_ip[service]:
                    zone1 = Util.GetHostZoneIds(host_tuple[0], all_zones)[0] #GetHostZone
                    zone2 = Util.GetHostZoneIds(host_tuple[1], all_zones)[0]
                    service_overlay.add_node(zone1, type='zone', label=zone1)
                    service_overlay.add_node(zone2, type='zone', label=zone2)
                    service_overlay.add_edge(zone1,zone2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_final/ip/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_ip.graphml"))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_ip.pdf"))

            # save final tcp service overlays
            #..by host
            for service in self.final_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for tuple in self.final_allowed_services_tcp[service]:
                    source = ""
                    dest =""
                    if tuple[0] != None:
                        if isinstance(tuple[0], ipaddr.IPv4Address):
                            #host
                            source= "host %s(%s)" % (tuple[0], self.HostnameReverseLookup("host %s"%tuple[0]))
                        elif isinstance(tuple[0], ipaddr.IPv4Network):
                            if tuple[0]._prefixlen <32:
                                #subnet
                                source = "subnet %s/%s" % (tuple[0].network,tuple[0]._prefixlen)
                            else:
                                #host
                                source= "host %s(%s)" % (tuple[0].network, self.HostnameReverseLookup("host %s"%tuple[0].network))

                    if tuple[1] !=None:
                        if isinstance(tuple[1], ipaddr.IPv4Address):
                            #host
                            dest= "host %s(%s)" % (tuple[1], self.HostnameReverseLookup("host %s"%tuple[1]))
                        elif isinstance(tuple[1], ipaddr.IPv4Network):
                            if tuple[1]._prefixlen <32:
                                #subnet
                                dest = "subnet %s/%s" % (tuple[1].network,tuple[1]._prefixlen)
                            else:
                                #host
                                dest= "host %s(%s)" % (tuple[1].network, self.HostnameReverseLookup("host %s"%tuple[1].network))
                    if not service_overlay.has_node(source):
                        service_overlay.add_node(source, type='', label=source)
                    if not service_overlay.has_node(dest):
                        service_overlay.add_node(dest, type='', label=dest)
                    if not service_overlay.has_edge(source,dest):
                        service_overlay.add_edge(source,dest,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_final/tcp/host/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%Util.GetServiceName('tcp',service)))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%Util.GetServiceName('tcp',service)))

            #..by zone
            for service in self.final_allowed_services_tcp:
                service_overlay = nx.DiGraph()
                for host_tuple in self.final_allowed_services_tcp[service]:
                    if host_tuple[0]!=None and host_tuple[1]!=None:
                        zone1 = Util.GetHostZoneIds(host_tuple[0], all_zones)[0]
                        zone2 = Util.GetHostZoneIds(host_tuple[1], all_zones)[0]
                        service_overlay.add_node(zone1, type='zone', label=zone1)
                        service_overlay.add_node(zone2, type='zone', label=zone2)
                        service_overlay.add_edge(zone1,zone2,is_directed=True,label="")

                if graphml_file_path:

                    parentFolderPath1 = ('%s/service_final/tcp/zone/'%graphml_file_path)

                    # Save zone-firewall topology to file
                    nx.write_graphml(service_overlay, os.path.join(parentFolderPath1, "service_tcp_%s.graphml"%service))
                    #..and as pdf
                    plt.clf()
                    pos=nx.spring_layout(service_overlay) # an example of quick positioning
                    nx.draw_networkx(service_overlay, pos)
                    plt.savefig(os.path.join(parentFolderPath1, "service_tcp_%s.pdf"%service))

            # TODO: Create final service overlay graphs taking into account individual explicit overlays with final ip overlay
            #self.explicitly_allowed_services_tcp
            #self.final_allowed_services_ip
            #self.final_allowed_services_tcp

        def AllocateZoneHostsAndSubnets(self, all_zones_list, fw_zones, source_zones, other_zones, entry, ace, source_ip_list, dest_ip_list, unallocated, acl_errors):
            '''  Allocates source and destination addresses in an ACL to respective zones
            '''
            is_error_entry=False
            for source_ip in source_ip_list:
                source_allocated = False
                for zone in all_zones_list:
                    if source_ip!=None and zone.ContainsSubnetOrIpaddress(source_ip):
                        # source ip in ACL rule can be allocated to a zone
                        if (not zone.ContainsSubElement(ace.Source)):
                            zone.AddSubElement(ace.Source,True)
                        source_allocated = True

                        # ideally source ip must be inside a source zone
                        #..else possible acl error
                        unexpected_source_zone=True
                        for source_zone in source_zones:
                            if source_zone.zone_id==zone.zone_id:
                                unexpected_source_zone=False
                        if unexpected_source_zone and not acl_errors.__contains__(ace):
                            acl_errors.append(ace)
                        if unexpected_source_zone: is_error_entry =True
                        break

                    elif source_ip!=None and fw_zones!=None and len(fw_zones)>0:
                        excluded=None
                        #check whether zone+fw_zone includes the host_ip
                        for fw_zone in fw_zones:
                            for ipaddress in fw_zone.ipaddress_list:
                                try:
                                    excluded = ipaddr.IPv4Network(source_ip).address_exclude(ipaddress)
                                    break
                                except ValueError, e:
                                    # not contained
                                    pass
                        if zone.ContainsSubnetOrIpaddress(excluded):
                            # source ip in ACL rule can be allocated to a zone
                            for element in excluded:
                                if (not zone.ContainsSubElement(element)):
                                    if element.prefixlen ==32 and element.ip!=element.network:
                                        # host
                                        zone.AddSubElement("host %s"%element.ip, True)
                                    else:
                                        # subnet
                                        zone.AddSubElement("%s/%s"%(element.network,element.prefixlen),True)
                            source_allocated = True
                            # ideally source ip must be inside a source zone
                            #..else possible acl error
                            unexpected_source_zone=True
                            for source_zone in source_zones:
                                if source_zone.zone_id==zone.zone_id:
                                    unexpected_source_zone=False
                            if unexpected_source_zone and not acl_errors.__contains__(ace):
                                acl_errors.append(ace)
                            if unexpected_source_zone: is_error_entry =True
                            break


                if not source_allocated:
                    # source ip cannot be allocated..potential acl error
                    if ace.Source!=None and not unallocated.__contains__(ace.Source):
                        unallocated.append(ace.Source)
                        if not acl_errors.__contains__(ace):
                            log.error("source cannot be allocated for entry - %s"%entry)
                            acl_errors.append(ace)
                    if ace.Source!=None: is_error_entry =True

            for dest_ip in dest_ip_list:
                dest_allocated = False
                for zone in all_zones_list:

                    if dest_ip!=None and dest_ip.is_multicast:
                        # Multicast addresses belong to any other_zone
                        #log.info("multicast address found: %s"%dest_ip)
                        dest_allocated = True

                    elif dest_ip!=None and zone.ContainsSubnetOrIpaddress(dest_ip):
                        # dest ip in ACL rule can be allocated to zone
                        if (not zone.ContainsSubElement(ace.Dest)):
                            zone.AddSubElement(ace.Dest,True)
                        dest_allocated = True

                        # ideally dest ip must be inside a non-source zone(i.e. in other zones)
                        #..else possible acl error
                        zone_in_other_zone = False
                        for other_zone in other_zones:
                            #log.info("check1 dest in zone: %s for: %s"%(other_zone.zone_id,zone.zone_id))
                            if other_zone.zone_id==zone.zone_id:
                                zone_in_other_zone = True
                                break
                        if not zone_in_other_zone:
                            if not acl_errors.__contains__(ace):
                                log.info("Dest cannot be allocated for entry - %s"%entry)
                                acl_errors.append(ace)
                            is_error_entry =True
                        break

                    elif dest_ip!=None and fw_zones!=None and len(fw_zones)>0:
                        excluded=None
                        #check whether zone+fw_zone includes the dest_ip
                        for fw_zone in fw_zones:
                            for ipaddress in fw_zone.ipaddress_list:
                                try:
                                    excluded = ipaddr.IPv4Network(dest_ip).address_exclude(ipaddress)
                                    break
                                except ValueError, e:
                                    # not contained
                                    pass
                        if zone.ContainsSubnetOrIpaddress(excluded):
                            # source ip in ACL rule can be allocated to a zone
                            for element in excluded:
                                if (not zone.ContainsSubElement(element)):
                                    if element.prefixlen ==32 and element.ip!=element.network:
                                        # host
                                        zone.AddSubElement("host %s"%element.ip, True)
                                    else:
                                        # subnet
                                        zone.AddSubElement("%s/%s"%(element.network,element.prefixlen),True)

                            dest_allocated = True
                            # ideally dest ip must be inside a non-source zone(i.e. in other zones)
                            #..else possible acl error
                            zone_in_other_zone = False
                            for other_zone in other_zones:
                                #log.info("check2 dest in zone: %s for: %s"%(other_zone.zone_id,zone.zone_id))
                                if other_zone.zone_id==zone.zone_id:
                                    zone_in_other_zone = True
                                    break
                            if not zone_in_other_zone:
                                if not acl_errors.__contains__(ace):
                                    log.info("Dest cannot be allocated for entry - %s"%entry)
                                    acl_errors.append(ace)
                                is_error_entry =True
                            break


                if not dest_allocated:
                    # dest ip cannot be allocated..potential acl error
                    if ace.Dest!=None and not unallocated.__contains__(ace.Dest):
                        unallocated.append(ace.Dest)
                        if not acl_errors.__contains__(ace):
                            acl_errors.append(ace)
                    if ace.Dest!=None: is_error_entry =True

            return is_error_entry

        def CheckMergeZones(self, firewall, acl_details, all_zones):
            if self.IsZoneMergePending(firewall, acl_details, all_zones):
                self.DoMergeZones(all_zones,self.zones_to_merge)
                self.CheckMergeZones(firewall, acl_details, all_zones)

        def DoMergeZones(self,all_zones, zones_to_merge):
            merge_source=zones_to_merge[1:]
            merge_dest=zones_to_merge[0]
            merge_source_int = []
            merge_des_int = None
            ip_list = []
            for interface in all_zones.keys():
                zone=all_zones[interface]
                if merge_source.__contains__(zone.zone_id):
                    merge_source_int.append(interface)
                    for ip in zone.ipaddress_list:
                        ip_list.append(ip)
            for interface in all_zones.keys():
                zone=all_zones[interface]
                if zone.zone_id == merge_dest:
                    merge_des_int = interface
                    for ip in ip_list:
                        zone.ipaddress_list.append(ip)
            for source_int in merge_source_int:
                all_zones[source_int] = all_zones[merge_des_int]

        def ProcessStaticRoutes(self,firewalls, all_zones, file_contents):

            CiscoConfigParser().ProcessStaticRoutes(firewalls, all_zones, file_contents)
            self.potential_route_errors = CiscoConfigParser().potential_route_errors
            self.unallocated_gateways =CiscoConfigParser().unallocated_gateways

        def CreateZoneBreakdowns(self, gen_zones, graphml_file_path):

            # Create zone breakdown
            for interfaces in gen_zones.values():
                for zone in interfaces.values():
                    zone_breakdown = nx.Graph()
                    counter =0
                    for element in zone.sub_elements:
                        node_id = "n%s"%counter
                        label="%s(%s)"% (element,self.HostnameReverseLookup(element))
                        if not label.__contains__('any'):
                            zone_breakdown.add_node(node_id,label=label)
                        counter = counter+1

                    if graphml_file_path:

                        # Save zone-firewall topology to file
                        nx.write_graphml(zone_breakdown, os.path.join(graphml_file_path, "%s.graphml"%zone.zone_id))
                        #..and as pdf
                        plt.clf()
                        pos=nx.spring_layout(zone_breakdown) # an example of quick positioning
                        nx.draw_networkx(zone_breakdown, pos)
                        plt.savefig(os.path.join(graphml_file_path, "%s.pdf"%zone.zone_id))

        def IsZoneMergePending(self,firewall,acl_details,all_zones):

            for interface in firewall.interfaces:
                other_zones = []
                acl_in = None
                acl_out = None
                attached_zone = all_zones[firewall.interfaces[interface].type]
                for zone in all_zones.values():
                    if zone!=attached_zone: other_zones.append(zone)
                if firewall.interfaces[interface].acl.has_key('in'):
                    acl_in = firewall.interfaces[interface].acl['in']
                if firewall.interfaces[interface].acl.has_key('out'):
                    acl_out = firewall.interfaces[interface].acl['out']

                self.unallocated = dict()
                self.potential_acl_errors=dict()
                acl_errors = []

                # TODO: need to extend to include acl_out processing (i.e. targets will be in attached_zone)
                if acl_in==None: continue

                # Extract all distinct sources
                for entry in acl_details[acl_in].Entries:

                    # Convert entry to ACE
                    ace = Util.GetCiscoACE(entry)

                    # Ignore any remarks
                    if ace == None: continue

                    # Convert ACE source, dest criteria to ip list
                    source_ip_list = Util.GetIpList(ace.Source, [attached_zone])
                    dest_ip_list = Util.GetIpList(ace.Dest, other_zones)

                    # Check for zone merges
                    for source_ip in source_ip_list:
                        if source_ip != None and not attached_zone.ContainsSubnetOrIpaddress(source_ip):
                            # Check whether ip in other zones
                            rule_invalid = True
                            zone_to_merge_with = None
                            for zone in other_zones:
                                if zone.ContainsSubnetOrIpaddress(source_ip):
                                    # Verify this traffic restriction also applies on other zone interface..else must be an error
                                    for key in all_zones:
                                        lookup_zone = all_zones[key]
                                        if lookup_zone.zone_id==zone.zone_id:
                                            # Extract any interface ACLs
                                            for interface in firewall.interfaces:
                                                if firewall.interfaces[interface].type ==  key:
                                                    if firewall.interfaces[interface].acl.has_key('in'):
                                                        for entry in acl_details[firewall.interfaces[interface].acl['in']].Entries:
                                                            if ace.RuleCore in entry:
                                                                # definitely an alternative internal traffic path exists
                                                                rule_invalid = False
                                                                zone_to_merge_with = zone
                                                                break
                            if rule_invalid:
                                if not acl_errors.__contains__(entry):
                                    acl_errors.append(entry)
                                if len(acl_errors) > 0:
                                    self.potential_acl_errors[acl_in] = acl_errors

                            else :
                                # Merge required attached_zone,zone_to_merge_with
                                if not self.zones_to_merge.__contains__(attached_zone.zone_id):
                                    self.zones_to_merge.append(attached_zone.zone_id)
                                if not self.zones_to_merge.__contains__(zone_to_merge_with.zone_id):
                                    self.zones_to_merge.append(zone_to_merge_with.zone_id)
                                return True

            return False

        def GetConnectedComponentWithNode(self, nodeId, connectedComponents):

            if not nodeId:
                raise ValueError("nodeId", resources['ValueNull'])
            if not connectedComponents:
                raise ValueError("connectedComponents", resources['ValueNull'])

            for connectedComponent in connectedComponents:
                for node in connectedComponent:
                    if node == nodeId: return connectedComponent
            return None

        def ProcessInboundACL(self, firewall, interface_name, acl_in, acl_details, all_zones):

            # Create copy of original zone-firewall model
            graphCopy = self.zone_firewall_top.copy()

            # Extract possible source zones attached to ACL interface
            attached_zone = all_zones[firewall.name][firewall.interfaces[interface_name].type]
            # Remove firewall node from zone-firewall model and obtain connected-components list
            graphCopy.remove_node("fw(%s)"%firewall.name)
            components = nx.connected_components(graphCopy.to_undirected())

            # Find all zones inside the connected component that contains attached_zone : these are the source_zones
            connected_component = self.GetConnectedComponentWithNode(attached_zone.zone_id, components)
            source_zones = dict()
            for component in connected_component:
                for host in all_zones:
                    for zone in all_zones[host].values():
                        if zone.zone_id==component and not source_zones.has_key(zone.zone_id):
                            source_zones[zone.zone_id]=zone

            #..and the remaining zones
            other_zones= []
            all_zones_list= []
            other_zone_ids=[]
            all_zone_ids=[]
            for interfaces in all_zones.values():
                for zone in interfaces.values():
                    if not source_zones.has_key(zone.zone_id) and not other_zone_ids.__contains__(zone.zone_id):
                        other_zones.append(zone)
                        other_zone_ids.append(zone.zone_id)
                    if not all_zone_ids.__contains__(zone.zone_id):
                        all_zones_list.append(zone)
                        all_zone_ids.append(zone.zone_id)

            # TODO: do this properly to form zone-hierarchy : Sort the all_zones_list
            all_zones_list = self.SortZones(all_zones_list)

            # work data
            acl_errors = []
            unallocated=[]
            previous_entries=[]
            interacting_acl_entries=[]
            entry_index = 0

            # Extract all distinct sources
            for entry in acl_details[firewall.name][acl_in].Entries:

                if not self.intra_acl_interaction_stats.has_key(firewall.name):
                    self.intra_acl_interaction_stats[firewall.name]=dict()
                if not self.intra_acl_interaction_stats[firewall.name].has_key(acl_in):
                    self.intra_acl_interaction_stats[firewall.name][acl_in]=dict()

                # Extract entry fields and create ACE
                # if entry=="line 5 extended permit icmp host 172.18.90.6 any (hitcnt=86404) 0x8ce90628":
                   # print('test')

                ace = Util.GetCiscoACE(entry)
                # Ignore any remarks
                if ace==None: continue

                # Convert ACE source criteria to ip list
                source_ip_list = Util.GetIpList(ace.Source, source_zones.values())
                dest_ip_list = Util.GetIpList(ace.Dest, other_zones)

                fw_zones=[]
                # Find the firewall zones
                for interfaces in all_zones.values():
                    if interfaces.has_key('management_data_interface'):
                        fw_zones.append(interfaces['management_data_interface'])

                # Allocate source, dest hosts and subnets to their respective zones
                is_error= self.AllocateZoneHostsAndSubnets(all_zones_list, fw_zones, source_zones.values(), other_zones, entry, ace, source_ip_list, dest_ip_list, unallocated, acl_errors)
                if is_error:
                    continue
                # source,dest,service
                # process services by ip
                source_port = None
                dest_port =None
                if ace.SourcePortFilter != None:
                    source_port = ace.SourcePortFilter.split(' ')[1]
                if ace.SourcePortFilter != None:
                    dest_port = ace.SourcePortFilter.split(' ')[1]

                # Convert ACE to conventional (uncompressed) format
                # ..e.g. permit tcp any hostX eq 80  :can generate several subrules based on the interpretation of 'any'
                subrules = Util.ConvertToSubrulesList(ace,source_ip_list, dest_ip_list)
                # intra-ACL filtering
                # ...obtain interaction free sub-rule (i.e. net-effect of rule)
                counter=1
                for subrule in subrules:
                    self.is_interacting = False

                    # default networks are too ambiguous
                    if (subrule.SourceIp == ipaddr.IPv4Network("0.0.0.0/0.0.0.0") or
                        subrule.DestIp == ipaddr.IPv4Network("0.0.0.0/0.0.0.0")):
                        continue

                    import traceback

                    try:
                        #if subrule.entry=="permit icmp host 172.18.90.6 any" and subrule.DestIp==ipaddr.IPv4Network('172.18.5.253/32') and subrule.SourceIp==ipaddr.IPv4Network('172.18.90.6/32'):
                        #    print('test')
                        interaction_free_subrules = self.CheckIntraACLRuleInteractions(subrule, previous_entries) #
                    except BaseException, e:
                        #tb = traceback.format_exc()
                        log.error(e.message)
                        #log.error(tb)

                    if self.is_interacting:
                        record = "Entry- %s  Prev- %s"%(entry,self.interacting_prev_rule)
                        if not interacting_acl_entries.__contains__(record):
                            interacting_acl_entries.append(record)

                    if self.interaction_type == RuleInteractionType.Shadow:
                        if not  self.intra_acl_interaction_stats[firewall.name][acl_in].has_key('shadow'):
                             self.intra_acl_interaction_stats[firewall.name][acl_in]['shadow']=1
                        else:
                            self.intra_acl_interaction_stats[firewall.name][acl_in]['shadow'] +=1
                    elif self.interaction_type == RuleInteractionType.Conflict:
                        if not  self.intra_acl_interaction_stats[firewall.name][acl_in].has_key('conflict'):
                             self.intra_acl_interaction_stats[firewall.name][acl_in]['conflict']=1
                        else:
                            self.intra_acl_interaction_stats[firewall.name][acl_in]['conflict'] +=1
                    elif self.interaction_type == RuleInteractionType.PartialOverlap:
                        if not  self.intra_acl_interaction_stats[firewall.name][acl_in].has_key('overlap'):
                             self.intra_acl_interaction_stats[firewall.name][acl_in]['overlap']=1
                        else:
                            self.intra_acl_interaction_stats[firewall.name][acl_in]['overlap'] +=1
                    elif self.interaction_type == RuleInteractionType.Generalisation:
                        if not  self.intra_acl_interaction_stats[firewall.name][acl_in].has_key('general'):
                             self.intra_acl_interaction_stats[firewall.name][acl_in]['general']=1
                        else:
                            self.intra_acl_interaction_stats[firewall.name][acl_in]['general'] +=1

                    if interaction_free_subrules != None and len(interaction_free_subrules)>0:
                        for interaction_free_subrule in interaction_free_subrules:
                            previous_entries.append(interaction_free_subrule)

                    counter=counter+1

            # Retain intra-acl details
            acl_details[firewall.name][acl_in].EntriesPostIntraACLFiltering = previous_entries
            acl_details[firewall.name][acl_in].IntraACLInteractions = interacting_acl_entries

            if len(acl_errors) > 0:
                if not self.potential_acl_errors.has_key(firewall.name):
                    self.potential_acl_errors[firewall.name]=dict()
                if not self.potential_acl_errors[firewall.name].has_key(acl_in):
                    self.potential_acl_errors[firewall.name][acl_in]=[]
                self.potential_acl_errors[firewall.name][acl_in] = acl_errors

            if len(unallocated) >0:
                self.unallocated[acl_in] = unallocated

        def ProcessOutboundACL(self, firewall, interface_name, acl_out, acl_details, all_zones):

            # Create copy of original zone-firewall model
            graphCopy = self.zone_firewall_top.copy()

            # Extract possible source zones attached to ACL interface
            attached_zone = all_zones[firewall.name][firewall.interfaces[interface_name].type]
            # Remove firewall node from zone-firewall model and obtain connected-components list
            graphCopy.remove_node("fw(%s)"%firewall.name)
            components = nx.connected_components(graphCopy.to_undirected())

            # Find all zones inside the connected component that contains attached_zone : these are the source_zones
            connected_component = self.GetConnectedComponentWithNode(attached_zone.zone_id, components)
            dest_zones = dict()
            for component in connected_component:
                for host in all_zones:
                    for zone in all_zones[host].values():
                        if zone.zone_id==component and not dest_zones.has_key(zone.zone_id):
                            dest_zones[zone.zone_id]=zone

            #..and the remaining zones
            source_zones= []
            all_zones_list= []
            source_zone_ids=[]
            all_zone_ids=[]
            for interfaces in all_zones.values():
                for zone in interfaces.values():
                    if not dest_zones.has_key(zone.zone_id) and not source_zone_ids.__contains__(zone.zone_id):
                        source_zones.append(zone)
                        source_zone_ids.append(zone.zone_id)
                    if not all_zone_ids.__contains__(zone.zone_id):
                        all_zones_list.append(zone)
                        all_zone_ids.append(zone.zone_id)

            # TODO: do this properly to form zone-hierarchy : Sort the all_zones_list
            all_zones_list = self.SortZones(all_zones_list)

            # work data
            acl_errors = []
            unallocated=[]
            previous_entries=[]
            interacting_acl_entries=[]
            entry_index = 0

            # Extract all distinct sources
            for entry in acl_details[firewall.name][acl_out].Entries:

                # Extract entry fields and create ACE
                #if entry=="permit ip host 172.27.8.195 host 172.19.1.8":
                #    print('test')

                ace = Util.GetCiscoACE(entry)
                # Ignore any remarks
                if ace==None: continue

                # Convert ACE source criteria to ip list
                #print(ace.rule_core)
                source_ip_list = Util.GetIpList(ace.Source, source_zones)
                dest_ip_list = Util.GetIpList(ace.Dest, dest_zones.values())

                fw_zones=[]
                # Find the firewall zones
                for interfaces in all_zones.values():
                    if interfaces.has_key('management_data_interface'):
                        fw_zones.append(interfaces['management_data_interface'])

                # Allocate source, dest hosts and subnets to their respective zones
                is_error= self.AllocateZoneHostsAndSubnets(all_zones_list, fw_zones, source_zones, dest_zones.values(), entry, ace, source_ip_list, dest_ip_list, unallocated, acl_errors)
                if is_error:
                    continue
                # source,dest,service
                # process services by ip
                source_port = None
                dest_port =None
                if ace.SourcePortFilter != None:
                    source_port = ace.SourcePortFilter.split(' ')[1]
                if ace.SourcePortFilter != None:
                    dest_port = ace.SourcePortFilter.split(' ')[1]

                # Convert ACE to conventional (uncompressed) format
                # ..e.g. permit tcp any hostX eq 80  :can generate several subrules based on the interpretation of 'any'
                subrules = Util.ConvertToSubrulesList(ace,source_ip_list, dest_ip_list)
                # intra-ACL filtering
                # ...obtain interaction free sub-rule (i.e. net-effect of rule)
                counter=1
                for subrule in subrules:
                    self.is_interacting = False

                    # default networks are too ambiguous
                    if (subrule.SourceIp == ipaddr.IPv4Network("0.0.0.0/0.0.0.0") or
                        subrule.DestIp == ipaddr.IPv4Network("0.0.0.0/0.0.0.0")):
                        continue

                    interaction_free_subrules = self.CheckIntraACLRuleInteractions(subrule, previous_entries) #
                    if self.is_interacting:
                        record = "Entry- %s  Prev- %s"%(entry,self.interacting_prev_rule)
                        if not interacting_acl_entries.__contains__(record):
                            interacting_acl_entries.append(record)
                    if interaction_free_subrules != None and len(interaction_free_subrules)>0:
                        for interaction_free_subrule in interaction_free_subrules:
                            previous_entries.append(interaction_free_subrule)

                    counter=counter+1

            # Retain intra-acl details
            acl_details[firewall.name][acl_out].EntriesPostIntraACLFiltering = previous_entries
            acl_details[firewall.name][acl_out].IntraACLInteractions = interacting_acl_entries

            if len(acl_errors) > 0:
                if not self.potential_acl_errors.has_key(firewall.name):
                    self.potential_acl_errors[firewall.name]=dict()
                if not self.potential_acl_errors[firewall.name].has_key(acl_out):
                    self.potential_acl_errors[firewall.name][acl_out]=[]
                self.potential_acl_errors[firewall.name][acl_out] = acl_errors

            if len(unallocated) >0:
                self.unallocated[acl_out] = unallocated

        def SortZones(self, zones_list):
            sorted=[]
            parent=None
            for zone in zones_list:
                if not zone.ipaddress_list.__contains__(ipaddr.IPv4Network("0.0.0.0/0.0.0.0")):
                    sorted.append(zone)
                else:
                    parent=zone

            if parent!=None:
                sorted.append(parent)

            return sorted

        def CheckInterACLRuleInteractions(self, current_rule, other_acl_entries):

            if not current_rule:
                raise ValueError('current_rule', resources['value_null'])

            result = RuleInteraction(current_rule)
            rules_to_compare=[current_rule]
            self.is_interacting = False
            self.interaction_type = None
            self.interacting_other_rule = None

            for other_rule in other_acl_entries:
                net_result=dict()
                for rule in rules_to_compare:
                    if isinstance(other_rule,list):
                        for o_rule in other_rule:
                            if isinstance(rule,list):
                                for c_rule in rule:
                                    net = self.GetInterACLRuleInteractions(c_rule, o_rule)
                                    if net!=None and len(net)>0:
                                        net_result[c_rule]=[]
                                        for net_rule in net:
                                            net_result[c_rule].append(net_rule)
                            else:
                                net = self.GetInterACLRuleInteractions(rule, o_rule)
                                if net!=None and len(net)>0:
                                    net_result[rule]=[]
                                    for net_rule in net:
                                        net_result[rule].append(net_rule)
                    else:
                        if isinstance(rule,list):
                            for c_rule in rule:
                                net = self.GetInterACLRuleInteractions(c_rule, other_rule)
                                if net!=None and len(net)>0:
                                    net_result[c_rule]=[]
                                    for net_rule in net:
                                        net_result[c_rule].append(net_rule)
                        else:
                            net = self.GetInterACLRuleInteractions(rule, other_rule)
                            if net!=None and len(net)>0:
                                net_result[rule]=[]
                                for net_rule in net:
                                    net_result[rule].append(net_rule)

                # update rules_to_compare
                replaced=[]
                for rule in rules_to_compare:
                    if isinstance(rule,list):
                        for to_rule in rule:
                            if net_result.has_key(to_rule):
                                [replaced.append(net_rule) for net_rule in net_result[to_rule]]
                            else:
                                replaced.append(to_rule)
                    else:
                        if net_result.has_key(rule):
                            [replaced.append(net_rule) for net_rule in net_result[rule]]
                        else:
                            replaced.append(rule)
                rules_to_compare=replaced

            return rules_to_compare

        def GetInterACLRuleInteractions(self, rule1, rule2):

            net_result=[]
            if rule1.Overlaps(rule2):
                self.is_interacting = True
                self.interaction_type = RuleInteractionType.PartialOverlap
                self.interacting_other_rule=rule2.entry
                #result.Type = RuleInteractionType.Overlap
                if rule1.IsShadowedBy(rule2):
                    # current_rule is a subset of other_rule...net-effect is current rule
                    net_result.append(rule1)

                elif rule2.IsShadowedBy(rule1):
                    # other_rule is a proper subset of current_rule
                    # net-effect depends on whether (current_rule - other_rule) has overlaps with the remaining rules of other_rules
                    # net includes other_rules
                    net_result.append(rule2)
                    to_check = Util.GetNetRule(rule1, rule2, RuleOperation.Exclude, rule1.Action)
                    for rule_to_check in to_check:
                        net_result.append(rule_to_check)
                else:
                    # Partial overlap..take intersection
                    intersection = Util.GetNetRule(rule1, rule2, RuleOperation.Intersect, rule1.Action)
                    # intersection is in the net rule
                    net_result.append(intersection)
                    # compute current_rule - (other_rule intersection current_rule)...this may overlap with remaining other_rules
                    to_check = Util.GetNetRule(rule1, intersection, RuleOperation.Exclude, rule1.Action)
                    for rule_to_check in to_check:
                        net_result.append(rule_to_check)

            elif rule1.Conflicts(rule2):
                self.is_interacting = True
                self.interaction_type = RuleInteractionType.Conflict
                self.interacting_other_rule=rule2.entry
                #result.Type = RuleInteractionType.Conflict
                if rule1.IsShadowedBy(rule2):
                    # current_rule is a subset of other_rule...take current_rule with action=deny as net
                    net_result.append(AtomicACE(RuleEffect.Deny, rule1.Protocols, rule1.SourceIp, rule1.SourcePort, rule1.DestIp, rule1.DestPort, rule1.icmp_type, rule1.entry))

                elif rule2.IsShadowedBy(rule1):
                    # other_rule is a proper subset of current_rule
                    # net-effect includes other_rule with action=deny
                    net_result.append(AtomicACE(RuleEffect.Deny, rule2.Protocols, rule2.SourceIp, rule2.SourcePort, rule2.DestIp, rule2.DestPort, rule2.icmp_type, rule2.entry))
                    # current_rule-other_rule may apply or not..check
                    to_check= Util.GetNetRule(rule1, rule2, RuleOperation.Exclude, rule1.Action)
                    for rule_to_check in to_check:
                        net_result.append(rule_to_check)

                else:
                    # Partial overlap..take intersection with action=deny
                    intersection = Util.GetNetRule(rule1, rule2, RuleOperation.Intersect, RuleEffect.Deny)
                    # intersection is in the net rule
                    net_result.append(intersection)
                    # compute current_rule - (intersection)...this may overlap with remaining other_rules
                    to_check = Util.GetNetRule(rule1, intersection, RuleOperation.Exclude, rule1.Action)
                    for rule_to_check in to_check:
                        net_result.append(rule_to_check)

            else:
                # No interactions
                net_result.append(rule1)

            return net_result

        def CheckIntraACLRuleInteractions(self, current_rule, previous_acl_entries):

            if not current_rule:
                raise ValueError('current_rule', resources['value_null'])

            result = RuleInteraction(current_rule)
            rules_to_compare=[current_rule]
            self.is_interacting = False
            self.interaction_type=None
            self.interacting_other_rule = None

            for prev_rule in previous_acl_entries:
                net_result=dict()
                for rule in rules_to_compare:
                    net = self.GetIntraACLRuleInteractions(rule, prev_rule)
                    if net!=None and len(net)>0:
                        net_result[rule]=[]
                        for net_rule in net:
                            net_result[rule].append(net_rule)

                # update rules_to_compare
                replaced=[]
                for rule in rules_to_compare:
                    if net_result.has_key(rule):
                        [replaced.append(net_rule) for net_rule in net_result[rule]]
                rules_to_compare=replaced

            return rules_to_compare

        def GetIntraACLRuleInteractions(self, rule1, rule2):
            import traceback
            try:
                net_result=[]
                if rule1.Overlaps(rule2):
                    self.is_interacting = True
                    self.interacting_prev_rule=rule2.entry
                    #result.Type = RuleInteractionType.Overlap
                    if rule1.IsShadowedBy(rule2):
                        # current_rule is a subset of other_rule...net-effect is nothing
                        self.interaction_type = RuleInteractionType.Shadow
                        pass

                    elif rule2.IsShadowedBy(rule1):
                        # prev_rule is a proper subset of current_rule...take (current_rule - prev_rule) as net effect
                        net = Util.GetNetRule(rule1, rule2, RuleOperation.Exclude, rule1.Action)
                        [net_result.append(rule) for rule in net]
                        self.interaction_type = RuleInteractionType.Generalisation

                    else:
                        # Partial overlap..take current_rule - (prev_rule intersection current_rule)
                        intersection = Util.GetNetRule(rule1, rule2, RuleOperation.Intersect, rule1.Action)
                        self.interaction_type = RuleInteractionType.PartialOverlap
                        if intersection != None:
                            net = Util.GetNetRule(rule1, intersection, RuleOperation.Exclude, rule1.Action)
                            [net_result.append(rule) for rule in net]

                elif rule1.Conflicts(rule2):
                    self.is_interacting = True
                    self.interacting_prev_rule=rule2.entry
                    self.interaction_type = RuleInteractionType.Conflict
                    #result.Type = RuleInteractionType.Conflict
                    if rule1.IsShadowedBy(rule2):
                        # current_rule is a subset of other_rule...net-effect is nothing
                        pass

                    elif rule2.IsShadowedBy(rule1):
                        # prev_rule is a proper subset of current_rule...take (current_rule - prev_rule) as net effect
                        net = Util.GetNetRule(rule1, rule2, RuleOperation.Exclude, rule1.Action)
                        [net_result.append(rule) for rule in net]

                    else:
                        # Partial overlap..take current_rule - (prev_rule intersection current_rule)
                        intersection = Util.GetNetRule(rule1, rule2, RuleOperation.Intersect, rule1.Action)
                        net = Util.GetNetRule(rule1, intersection, RuleOperation.Exclude, rule1.Action)
                        [net_result.append(rule) for rule in net]
                else:
                    # No interactions
                    net_result.append(rule1)

                return net_result

            except BaseException,e:
                tb = traceback.format_exc()
                log.error(tb)

        def CleanupZones(self,all_zones,hosts_to_cleanup):

            for zone in all_zones.values():
                hosts_to_remove = []
                for included_item in zone.sub_elements:
                    if hosts_to_cleanup.has_key(included_item):
                        remove_from_zones = hosts_to_cleanup[included_item]
                        for item in remove_from_zones:
                            zone1 = item.replace(' ','')
                            zone2 = zone.zone_id.replace(' ','')
                            if  zone1==zone2 :
                                hosts_to_remove.append(included_item)

                # Remove marked hosts from zone
                for host in hosts_to_remove:
                    if zone.sub_elements.has_key(host):
                        zone.sub_elements.__delitem__(host)

        def PerformZoneMergeAndCleanup(self, all_zones):

            hosts_to_cleanup=dict()
            lookup_table = self.CreateLookupTable(all_zones)
            if self.IsZoneMergeRequired(lookup_table):
                self.MergeZones(all_zones,self.zones_to_merge)
                self.PerformZoneMergeAndCleanup(all_zones)
            elif self.IsZoneCleanupRequired(lookup_table):
                self.CleanupZones(all_zones,self.hosts_to_cleanup)
            return

        def CreateLookupTable(self, all_zones):
            # Use this for cleanup (1) and zone_merging (2) etc
            lookup_table = dict()
            for zone in all_zones.values():
                for element in zone.sub_elements:
                    key = "%s (%s)" % (zone.zone_id, zone.sub_elements[element])
                    if key==0:
                        continue
                    if not lookup_table.has_key(element):
                        zone_list = []
                        zone_list.append(key)
                        lookup_table[element] = zone_list
                    else:
                        lookup_table[element].append(key)
            return lookup_table

        def IsZoneCleanupRequired(self, lookup_table):

            self.hosts_to_cleanup = dict()
            cleanup_req = False
            for host in lookup_table.keys():
                item = lookup_table[host]
                true_count = 0
                false_count = 0
                zones_list =[]
                for elt in item:
                    p = re.search('True', elt)
                    if p:
                        true_count = true_count + 1
                    else:
                        zones_list.append(elt.split('(')[0])
                        false_count = false_count + 1
                if true_count >=1 and false_count >0:
                    # Cleanup required
                    self.hosts_to_cleanup[host] = zones_list
                    cleanup_req = True

            return cleanup_req

        def HostnameReverseLookup(self, host_ip):
            p= re.search('host', host_ip)
            hostname = None
            if p:
               ipaddress = host_ip.split(' ')[1]
               if self.hostname_lookup.values().__contains__(ipaddress):
                   hostname = next((hostname for hostname, ip in self.hostname_lookup.items() if ip == ipaddress), None)

            return hostname










