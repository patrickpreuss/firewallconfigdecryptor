import pkg_resources
import firewallconfigdecryptor.log as log
from exception import ParserException
from input_parser import InputParser
import sys

try:
    FCD_VERSION = pkg_resources.get_distribution("firewallconfigdecryptor").version
except pkg_resources.DistributionNotFound:
    FCD_VERSION = "dev"

def console_entry():
    """If come from console entry point"""
    args = parse_options()
    main(args)

def parse_options(argument_string=None):
    """Parse user-provided options"""
    import argparse
    usage = "firewallconfigdecryptor -f input.txt"
    version = "%(prog)s " + str(FCD_VERSION)
    parser = argparse.ArgumentParser(description=usage, version=version)

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        '--config', '-c', default=None, help="Load configuration(s) from folder")

    parser.add_argument('--debug', action="store_true",
                        default=False, help="Debug mode")

    if argument_string:
        arguments = parser.parse_args(argument_string.split())
    else:
        # from command line arguments
        arguments = parser.parse_args()
    return arguments


def main(options):

    log.info("firewallconfigdecryptor %s" % FCD_VERSION)

    if options.debug: #or settings['General']['debug']:
        # TODO: fix this
        import logging
        logger = logging.getLogger("FCD")
        logger.setLevel(logging.DEBUG)

    #else:
    #    log.info("No input file specified. Exiting")
    #    raise SystemExit

    try:
        parse_input(options)
            #, timestamp,build_options=build_options, grid=options.grid)
    except ParserException,e:
        log.error("Unable to parse device configurations", exc_info=True)
        sys.exit()
    except Exception, err:
        log.error(
            "Unable to parse device configurations: %s. More information may be available in the debug log." % err)
        log.debug("Unable to parse device configurations", exc_info=True)
        sys.exit()


def parse_input(options):
    """ validate and parse input high-level description file"""
    if options.config:
       log.info("Parsing device configuration files located in : %s"%(options.config))
       InputParser().ParseDeviceConfigurations(options.config)

# !! The main function are only here for debug. The real compiler don't need this`!!
if __name__ == '__main__':

    from config_parser import ConfigParser
    import os

    # Gets firewall configuration path
    # MODIFY this path to input your own Cisco ASA series firewall configuration file
    cwd = os.getcwd()
    firewall_configuration_file_path = os.path.join(cwd, 'sample_config')

    # Load config and parse
    parser=ConfigParser()
    parser.Parse("F:\Parser Input-pwc")

    #import sys
    #global warningfound
    # parse high-level spec
    #args= parse_options("--policy /Users/a1070571/Documents/bin/code1.policyml")#mac-("--policy /Users/a1070571/Documents/bin/code1.policyml") #windows-("--policy c:\\bin\\code1.policyml") #linux-("--policy /home/dinesha/Downloads/code1.policyml")
    #main(args)
    # compile to network-level
    #args= parse_options("--network c:\\bin\\network100.graphml")#("--network /home/dinesha/Downloads/network100.graphml")#("--network /Users/a1070571/Documents/bin/network.graphml")#("--network c:\\bin\\network100.graphml")
    #main(args)
    # render
    #args= parse_options("--render cisco")
    #main(args)
    #args= parse_options("--deploy start")
    #main(args)









