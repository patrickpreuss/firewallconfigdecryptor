from os.path import isabs
from properties import resources
from exception import ParserException
from config_parser import ConfigParser
from utilities import Singleton
import firewallconfigdecryptor.log as log

@Singleton
class InputParser(object):

    def __init__(self):
        return

    def ParseDeviceConfigurations(self, folder):
        import os
        default_folder_path=os.getcwd()
        # check if absolute path provided
        if not isabs(folder): folder = default_folder_path + '/' + folder
        try:
            # parses Cisco PIX, IOX, ASA firewall configurations
            parser=ConfigParser()
            parser.Parse(folder)

        except BaseException,e:
            if e.message:
                log.error(e.message)
            else:
                log.error("%s"%e)






