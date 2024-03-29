import logging
import logging.handlers
import firewallconfigdecryptor.config as config


fcd_logger = logging.getLogger("FCD")
if not fcd_logger.handlers:
    console_formatter = logging.Formatter("%(levelname)-1s %(message)s")
    ch = logging.StreamHandler()
    #ch.setLevel(logging.INFO)
    ch.setFormatter(console_formatter)
    fcd_logger.addHandler(ch)

    file_logging = config.settings['Logging']['file']
    if file_logging:
        LOG_FILENAME =  "firewallconfigdecryptor.log"
        #fh = logging.FileHandler(LOG_FILENAME)
        LOG_SIZE = 2097152 # 2 MB
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILENAME, maxBytes=LOG_SIZE, backupCount=5)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s %(levelname)s "
            "%(funcName)s %(message)s")
        fh.setFormatter(formatter)
        fcd_logger.addHandler(fh)

fcd_logger.setLevel(logging.INFO)
# Reference for external access
logger = fcd_logger
# Use approach of Pika, allows for firewallconfigdecryptor.log.debug("message")
debug = logger.debug
error = logger.error
info = logger.info
warning = logger.warning
exception = logger.exception
critical = logger.critical
