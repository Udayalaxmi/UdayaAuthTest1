import logging,sys
import os

LOG_FILE_PATH = './logs'
LOG_FILE_NAME = os.path.join(LOG_FILE_PATH,'authlogs.log')
LOGGER_NAME = 'oauth2log'

format = logging.Formatter("%(levelname)-10s %(asctime)s %(module)s:%(lineno)d: %(message)s")

critical_handler = logging.StreamHandler(sys.stderr)
critical_handler.setLevel(logging.CRITICAL)
critical_handler.setFormatter(format)

file_handler = logging.FileHandler(LOG_FILE_NAME)
file_handler.setFormatter(format)

log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)
log.addHandler(file_handler)
log.addHandler(critical_handler)
