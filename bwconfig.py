import os
import logging
import ConfigParser


def get_config():
    config_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "config", "config.ini")
    if not os.path.exists(config_file_path):
        raise EnvironmentError("No configuration file found")

    logging.debug("reading config file")
    config = ConfigParser.ConfigParser()
    try:
        config.read(config_file_path)
        # if given loglevel is debug:
        # TODO: check config file integrity
        # if globalVars.config.getint("BOSWatch", "loglevel") == 10:
    except ConfigParser.Error as error:
        # we cannot work without config, log and re-raise
        #logging.critical("cannot read config file %s", error)
        #logging.debug("cannot read config file", exc_info=True)
        raise
    return config
