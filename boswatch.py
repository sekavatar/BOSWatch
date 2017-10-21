#!/usr/bin/python
# -*- coding: UTF-8 -*-
#
"""
BOSWatch
Python script to receive and decode German BOS information with rtl_fm and multimon-NG
Through a simple plugin system, data can easily be transferred to other applications
For more information see the README.md

@author: 		Bastian Schroll
@author: 		Jens Herrmann

Thanks to smith_fms and McBo from Funkmeldesystem.de - Forum for Inspiration and Groundwork!

GitHUB:		https://github.com/Schrolli91/BOSWatch
"""

import logging
import logging.handlers

import argparse		 # for parse the args
import ConfigParser	 # for parse the config file
import os			 # for log mkdir
import sys			 # for py version
import time			 # for time.sleep()
import subprocess	 # for starting rtl_fm and multimon-ng
import shlex         # for command line parameter splitting

from includes import globalVars  # Global variables
from includes import checkSubprocesses  # check startup of the subprocesses
from includes.helper import configHandler
from includes.helper import freqConverter


def init_logging(args):
    #
    # Create new bw_logger...
    #

    bw_logger = logging.getLogger()
    bw_logger.setLevel(logging.DEBUG)
    # set log string format
    formatter = logging.Formatter('%(asctime)s - %(module)-15s [%(levelname)-8s] %(message)s', '%d.%m.%Y %H:%M:%S')
    # create a file logger
    # TODO: read backupCount from config file, so that we can remove additional class
    fh = logging.handlers.TimedRotatingFileHandler(os.path.join(globalVars.log_path, "boswatch.log"), "midnight",
                                                   interval=1, backupCount=9)
    # Starts with log level >= Debug
    # will be changed with config.ini-param later
    # TODO: read log level from config file
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    bw_logger.addHandler(fh)
    # create a display logger
    ch = logging.StreamHandler()
    # log level for display: Default: info
    if args.verbose:
        ch.setLevel(logging.DEBUG)
    elif args.quiet:
        ch.setLevel(logging.CRITICAL)
    else:
        ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    bw_logger.addHandler(ch)

    # initialization of the logging was fine, continue...

    try:
        # Clear the log files
        fh.doRollover()
        open(os.path.join(globalVars.log_path, "rtl_fm.log"), "w").close()
        open(os.path.join(globalVars.log_path, "multimon.log"), "w").close()
        open(os.path.join(globalVars.log_path, "mm_raw.txt"), "w").close()
        logging.debug("BOSWatch has started")
        logging.debug("Log files cleared")

    except IOError:
        # It's an error, but we could work without that stuff...
        logging.error("cannot clear Logfiles")
        logging.debug("cannot clear Logfiles", exc_info=True)

    # For debug display/log args

    logging.debug("SW Version:	%s", globalVars.versionNr)
    logging.debug("Branch:		%s", globalVars.branch)
    logging.debug("Build Date:	%s", globalVars.buildDate)
    logging.debug("Python Vers:	%s", sys.version)
    logging.debug("BOSWatch given arguments")
    if args.test:
        logging.debug(" - Test-Mode!")

    logging.debug(" - Frequency: %s", freqConverter.freqToHz(args.freq))
    logging.debug(" - Device: %s", args.device)
    logging.debug(" - PPM Error: %s", args.error)
    logging.debug(" - Squelch: %s", args.squelch)
    logging.debug(" - Gain: %s", args.gain)


def check_dependencies():
    return "something", None, None


def parse_config(config_file_path):
    #
    # Read config.ini
    #
    # if not os.path.exists(os.path.dirname(os.path.abspath(__file__)) + "/config/config.ini"):
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
        logging.critical("cannot read config file %s", error)
        logging.debug("cannot read config file", exc_info=True)
        raise
    return config


#
# ArgParser
# Have to be before main program
#
def get_arguments():
    # With -h or --help you get the Args help
    parser = argparse.ArgumentParser(
        description="BOSWatch is a Python Script to recive and decode german BOS information with rtl_fm and multimon-NG",
        epilog="More options you can find in the extern config.ini file in the folder /config")
    # parser.add_argument("-c", "--channel", help="BOS Channel you want to listen")
    parser.add_argument("-f", "--freq", help="Frequency you want to listen to", required=True)
    parser.add_argument("-d", "--device", help="Device you want to use (check with rtl_test)", type=int, default=0)
    parser.add_argument("-e", "--error", help="Frequency-error of your device in PPM", default=0)
    parser.add_argument("-a", "--demod", help="Demodulation functions",
                        choices=['FMS', 'ZVEI', 'POC512', 'POC1200', 'POC2400'], required=True, nargs="+")
    parser.add_argument("-s", "--squelch", help="Level of squelch", type=int, default=0)
    parser.add_argument("-g", "--gain", help="Level of gain", type=int, default=100)
    parser.add_argument("-u", "--usevarlog",
                        help="Use '/var/log/boswatch' for logfiles instead of subdir 'log' in BOSWatch directory",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="Show more information", action="store_true")
    parser.add_argument("-q", "--quiet", help="Show no information. Only logfiles", action="store_true")
    # We need this argument for testing (skip instantiate of rtl-fm and multimon-ng):
    parser.add_argument("-t", "--test", help=argparse.SUPPRESS, action="store_true")
    return parser.parse_args()


#
# Main program
#
def main():
    rtl_fm = None
    multimon_ng = None
    nma_handler = None
    args = get_arguments()

    #
    # Script-pathes
    #
    # globalVars.script_path = os.path.dirname(os.path.abspath(__file__))

    #
    # Set log_path
    #
    if args.usevarlog:
        globalVars.log_path = "/var/log/BOSWatch/"
    else:
        globalVars.log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log")

    #
    # If necessary create log-path
    #
    if not os.path.exists(globalVars.log_path):
        os.mkdir(globalVars.log_path)

    config = parse_config(os.path.join(globalVars.script_path, "config", "config.ini"))

    init_logging(args)
    try:
        rtl_fm, multimon_ng, nma_handler = check_dependencies()

        demodulation = ""
        if "FMS" in args.demod:
            demodulation += "-a FMSFSK "
            logging.debug(" - Demod: FMS")
        if "ZVEI" in args.demod:
            demodulation += "-a ZVEI1 "
            logging.debug(" - Demod: ZVEI")
        if "POC512" in args.demod:
            demodulation += "-a POCSAG512 "
            logging.debug(" - Demod: POC512")
        if "POC1200" in args.demod:
            demodulation += "-a POCSAG1200 "
            logging.debug(" - Demod: POC1200")
        if "POC2400" in args.demod:
            demodulation += "-a POCSAG2400 "
            logging.debug(" - Demod: POC2400")

        logging.debug(" - Use /var/log: %s", args.usevarlog)
        logging.debug(" - Verbose Mode: %s", args.verbose)
        logging.debug(" - Quiet Mode: %s", args.quiet)

        if not args.quiet:  # only if not quiet mode
            from includes import shellHeader
            shellHeader.printHeader(args)

        if args.test:
            logging.warning("!!! We are in Test-Mode !!!")

        #
        # Add NMA logging handler
        #
        if nma_handler is not None:
            if config.getboolean("NMAHandler", "enableHandler"):
                # We do need some API key
                if len(config.get("NMAHandler", "APIKey")) > 0:
                    logging.debug("adding NMA logging handler")
                    from includes import NMAHandler  # TODO: Install nmapy as python module
                    if config.get("NMAHandler", "appName") == "":
                        nma_handler = NMAHandler.NMAHandler(config.get("NMAHandler", "APIKey"))
                    else:
                        nma_handler = NMAHandler.NMAHandler(config.get("NMAHandler", "APIKey"),
                                                            config.get("NMAHandler", "appName"))
                    nma_handler.setLevel(config.getint("NMAHandler", "loglevel"))
                    logging.getLogger().addHandler(nma_handler)
        else:
            # It's an error, but we can work without that stuff...
            logging.error("cannot add NMA logging handler")
            logging.debug("cannot add NMA logging handler", exc_info=True)

        # initialization was fine, continue with main program...

        #
        # Load plugins
        #
        # TODO: re-enable plugin loading
        # try:
        #    from includes import pluginLoader
        #    pluginLoader.loadPlugins()
        # except:
        #    # we couldn't work without plugins -> exit
        #    logging.critical("cannot load Plugins")
        #    logging.debug("cannot load Plugins", exc_info=True)
        #    exit(1)

        #
        # Load filters
        #
        # TODO: re-enable filter loading
        # try:
        #    if globalVars.config.getboolean("BOSWatch", "useRegExFilter"):
        #        from includes import regexFilter
        #        regexFilter.loadFilters()
        # except:
        #    # It's an error, but we could work without that stuff...
        #    logging.error("cannot load filters")
        #    logging.debug("cannot load filters", exc_info=True)

        #
        # TODO: re-enable description list loading
        # Load description lists
        #
        # try:
        #    if globalVars.config.getboolean("FMS", "idDescribed") or globalVars.config.getboolean("ZVEI", "idDescribed") or globalVars.config.getboolean("POC", "idDescribed"):
        #        from includes import descriptionList
        #        descriptionList.loadDescriptionLists()
        # except:
        #    # It's an error, but we could work without that stuff...
        #    logging.error("cannot load description lists")
        #    logging.debug("cannot load description lists", exc_info=True)

        #
        # Start rtl_fm
        #
        if rtl_fm is not None:
            if not args.test:
                logging.debug("starting rtl_fm")
                command = "rtl_fm"
                if config.has_option("BOSWatch", "rtl_path"):
                    command = os.path.join(config.get("BOSWatch", "rtl_path"), command)
                command += " -d " + str(args.device) + " -f " + str(freqConverter.freqToHz(args.freq)) + \
                          " -M fm -p "+str(args.error)+" -E DC -F 0 -l " + \
                          str(args.squelch) + " -g " + str(args.gain) + " -s 22050"
                rtl_fm = subprocess.Popen(shlex.split(command),
                                          stdout=subprocess.PIPE,
                                          stderr=open(globalVars.log_path + "rtl_fm.log", "a"),
                                          shell=False)
                # rtl_fm doesn't self-destruct, when an error occurs
                # wait a moment to give the subprocess a chance to write the logfile
                # TODO: I assume we are checking for errors here?
                time.sleep(3)
                checkSubprocesses.checkRTL()
            else:
                logging.warning("!!! Test-Mode: rtl_fm not started !!!")
        else:
            # we couldn't work without rtl_fm -> exit
            logging.critical("cannot start rtl_fm")
            logging.debug("cannot start rtl_fm", exc_info=True)
            raise EnvironmentError("rtl_fm could not be started")

        #
        # Start multimon
        #
        if multimon_ng is not None:
            if not args.test:
                logging.debug("starting multimon-ng")
                command = ""
                if globalVars.config.has_option("BOSWatch", "multimon_path"):
                    command = globalVars.config.get("BOSWatch", "multimon_path")
                command += "multimon-ng " + str(demodulation) + " -f alpha -t raw /dev/stdin - "
                multimon_ng = subprocess.Popen(command.split(),
                                               stdin=rtl_fm.stdout,
                                               stdout=subprocess.PIPE,
                                               stderr=open(globalVars.log_path+"multimon.log", "a"),
                                               shell=False)
                # multimon-ng  doesn't self-destruct, when an error occurs
                # wait a moment to give the subprocess a chance to write the logfile
                time.sleep(3)
                checkSubprocesses.checkMultimon()
            else:
                logging.warning("!!! Test-Mode: multimon-ng not started !!!")
        else:
            # we couldn't work without multimon-ng -> exit
            logging.critical("cannot start multimon-ng")
            logging.debug("cannot start multimon-ng", exc_info=True)
            exit(1)

        #
        # Get decoded data from multimon-ng and call BOSWatch-decoder
        #
        if not args.test:
            logging.debug("start decoding")
            while True:
                decoded = str(multimon_ng.stdout.readline())  # Get line data from multimon stdout
                from includes import decoder
                decoder.decode(freqConverter.freqToHz(args.freq), decoded)

                # write multimon-ng raw data
                if globalVars.config.getboolean("BOSWatch", "writeMultimonRaw"):
                    try:
                        raw_mm_out = open(globalVars.log_path+"mm_raw.txt", "a")
                        raw_mm_out.write(decoded)
                    except:
                        logging.warning("cannot write raw multimon data")
                    finally:
                        raw_mm_out.close()
        else:
            logging.debug("start testing")
            test_file = open(globalVars.script_path+"/citest/testdata.txt", "r")
            for testData in test_file:
                if (len(testData.rstrip(' \t\n\r')) > 1) and ("#" not in testData[0]):
                    logging.info("Testdata: %s", testData.rstrip(' \t\n\r'))
                    from includes import decoder
                    decoder.decode(freqConverter.freqToHz(args.freq), testData)
            logging.debug("test finished")

    except KeyboardInterrupt:
        logging.warning("Keyboard Interrupt")
    except SystemExit:
        # SystemExitException is thrown if daemon was terminated
        logging.warning("SystemExit received")
        # only exit to call finally-block
        exit()
    except:
        logging.exception("unknown error")
    finally:
        try:
            logging.debug("BOSWatch shuting down")
            if multimon_ng and multimon_ng.pid:
                logging.debug("terminate multimon-ng (%s)", multimon_ng.pid)
                multimon_ng.terminate()
                multimon_ng.wait()
                logging.debug("multimon-ng terminated")
            if rtl_fm and rtl_fm.pid:
                logging.debug("terminate rtl_fm (%s)", rtl_fm.pid)
                rtl_fm.terminate()
                rtl_fm.wait()
                logging.debug("rtl_fm terminated")
            logging.debug("exiting BOSWatch")
        except:
            logging.warning("failed in clean-up routine")
            logging.debug("failed in clean-up routine", exc_info=True)

        finally:
            # Close Logging
            logging.debug("close Logging")
            # Waiting for all Threads to write there logs
            if config.getboolean("BOSWatch", "processAlarmAsync"):
                logging.debug("waiting 3s for threads...")
                time.sleep(3)
            logging.info("BOSWatch exit()")
            logging.shutdown()
            if nma_handler:
                nma_handler.close()


if __name__ == "__main__":
    sys.exit(main())
