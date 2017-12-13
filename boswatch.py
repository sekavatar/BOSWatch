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

import bwconfig

import argparse		 # for parse the args
import os			 # for log mkdir
import sys			 # for py version
import time			 # for time.sleep()
import subprocess	 # for starting rtl_fm and multimon-ng
import shlex         # for command line parameter splitting

from includes import globalVars  # Global variables
from includes.helper import configHandler
from includes.helper import freqConverter


def init_logging(args, log_path):
    #
    # Create new bw_logger...
    #

    bw_logger = logging.getLogger()
    bw_logger.setLevel(logging.DEBUG)
    # set log string format
    formatter = logging.Formatter('%(asctime)s - %(module)-15s [%(levelname)-8s] %(message)s', '%d.%m.%Y %H:%M:%S')
    # create a file logger
    # TODO: read backupCount from config file, so that we can remove additional class
    fh = logging.handlers.TimedRotatingFileHandler(os.path.join(log_path, "boswatch.log"), "midnight",
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
        open(os.path.join(log_path, "rtl_fm.log"), "w").close()
        open(os.path.join(log_path, "multimon.log"), "w").close()
        open(os.path.join(log_path, "mm_raw.txt"), "w").close()
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
    logging.debug(" - Frequency: %s", freqConverter.freqToHz(args.freq))
    logging.debug(" - Device: %s", args.device)
    logging.debug(" - PPM Error: %s", args.error)
    logging.debug(" - Squelch: %s", args.squelch)
    logging.debug(" - Gain: %s", args.gain)


def start_rtl_fm(executable, device, freq, error_freq, squelch, gain, log_path):
    logging.debug("starting rtl_fm")
    command = executable + " -d " + str(device) + " -f " + str(freqConverter.freqToHz(freq)) + \
              " -M fm -p " + str(error_freq) + " -E DC -F 0 -l " + \
              str(squelch) + " -g " + str(gain) + " -s 22050"
    return(subprocess.Popen(shlex.split(command),
                            stdout=subprocess.PIPE,
                            stderr=open(os.path.join(log_path, "rtl_fm.log"), "a"),
                            shell=False))
    # rtl_fm doesn't self-destruct, when an error occurs
    # wait a moment to give the subprocess a chance to write the logfile
    # TODO: I assume we are checking for errors here?
    # TODO: removing this for now, it'll only check to see if rtl_fm won't quit with an error
    # TODO: if ("exiting" in rtlLog) or  ("Failed to open" in rtlLog): Append fail log to debug output
    # time.sleep(3)
    # checkSubprocesses.checkRTL()


def start_multimon_ng(executable, rtl_fm_handle, demodulation, log_path):
    logging.debug("starting multimon-ng")
    command = executable + " " + str(demodulation) + " -f alpha -t raw /dev/stdin - "
    # TODO: if ("invalid" in multimonLog) or ("error" in multimonLog): append fail to debuglog
    return subprocess.Popen(command.split(),
                            stdin=rtl_fm_handle.stdout,
                            stdout=subprocess.PIPE,
                            stderr=open(os.path.join(log_path, "multimon.log"), "a"),
                            shell=False)


#
# Parse argv
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

    log_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "log")
    args = get_arguments()

    #
    # Script-pathes
    #
    # globalVars.script_path = os.path.dirname(os.path.abspath(__file__))

    #
    # Set log_path
    #
    if args.usevarlog:
        log_path = "/var/log/BOSWatch/"

    #
    # If necessary create log-path
    #
    if not os.path.exists(log_path):
        os.mkdir(log_path)

    cfg = bwconfig.get_config()

    init_logging(args, log_path)

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

    #
    # Add NMA logging handler
    #
    if cfg.getboolean("NMAHandler", "enableHandler"):
        # We do need some API key
        if len(cfg.get("NMAHandler", "APIKey")) > 0:
            logging.debug("adding NMA logging handler")
            from includes import NMAHandler  # TODO: Check if we can fullfill dependency
            if cfg.get("NMAHandler", "appName") == "":
                nma_handler = NMAHandler.NMAHandler(cfg.get("NMAHandler", "APIKey"))
            else:
                nma_handler = NMAHandler.NMAHandler(cfg.get("NMAHandler", "APIKey"),
                                                    cfg.get("NMAHandler", "appName"))
            nma_handler.setLevel(cfg.getint("NMAHandler", "loglevel"))
            logging.getLogger().addHandler(nma_handler)

    #
    # Load plugins
    #
    try:
        from includes import pluginLoader
        pluginLoader.loadPlugins()
    except:
        # we couldn't work without plugins -> exit
        logging.critical("cannot load Plugins")
        logging.debug("cannot load Plugins", exc_info=True)
        exit(1)

    #
    # Load filters
    #
    try:
        if cfg.getboolean("BOSWatch", "useRegExFilter"):
            from includes import regexFilter
            regexFilter.loadFilters()
    except:
        # It's an error, but we could work without that stuff...
        logging.error("cannot load filters")
        logging.debug("cannot load filters", exc_info=True)

    #
    # Load description lists
    #
    try:
        if cfg.getboolean("FMS", "idDescribed")\
                or cfg.getboolean("ZVEI", "idDescribed")\
                or cfg.getboolean("POC", "idDescribed"):
            from includes import descriptionList
            descriptionList.loadDescriptionLists()
    except:
        # It's an error, but we could work without that stuff...
        logging.error("cannot load description lists")
        logging.debug("cannot load description lists", exc_info=True)

    if args.test:
        logging.debug("start testing")
        test_file = open(os.path.join(globalVars.script_path, "citest/testdata.txt"), "r")
        for testData in test_file:
            if (len(testData.rstrip(' \t\n\r')) > 1) and ("#" not in testData[0]):
                logging.info("Testdata: %s", testData.rstrip(' \t\n\r'))
                from includes import decoder
                decoder.decode(freqConverter.freqToHz(args.freq), testData)
        logging.debug("test finished")
        return 0

    #
    # Start rtl_fm
    #
    rtl_fm = start_rtl_fm(os.path.join(cfg.get("BOSWatch", "rtl_path"), "rtl_fm"),
                          args.device, args.freq, args.error, args.squelch, args.gain, log_path)

    #
    # Start multimon
    #
    multimon_ng = start_multimon_ng(os.path.join(cfg.get("BOSWatch", "multimon_path"), "multimon-ng"), rtl_fm,
                                    demodulation, log_path)

    #
    # Get decoded data from multimon-ng and call BOSWatch-decoder
    #
    try:
        logging.debug("start decoding")
        while True:
            decoded = str(multimon_ng.stdout.readline())  # Get line data from multimon stdout
            from includes import decoder
            decoder.decode(freqConverter.freqToHz(args.freq), decoded)

            # write multimon-ng raw data
            if cfg.getboolean("BOSWatch", "writeMultimonRaw"):
                try:
                    raw_mm_out = open(os.path.join(log_path, "mm_raw.txt"), "a")
                    raw_mm_out.write(decoded)
                except:
                    logging.warning("cannot write raw multimon data")
                finally:
                    raw_mm_out.close()

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
            if cfg.getboolean("BOSWatch", "processAlarmAsync"):
                logging.debug("waiting 3s for threads...")
                time.sleep(3)
            logging.info("BOSWatch exit()")
            logging.shutdown()
            if nma_handler:
                nma_handler.close()


if __name__ == "__main__":
    sys.exit(main())
