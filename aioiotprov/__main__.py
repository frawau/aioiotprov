#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application looks for known AP (defined by plugins)
# and attempt to provision the respective IoT devices
#
# Copyright (c) 2018 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE
#
#
import argparse, os, sys, asyncio
import aioiotprov as aiop
import logging, json, shutil


class OptionString(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        self._nargs = nargs
        super(OptionString, self).__init__(option_strings, dest, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        options = {}

        try:
            for aval in values:
                key = aval.split(":")[0].strip()
                allvals = {}
                lovals = (":".join(aval.split("::")[1:])).split("||")
                for aval in lovals:
                    vkey = (aval.split("=="))[0].strip()
                    allvals[vkey] = (aval.split("=="))[1].strip()
                options[key] = allvals
        except:
            raise argparse.ArgumentTypeError(
                'Could not parse options "{}". You might want to add -- to end the options.'.format(
                    aval
                )
            )
        setattr(namespace, self.dest, options)


def main(args=None):
    # Needed arguments
    parser = argparse.ArgumentParser(description="Provision IoT devices")
    parser.add_argument("ssid", help="The SSID the device must be attaching to.")
    parser.add_argument(
        "passphrase", nargs="?", default="", help="The secret passphrase for the SSID."
    )
    parser.add_argument(
        "-u",
        "--user",
        default="",
        help="The user that will control access to the device",
    )
    parser.add_argument(
        "-p",
        "--password",
        default="",
        help="The password that will control access to the device.",
    )
    parser.add_argument(
        "-P", "--plugin", action="append", help="Select which plugin to use."
    )
    parser.add_argument(
        "-o",
        "--options",
        dest="options",
        default={},
        action=OptionString,
        nargs="*",
        metavar="<plugin>::opt1==val1||opt2==val2||..",
        help="Option to be passed to plugins.",
    )
    parser.add_argument(
        "-w",
        "--wpa",
        default=False,
        action="store_true",
        help="Use wpa_cli to control WiFi if command not found.",
    )
    parser.add_argument(
        "-n",
        "--nm",
        default=False,
        action="store_true",
        help="Use nmcli to control WiFi if command not found.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Print more information.",
    )
    parser.add_argument(
        "-j", "--json", default=False, action="store_true", help="Print result as json."
    )
    parser.add_argument(
        "-l",
        "--list",
        default=False,
        action="store_true",
        help="Just list the available SSID.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="Print debug information.",
    )

    try:
        opts = parser.parse_args()
    except Exception as e:
        parser.error("Error: " + str(e))
        sys.exit(1)

    if shutil.which("nmcli"):
        wifictl = aiop.NMWiFiManager()
    elif shutil.which("wpa_cli"):
        wifictl = aiop.WPAWiFiManager()
    elif opts.wpa:
        wifictl = aiop.WPAWiFiManager()
    elif opts.nm:
        wifictl = aiop.NMWiFiManager()
    else:
        print(
            "Error: Do not know how to managge WiFi interfaces. Neither 'nmcli' nor 'wpa_cli' are present."
        )
        sys.exit(1)

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif opts.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)

    loop = asyncio.get_event_loop()
    # First let's make sure we have the needed commands
    isok, errmsg = loop.run_until_complete(aiop.check_system())
    if not isok:
        print(errmsg)
        loop.close()
        sys.exit(1)

    provisioner = aiop.IoTProvision(opts.ssid, opts.passphrase, manager=wifictl)
    provisioner.set_secure(opts.user, opts.password)

    # First find out what interfaces are available
    interfaces = loop.run_until_complete(provisioner.gather_netinfo())

    if opts.list:
        loc = set()
        for aloc in provisioner.cells.values():
            for acell in [x["ssid"] for x in aloc]:
                loc.add(acell)
        print(json.dumps(list(loc)))
    else:
        if not provisioner.cells:
            print("Error: There seem to be no wifi adapter")
            sys.exit(2)

        isset = provisioner.select_iface(interfaces, provisioner.cells)
        if not isset:
            print("Error: No interface could be selected")

        else:
            logging.info(
                "Using interface {} with restore {}".format(
                    provisioner.iface, provisioner.is_shared
                )
            )
            resu = loop.run_until_complete(
                provisioner.provision(options=opts.options, plugins=opts.plugin)
            )
            logging.info("Got: {}".format(resu))
            if opts.json:
                print(json.dumps(resu))
    loop.close()


if __name__ == "__main__":
    main()
