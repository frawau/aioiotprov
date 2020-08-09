#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This plugin handles the provisioning of Sonoff devices running Tasmota
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
#
import asyncio
import aiohttp as aioh
import logging
import urllib

# DELAY=17
DELAY = 5


class Tasmota(object):

    name = "tasmota"

    def __init__(self, mac):
        """
        The go_on attribute must exist. It is set to False when provisioning is done

        :param mac: MAC address of the device being provisioned
        :type mac: str
        """
        self.go_on = True
        self.myid = "".join(mac.split(":")[-3:]).upper()
        self.myauth = None
        self.mac = mac
        self.options = {}

    @classmethod
    def can_handle(self, cells):
        """ Given a list of cell names, return a list of those it can handle

        :param cells: A list of cell names
        :type cmd: list
        :returns: A dictionary of those it can handle. The key is the cell's name, the value a dictionary
                  with a WIFI key "passwd" (empty is not needed) and IP addresses "ip" and "ipv6" (empty if use dhcp)
                  IP address must be of the form <address>/<bits>
        :rtype: dict
        """
        resu = {}
        for x in cells:
            if x.lower().strip().startswith("tasmota_"):
                resu[x] = {"passwd": "", "ip": "", "ipv6": ""}

        return resu

    async def secure(self, user, passwd):
        """ Setting the password... and remembering it for subsequent access
        With tasmota, we use the backlog command, to set everything at onece, so here we setup
        the options attribute
        """
        if passwd:
            self.myauth = aioh.BasicAuth(login=user, password=passwd)
            self.options["WebPassword"] = passwd
        await asyncio.sleep(0)

    async def set_options(self, options={}):
        """ Could set MQTT here

        :param options: A list of options to be set. Here MQTT setting is possible
        :type options: dict

        """
        logging.debug("options --> {}".format(options))
        # params = {}
        if "template" in options:
            self.options["Template"] = options["template"]
            self.options["Module"] = 0
            # params["t1"] = options["template"]
            # params["t2"] = 'on'
        elif "module" in options:
            self.options["Module"] = options["module"]

        if "mqtt" in options:
            if options["mqtt"] in [True, "on", 1]:
                self.options["SetOption3"] = 1
                for k, o in [
                    ("host", "MqttHost"),
                    ("port", "MqttPort"),
                    ("user", "MqttUser"),
                    ("password", "Mqttpassword"),
                ]:
                    if k in options:
                        self.options[o] = options[k]  # Set MQTT

                for k, o in [
                    ("client", "MqttClient"),
                    ("topic", "Topic"),
                    ("full topic", "FullTopic"),
                ]:
                    if k in options:
                        self.options[o] = options[k].replace(
                            "{mac}", "".join(self.mac.split(":")[-3:]).lower()
                        )  # Set MQTT
        await asyncio.sleep(0)

    async def provision(self, ip, ssid, psk, ktype="none"):
        """Coroutine to perform provisioning

           As long as this method returns AGAIN, this coroutine must be called after switching
           wireless network if necessary. Each AGAIN shoud toggle between the device being provisioned
           cell and the original cell (nothig is done if the interface was not being used.

           If information is returnedits handling should be application specific.

            :param ip: IP address of the interface configured to access the device
            :type cmd: str
            :param ssid: The cell the device should connect to
            :type ssid: str
            :param psk: The key for the cell the device should connect to
            :type psk: str
            :param ktype: The key encyption type: wep, wpa, wpa2, none
            :type ktype: str
            :returns: a dictionary of information or AGAIN if needed
            :rtype: list
        """
        resu = {}
        try:
            self.options.update(
                {
                    "SSID": ssid,
                    "PASSWORD1": psk,
                    "SSID2": ssid,
                    "PASSWORD2": psk,
                    "HOSTNAME": "1",
                }
            )
            param = {
                "cmnd": "Backlog "
                + ";".join([f"{x} {y}" for x, y in self.options.items()])
            }
            param = urllib.parse.urlencode(param, quote_via=urllib.parse.quote)
            doitagin = False
            async with aioh.ClientSession(auth=self.myauth) as session:
                async with session.request(
                    "get", "http://192.168.4.1/cm", params=param
                ) as resp:
                    logging.debug(resp.url)
                    logging.debug("Tasmota: Response status was {}".format(resp.status))
                    if resp.status == 401:
                        doitagin = True
            if doitagin:
                async with aioh.ClientSession(auth=None) as session:
                    async with session.request(
                        "get", "http://192.168.4.1/cm", params=param
                    ) as resp:
                        logging.debug(resp.url)
                        logging.debug(
                            "Tasmota: Response status was {}".format(resp.status)
                        )

            logging.debug("Tasmota: Set SSID and key")
            resu[self.mac] = {"type": "Tasmota"}
        except Exception as e:
            logging.debug(f"Tasmota: Could not set SSID: {e}")
            logging.exception(e)
        await asyncio.sleep(2)
        self.go_on = False
        return resu


PluginObject = Tasmota
