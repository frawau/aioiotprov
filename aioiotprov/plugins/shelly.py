#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This plugin handles the provisioning of Shelly devices running Tasmota
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

DELAY=2

class Shelly(object):

    name = "shelly"

    def __init__(self,mac):
        """
        The go_on attribute must exist. It is set to False when provisioning is done

        :param mac: MAC address of the device being provisioned
        :type mac: str
        """
        self.go_on=True
        self.myid = "".join(mac.split(":")[-3:]).upper()
        self.myauth = None
        self.mac = mac

    @classmethod
    def can_handle(self,cells):
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
            if x.lower().strip().startswith("shelly"):
                resu[x]={"passwd":"", "ip":"", "ipv6":""}

        return resu

    async def secure(self,user,passwd):
        """ Setting the password... and remembering it for subsequent access """
        if passwd:
            params={"enabled": 1, "username": user,"password":passwd}
            self.myauth = aioh.BasicAuth(login=user, password=passwd)
            try:
                async with aioh.ClientSession(auth=self.myauth) as session:
                    async with session.request("get","http://192.168.33.1/settings/login",params=params) as resp:
                        logging.debug(resp.url)
                        logging.debug("Shelly: Response status was {}".format(resp.status))
                        if resp.status != 200:
                            self.myauth = None
                        try:
                            logging.debug("Shelly: Response was {}".format( await resp.text()))
                        except:
                            pass
                        logging.debug("Shelly: Password %sset"%((self.myauth is None and "not") or "" ))
                await asyncio.sleep(DELAY)
            except Exception as e:
                logging.debug("Shelly: Something really went wrong when setting user/password: {}".format(e))
                await asyncio.sleep(0)
        else:
            await asyncio.sleep(0)

    async def set_options(self,options={}):
        """ Could set MQTT here

        :param options: A list of options to be set. Here MQTT setting is possible
        :type options: dict

        """
        logging.debug("options --> {}".format(options))
        if "mqtt" in options and options["mqtt"] in [True, "on", 1, '1']:
            if "host" in options:
                #All parameters shouuld be there I think
                params={"mqtt_enable": 1 }
                for k,o in [("host","mqtt_server"),("user","mqtt_user"),
                            ("password","mqtt_pass")]:
                    if k in options:
                        params[o]=options[k] #Set MQTT
                if "port" in options:
                    params["mqtt_server"]+=":"+options["port"]
                else:
                     params["mqtt_server"]+=":1883"
                async with aioh.ClientSession(auth=self.myauth) as session:
                    async with session.request("get","http://192.168.33.1/settings/mqtt",params=params) as resp:
                        logging.debug(resp.url)
                        logging.debug("Shelly: Response status was {}".format(resp.status))
                        if resp.status != 200:
                            logging.debug("Shelly: MQTT not configured")
                        else:
                            logging.debug("Shelly: MQTT configured")
                        try:
                            logging.debug("Shelly: Response was {}".format( await resp.text()))
                        except:
                            pass
                await asyncio.sleep(DELAY)
            else:
                logging.warning("Warning: host must be defined for MQTT to be enabled.")
                await asyncio.sleep(0)
        else:
            await asyncio.sleep(0)

    async def provision(self, ip, ssid, psk, ktype):
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
        resu={}
        try:
            params = {"enabled":1, "ssid": ssid, "key": psk, "ipv4_method":"dhcp"}
            async with aioh.ClientSession(auth=self.myauth) as session:
                async with session.request("get","http://192.168.33.1/settings/sta",params=params) as resp:
                    logging.debug(resp.url)
                    logging.debug("Shelly: Response status was {}".format(resp.status))
                    if resp.status != 200:
                        raise Exception()
            logging.debug("Shelly: Set SSID and key")
            resu[self.mac] = {"type":"Shelly"}
        except:
            logging.debug("Shelly: Could not set SSID")
        await asyncio.sleep(2)
        self.go_on = False
        return resu

PluginObject=Shelly
