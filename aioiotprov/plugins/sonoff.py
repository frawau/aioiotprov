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
import string
import random
def id_generator(size=5, chars=string.ascii_lowercase + string.digits):
   return ''.join(random.choice(chars) for _ in range(size))

class Sonoff(object):

    name = "Sonoff"

    def __init__(self):
        """
        The go_on attribute must exist. It is set to False when provisioning is done
        """
        self.go_on=True
        self.myid = id_generator()
        self.mypassword = ""
        pass

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
            if x.lower().strip().startswith("sonoff-"):
                resu[x]={"passwd":"", "ip":"", "ipv6":""}

        return resu

    async def secure(self,user,passwd):
        """ Nothing here """
        if passwd:
            self.mypassword = passwd
            params={"w":"5,1","p1":passwd,"a1":"Sonoff-%s"%id_generator(),"b2":0}
            auth = aioh.BasicAuth(login="admin", password=self.mypassword)
            async with aioh.ClientSession(auth=auth) as session:
                async with session.request("get","http://192.168.4.1/sv",params=params) as resp:
                    logging.debug(resp.url)
                    logging.debug("Sonoff: Response status was {}".format(resp.status))
                    if resp.status != 200:
                        self.mypassword = ""
                    try:
                        logging.debug("Sonoff: Response was {}".format( await resp.text()))
                    except:
                        pass
                    logging.debug("Sonoff: Set password")
            await asyncio.sleep(16)
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
        try:
            params = {"w":"1,1","s1":ssid,"p1":psk,"s2":ssid, "p2":psk,"h":"%s-%04d"}
            if self.mypassword:
                auth = aioh.BasicAuth(login="admin", password=self.mypassword)
                async with aioh.ClientSession(auth=auth) as session:
                    async with session.request("get","http://192.168.4.1/sv",params=params) as resp:
                        logging.debug(resp.url)
                        logging.debug("Sonoff: Response status was {}".format(resp.status))
            else:
                async with aioh.ClientSession() as session:
                    async with session.request("get","http://192.168.4.1/sv",params=params) as resp:
                        logging.debug(resp.url)
                        logging.debug("Sonoff: Response status was {}".format(resp.status))
            logging.debug("Sonoff: Set SSID and key")
        except:
            logging.debug("Sonoff: Could not set SSID")
        await asyncio.sleep(2)
        self.go_on = False
        return {}

PluginObject=Sonoff