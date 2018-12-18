#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This plugin handles the provisioning of TP-Link devices
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
from struct import pack
import logging
import json

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
        key = 171
        result = pack('>I', len(string))
        for i in string:
                a = key ^ ord(i)
                key = a
                result += bytes([a])
        return result

def decrypt(string):
        key = 171
        result = ""
        for i in string:
                a = key ^ i
                key = i
                result += chr(a)
        return result



class TPLink(object):

    name = "tp-link"

    def __init__(self,mac):
        """
        The go_on attribute must exist. It is set to False when provisioning is done

        :param mac: MAC address of the device being provisioned
        :type mac: str

        """
        self.go_on=True
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
            if x.lower().strip().startswith("tp-link"):
                resu[x]={"passwd":"", "ip":"", "ipv6":""}

        return resu

    async def secure(self,user,passwd):
        """ Nothing here """
        await asyncio.sleep(0)

    async def set_options(self,options={}):
        """ Nothing here """
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
        try:
            reader, writer = await asyncio.open_connection(".".join(ip.split(".")[:-1]+["1"]), 9999)
        except:
            self.go_on = False
            return {}
        message = """{"netif":{"set_stainfo":{"ssid":"%s","password":"%s","key_type":%d}}}"""
        message = message%(ssid,psk,["none","wep","wpa","wpa2"].index(ktype))
        logging.debug('TP-Link: Send: %r' % message)
        writer.write(encrypt(message))
        data = await reader.read(100)
        data = json.loads(decrypt(data[4:]))
        logging.debug('Received: %r' % data)
        writer.close()
        self.go_on = False
        resu = {}
        try:
            if data['netif']['set_stainfo']['err_code'] == 0:
                resu[data['netif']['set_stainfo']['mac']] = {"type":"TP-Link"}
        except:
            pass
        finally:
            return resu

PluginObject=TPLink
