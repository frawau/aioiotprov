#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This plugin handles the provisioning of Broadlink devices
# Taken from https://github.com/mjg59/python-broadlink
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
import logging, socket


class Broadlink(object):

    name = "broadlink"

    def __init__(self, mac):
        """
        The go_on attribute must exist. It is set to False when provisioning is done

        :param mac: MAC address of the device being provisioned
        :type mac: str
        """
        self.go_on = True
        self.mac = mac

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
            if x.lower().strip().startswith("broadlink"):
                resu[x] = {"passwd": "", "ip": "", "ipv6": ""}

        return resu

    async def secure(self, user, passwd):
        """ Nothing here """
        await asyncio.sleep(0)

    async def set_options(self, options={}):
        """ Nothing here """
        await asyncio.sleep(0)

    def build_message(self, ssid, psk, ktype):
        """Build the provisioning payload

            :param ssid: The cell the device should connect to
            :type ssid: str
            :param psk: The key for the cell the device should connect to
            :type psk: str
            :param ktype: The key encyption type: wep, wpa, wpa2, none
            :type ktype: str
            :returns: the message as a bytearray
            :rtype: bytearray
        """
        payload = bytearray(0x88)
        payload[0x26] = 0x14  # This seems to always be set to 14
        # Add the SSID to the payload
        ssid_start = 68
        ssid_length = 0
        for letter in ssid:
            payload[(ssid_start + ssid_length)] = ord(letter)
            ssid_length += 1
        # Add the WiFi password to the payload
        pass_start = 100
        pass_length = 0
        for letter in psk:
            payload[(pass_start + pass_length)] = ord(letter)
            pass_length += 1
        #
        payload[0x84] = ssid_length  # Character length of SSID
        payload[0x85] = pass_length  # Character length of password
        payload[0x86] = ["none", "wep", "wpa", "wpa2"].index(
            ktype
        )  # Type of encryption (00=none,01=WEP,02=WPA1,03=WPA2,04=WPA1/2)
        #
        checksum = 0xBEAF
        for i in range(len(payload)):
            checksum += payload[i]
            checksum = checksum & 0xFFFF
        #
        payload[0x20] = checksum & 0xFF  # Checksum 1 position
        payload[0x21] = checksum >> 8  # Checksum 2 position

        return payload

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

        class BroadlinktProtocol:
            def __init__(self, payload, ip):
                self.payload = payload
                self.ip = ip

            def connection_made(self, transport):
                self.transport = transport
                sock = transport.get_extra_info("socket")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.broadcast()

            def datagram_received(self, data, addr):
                logging.debug("data received: {}, {}".format(data, addr))

            def broadcast(self):
                self.transport.sendto(
                    payload, (".".join(self.ip.split(".")[:-1] + ["255"]), 80)
                )

        payload = self.build_message(ssid, psk, ktype)
        try:
            loop = asyncio.get_running_loop()
        except:
            loop = asyncio.get_event_loop()
        coro = loop.create_datagram_endpoint(
            lambda: BroadlinktProtocol(payload, ip), local_addr=("0.0.0.0", 8080)
        )
        xx = await coro
        await asyncio.sleep(3)
        self.go_on = False
        return {self.mac: {"type": "broadlink"}}


PluginObject = Broadlink
