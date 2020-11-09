#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This plugin handles the provisioning of Yeelight devices
# This is based on the protocol descrition, and the code from
# https://github.com/OpenMiHome/mihome-binary-protocol.
# Some of the code was copied.
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
from struct import pack, unpack
import logging
import json
import hashlib
import os
from base64 import b64encode

# https://cryptography.io/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from time import time

_backend = default_backend()


def md5(inp: bytes) -> bytes:
    m = hashlib.md5()
    m.update(inp)
    return m.digest()


def key_iv(token: bytes) -> (bytes, bytes):
    """Derive (Key, IV) from a Xiaomi MiHome device token (128 bits)."""
    key = md5(token)
    iv = md5(key + token)
    return (key, iv)


def AES_cbc_encrypt(token: bytes, plaintext: bytes) -> bytes:
    """Encrypt plain text with device token."""
    key, iv = key_iv(token)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def AES_cbc_decrypt(token: bytes, ciphertext: bytes) -> bytes:
    """Decrypt cipher text with device token."""
    key, iv = key_iv(token)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(bytes(ciphertext)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(padded_plaintext)
    unpadded_plaintext += unpadder.finalize()
    return unpadded_plaintext


def encrypt(stamp: int, token: bytes, devid: int, plaindata: bytes) -> bytes:
    """Generate an encrypted packet from plain data.

    Args:
        stamp: incrementing counter
        token: 128 bit device token
        plaindata: plain data
    """

    def init_msg_head(stamp: int, token: bytes, devid: int, packet_len: int) -> bytes:
        head = pack(
            "!BBHIII16s",
            0x21,
            0x31,  # const magic value
            packet_len,
            0,  # unknown const
            devid,  # unknown const
            # 0x02AF3988,  # unknown const
            stamp,
            token,  # overwritten by the MD5 checksum later
        )
        return head

    payload = AES_cbc_encrypt(token, plaindata)
    packet_len = len(payload) + 32
    packet = bytearray(init_msg_head(stamp, token, devid, packet_len) + payload)
    checksum = md5(packet)
    for i in range(0, 16):
        packet[i + 16] = checksum[i]
    return packet


def decrypt(token: bytes, cipherpacket: bytes) -> bytes:
    """Decrypt a packet.

    Args:
        token: 128 bit device token
        cipherpacket: packet data
    """
    ciphertext = cipherpacket[32:]
    plaindata = AES_cbc_decrypt(token, ciphertext)
    return plaindata


def print_head(raw_packet: bytes):
    """Print the header fields of a MiHome packet."""
    head = raw_packet[:32]
    magic, packet_len, unknown1, unknown2, stamp, md5 = unpack("!2sHIII16s", head)
    logging.debug("  magic:        %8s" % magic.hex())
    logging.debug("  packet_len:   %8x" % packet_len)
    logging.debug("  unknown1:     %8x" % unknown1)
    logging.debug("  devid:     %8x" % unknown2)
    logging.debug("  stamp:        %8x" % stamp)
    logging.debug("  md5 checksum: %s" % md5.hex())


class MiioPacket:
    def __init__(self):
        self.magic = (0x21, 0x31)
        self.length = None
        self.unknown1 = 0
        self.devid = 0x02AF3988
        self.stamp = 0
        self.data = None
        self.md5 = None

    def read(self, raw: bytes):
        """Parse the payload of a UDP packet."""
        head = raw[:32]
        self.magic, self.length, self.unknown1, self.devid, self.stamp, self.md5 = unpack(
            "!2sHIII16s", head
        )
        self.data = raw[32:]

    def generate(self, token: bytes) -> bytes:
        """Generate an encrypted packet."""
        return encrypt(self.stamp, token, self.devid, self.data)


class Yeelight(object):

    name = "yeelight"

    def __init__(self, mac):
        """
        The go_on attribute must exist. It is set to False when provisioning is done

        :param mac: MAC address of the device being provisioned
        :type mac: str

        """
        self.go_on = True
        self.mac = mac
        self.queue = asyncio.Queue()
        self.owner = "Karl_Marx@international.org"
        self.state = ["initial", "communicating", "closing"]

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
            if x.lower().strip().startswith("yeelink"):
                resu[x] = {"passwd": "", "ip": "", "ipv6": ""}

        return resu

    async def secure(self, user, passwd):
        """ Nothing here """
        await asyncio.sleep(0)

    async def set_options(self, options={}):
        """Just one thing """
        logging.debug("options --> {}".format(options))
        if "owner" in options:
            self.owner = options["owner"]
        await asyncio.sleep(0)

    async def provision(self, ip, ssid, psk, ktype="none"):
        """Coroutine to perform provisioning

           As long as this method returns AGAIN, this coroutine must be called after switching
           wireless network if necessary. Each AGAIN shoud toggle between the device being provisioned
           cell and the original cell (nothig is done if the interface was not being used.

           If information is returned its handling should be application specific.

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

        class MiioProtocol(asyncio.DatagramProtocol):
            def __init__(self, queue):
                super().__init__()
                self.queue = queue
                self.decrypt = False
                self.token = None
                self.addr = None
                self.devid = None
                self.stamp = None

            def connection_made(self, transport):
                logging.debug("Connected to Yeelight")
                self.transport = transport

            def datagram_received(self, data, addr):
                mydata = MiioPacket()
                mydata.read(data)
                print_head(data)
                if not self.decrypt:
                    logging.debug(f"When in init got {data}")
                    if data[:4] == b"\x21\x31\x00\x20":
                        self.addr = addr[0]
                        self.devid = mydata.devid
                        self.token = mydata.md5
                        self.stamp = mydata.stamp
                        self.decrypt = True
                        plaindata = f"Token = {self.token}"
                        logging.debug(f"devid {self.devid}")
                        logging.debug(f"Token {self.token}")
                        self.queue.put_nowait(
                            ("ok", {"token": self.token, "devid": self.devid})
                        )
                    else:
                        logging.debug("Not what we expected. So long")
                        self.queue.put_nowait(("error", "unexpected initial packet"))
                else:
                    plaindata = json.loads(decrypt(self.token, data))
                    logging.debug(f"From {addr} got {plaindata}")
                    if "result" in plaindata:
                        self.queue.put_nowait(("ok", plaindata["result"]))
                    else:
                        self.queue.put_nowait(("error", plaindata["error"]))

        try:
            targetip = ".".join(ip.split(".")[:-1]) + ".1"
            try:
                loop = asyncio.get_running_loop()
            except:
                loop = asyncio.get_event_loop()
            transp, proto = await loop.create_datagram_endpoint(
                lambda: MiioProtocol(self.queue), remote_addr=(targetip, 54321)
            )
            while True:
                if proto.token is None:
                    # Send hello packet
                    logging.debug("Sending Hello")
                    payload = b"\x21\x31\x00\x20" + b"\xff" * 28
                    transp.sendto(payload)
                else:
                    logging.debug("Provision Now with token")
                    payload = {"method": "miIO.config_router"}
                    payload["id"] = int(time())
                    payload["params"] = {"ssid": ssid, "passwd": psk, "uid": self.owner}
                    packet = MiioPacket()
                    packet.stamp = proto.stamp
                    packet.data = json.dumps(payload).encode()
                    packet.devid = proto.devid
                    realpayload = packet.generate(proto.token)
                    logging.debug(f"Sending {packet.data} for {packet.devid}")
                    logging.debug(["0x%02x" % x for x in realpayload])
                    transp.sendto(realpayload)
                try:
                    resu, msg = await asyncio.wait_for(self.queue.get(), timeout=2.0)
                    self.queue.task_done()
                except asyncio.TimeoutError:
                    resu = "error"
                    msg = "timeout error. Bailing out"
                if resu == "ok":
                    self.state = self.state[1:]
                else:
                    logging.debug(f"Got from queue: {msg}")
                    raise Exception(msg)
                if self.state[0] == "closing":
                    break
            retval = {
                self.mac: {
                    "type": "yeelight",
                    "token": b64encode(proto.token).decode(),
                    "device id": proto.devid,
                }
            }
            transp.close()
            self.go_on = False
            logging.debug(f"Got {retval} --> {proto.token}")
            return retval
        except Exception as e:
            logging.warning(f"Problem whilst provisioning Yeelight. Error was: {e}")
            transp.close()
            self.go_on = False
            return {}

    @classmethod
    def persist(self, values):
        """
        We have key to save
        """
        database = os.path.abspath(os.path.expanduser("~/.aioyeelight"))
        try:
            with open(database, "r") as tokendata:
                tokenlist = json.load(tokendata)
        except:
            tokenlist = {}
        dosave = False
        for mac in values:
            if "type" in values[mac] and values[mac]["type"] == "yeelight":
                tokenlist[mac] = values[mac]["token"]
                dosave = True
        if dosave:
            with open(database, "w") as tokendata:
                json.dump(tokenlist, tokendata)


PluginObject = Yeelight
