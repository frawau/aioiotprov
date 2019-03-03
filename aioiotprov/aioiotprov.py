#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This is a library to connect to the AP provided by IoT devices and
# provision them.
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
BUGGYMODULE = ["8192cu"]


import asyncio as aio
import re, sys, os, importlib, logging
from collections import defaultdict

ifaceregexp = re.compile(r"^[0-9]+: (?P<iface>[a-zA-Z0-9]+): .*$")

ipregexps = [
    re.compile(r"^link/ether (?P<mac>[0-9a-fA-F:]+) brd .*$"),
    re.compile(r"^inet (?P<ip>[0-9.]+)/[0-9]+ .*$"),
    re.compile(r"^inet6 (?P<ipv6>[0-9:a-fA-F]+)/[0-9]+ .*$")
]


def parse_ifaces(content):
    """Parsing the output of command "ip addr".

       This returns a dictionary of dictionaries.
        At the first level, the key is the interface name
            At the second level the values are lists and the keys are
                mac : List of mac addresses (usually 1)
                ip  : List if IPv4 addresses
                ipv6: List of IPv6 adresses

        :param content: A string to be parsed
        :type cmd: str
        :returns: Parsed content as a dictionary..
        :rtype: dict
    """
    loiface = {}
    addrs = defaultdict(list)
    iface = None
    lines = content.split('\n')
    for line in lines:
        if not line:
            continue
        niface = ifaceregexp.search(line)
        if niface:
            if iface and addrs:
                loiface[iface]=addrs
            addrs = defaultdict(list)
            iface = niface.groupdict()["iface"]
            continue
        line = line.strip()
        for expression in ipregexps:
            result = expression.search(line)
            if result is not None:
                for x,y in result.groupdict().items():
                    addrs[x].append(y)
                continue
    if iface and addrs:
        loiface[iface]=addrs
    logging.debug("--> {}".format(loiface))
    return loiface


class WiFiManager(object):

    def __init__(self):
        pass

class WPAWiFiManager(WiFiManager):

    def parse_cells(self, content):
        """This function parses the output of the command "/sbin/wpa_cli  scan_result"

        This function returns the parsed content as a list of dictionary.
        Each dictionary describes one scanned cell: ESSID,
        Encryption, BSSID


            :param content: A string to be parsed
            :type cmd: str
            :returns: Parsed content as a list..
            :rtype: list
        """
        foundheader = False
        lines = content.split('\n')
        locells = []
        for line in lines:
            if not line:
                continue
            thisline = [x for x in line.split("\t") if x.strip()]
            if "bssid" in line.lower() and  "ssid" in line.lower():
                foundheader = True
                continue
            if foundheader:
                try:
                    acell={}
                    acell["bssid"]=thisline[0]
                    if "[" in thisline[3]:
                        if "WPA2" in thisline[3]:
                            acell["encryption"]="wpa2"
                        elif "WPA" in thisline[3]:
                            acell["encryption"]="wpa"
                        elif "WEP" in thisline[3]:
                            acell["encryption"]="wep"
                        else:
                            acell["encryption"]="none"
                        acell["ssid"]=thisline[4]
                    else:
                        acell["encryption"]="none"
                        acell["ssid"]=thisline[3]

                    locells.append(acell)
                except:
                    #In all likelyhood, a hidden SSID, ignore those
                    pass

        logging.debug ("--> {}".format(locells))
        return locells

    async def gather_cellinfo(self, interfaces):

        cells = {}
        for iface in interfaces:
            iswifi = await run_cmd(["sudo", "/sbin/wpa_cli","-i",iface,"scan"])
            if iswifi and iswifi.strip().lower() == "ok":
                await aio.sleep(4)
                cells[iface] = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface, "scan_result"], self.parse_cells)
        return cells

    async def wifi_connect(self, iface, ssid, psk=None,is_wep=False):
        """Connect to the given wifi network.

            :param ssid: Name of the cell to connect to
            :type ssid: str
            :param psk: Key to use
            :type psk: str
            :returns: id of the network
            :rtype: int

        """
        netid= int(await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface, "add_network"]))
        if psk and not is_wep:
            wpacmd = ["set_network %d ssid \"%s\""%(netid,ssid),
                    "set_network %d psk \"%s\""%(netid,psk),
                    "enable_network %d"%netid,
                    3,
                    "quit"]
        elif psk and is_wep:
            wpacmd = ["set_network %d ssid \"%s\""%(netid,ssid),
                    "set_network %d key_mgmt NONE"%(netid),
                    "set_network %d wep_key0 %s"%(netid,psk),
                    "set_network %d auth_alg SHARED"%(netid),
                    "enable_network %d"%netid,
                    3,
                    "quit"]
        else:
            wpacmd = ["set_network %d ssid \"%s\""%(netid,ssid),
                    "set_network %d key_mgmt NONE"%(netid),
                    "enable_network %d"%netid,
                    3,
                    "quit"]

        resul = await run_inter_cmd(["/sbin/wpa_cli", "-i", iface],wpacmd)
        logging.debug("{}".format(resul))
        return netid

    async def wifi_disconnect(self, iface, netid):
        """Connect to the given wifi network.

            :param netid: Network id, Got when connecting
            :type netid: int
            :returns: None
            :rtype: None

        """
        logging.debug("Disconnecting {}".format(iface))
        xx = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface,"bss_flush"])
        xx = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface,"disable_network", str(netid)])
        xx = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface,"remove_network", str(netid)])
        xx = await run_cmd(["sudo", "/sbin/ip", "link","set","down","dev", iface])
        xx = await run_cmd(["sudo", "/sbin/ip", "link","set","up","dev", iface])
        #Work around bug with 8192cu
        for module in BUGGYMODULE:
            driver = await run_cmd(["sudo", "/bin/readlink", "/sys/class/net/%s/device/driver"%iface])
            driver = driver.strip()
            logging.debug("Driver is {} it does{}end by {}".format(driver,driver.endswith(module) and " " or " not ",module))
            if driver.endswith(module):
                logging.debug("Work around for {}".format(module))
                xx = await run_cmd(["sudo", "/sbin/rmmod", module])
                xx = await aio.sleep(2)
                xx = await run_cmd(["sudo", "/sbin/modprobe", module])
                xx = await aio.sleep(1)

    async def wifi_reset(self, iface, ssid, psk):
        """Connect to the given wifi network.

            :returns: None
            :rtype: None

        """
        xx = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface,"bss_flush"])
        xx = await run_cmd(["sudo", "/sbin/wpa_cli", "-i", iface,"reconfigure"])


class NMWiFiManager(WiFiManager):

    def parse_cells(self, content):
        """This function parses the output of the command "nmcli -t -f ssid,security,bssid -c no device wifi list"

        This function returns the parsed content as a list of dictionary.
        Each dictionary describes one scanned cell: ESSID,
        Encryption, BSSID


            :param content: A string to be parsed
            :type cmd: str
            :returns: Parsed content as a list..
            :rtype: list
        """
        locells = []
        lines = content.split('\n')
        for line in lines:
            if not line:
                continue
            thisline = [x for x in line.split(":")]
            if len(thisline) == 0 or thisline[0] in ["--",""]:
                continue
            try:
                acell={}
                acell["ssid"]=thisline[0]
                acell["bssid"]=":".join(thisline[2:]).replace("\\","").lower()
                if len(thisline) > 1:
                    if "WPA2" in thisline[1]:
                        acell["encryption"]="wpa2"
                    elif "WPA" in thisline[1]:
                        acell["encryption"]="wpa"
                    elif "WEP" in thisline[1]:
                        acell["encryption"]="wep"
                    else:
                        acell["encryption"]="none"
                else:
                    acell["encryption"]="none"

                locells.append(acell)
            except:
                #In all likelyhood, a hidden SSID, ignore those
                pass

        logging.debug ("--> {}".format(locells))
        return locells

    async def gather_cellinfo(self, interfaces):
        wifaces = []
        iswifi = await run_cmd(["sudo", "/usr/bin/nmcli", "-t", "-f", "device,type", "device", "status"])
        lines = iswifi.split('\n')
        for line in lines:
            if not line:
                continue
            thisline = [x for x in line.split(":")]
            if thisline[1] == "wifi":
                wifaces.append(thisline[0].strip())
        cells = {}
        iswifi = await run_cmd(["sudo", "/usr/bin/nmcli", "device", "wifi", "rescan"])
        #TDO check returned values
        await aio.sleep(4)
        allcells = await run_cmd(["sudo", "/usr/bin/nmcli", "-t", "-f", "ssid,security,bssid", "-c", "no", "device", "wifi", "list"], self.parse_cells)
        for iface in wifaces:
            cells[iface]=allcells
        return cells

    async def wifi_connect(self, iface, ssid, psk=None,is_wep=False):
        """Connect to the given wifi network.

            :param ssid: Name of the cell to connect to
            :type ssid: str
            :param psk: Key to use
            :type psk: str
            :returns: id of the network
            :rtype: int

        """
        con = await run_cmd(["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", psk, "ifname", iface])
        return None

    async def wifi_disconnect(self, iface, netid):
        """Connect to the given wifi network.

            :param netid: Network id, Got when connecting
            :type netid: int
            :returns: None
            :rtype: None

        """
        logging.debug("Disconnecting {}".format(iface))
        con = await run_cmd(["sudo", "nmcli", "device", "disconnect", iface])

    async def wifi_reset(self, iface, ssid, psk):
        """Connect to the given wifi network.

            :returns: None
            :rtype: None

        """
        await self.wifi_connect(iface, ssid,psk)

async def run_cmd(cmd,parse=None):
    """This coroutine runs a shell command within the asyncio framework

        :param cmd: A list with the various atoms of the command
        :type cmd: list
        :param parse: function to parse the command output.
        :type mac: func
        :returns: The output of the command possibly parsed.
        :rtype: object

    """
    proc = await aio.create_subprocess_exec(*cmd, stdout=aio.subprocess.PIPE, stderr=aio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if stderr:
        logging.info('Error whilst executing command:\n{}\n'.format(stderr.decode()))
    if stdout:
        if parse:
            return parse(stdout.decode())
        else:
            return stdout.decode()


async def run_inter_cmd(cmd,icmd,parse=None):
    """This coroutine runs an interactive shell command within the asyncio framework

        :param cmd: A list with the various atoms of the command
        :type cmd: list
        :param icmd: A list of strings with the various commands to send down stdin. Integer indicate pauses in secs.
        :type icmd: list
        :param parse: function to parse the command output.
        :type mac: func
        :returns: The output of the command possibly parsed.
        :rtype: object

    """
    proc = await aio.create_subprocess_exec(*cmd, stdin=aio.subprocess.PIPE, stdout=aio.subprocess.PIPE, stderr=aio.subprocess.PIPE)
    for scmd in icmd:
        if isinstance(scmd,int):
            await aio.sleep(scmd)
        else:
            proc.stdin.write(scmd.encode()+b"\n")
            await proc.stdin.drain()
    stdout, stderr = await proc.communicate()
    if stderr:
        logging.info('Error whilst executing command:\n{}\n'.format(stderr.decode()))
    if stdout:
        if parse:
            return parse(stdout.decode())
        else:
            return stdout.decode()


async def check_system(neededcmd=["ip","wpa_supplicant","/sbin/wpa_cli"]):
    """Coroutine to check that a number of shell commands can be used.

        :param neededcmd: A list of the command to be checked
        :type neededcmd: list
        :returns: True or False, and a possible error message
        :rtype: 2-uple
    """
    for cmd in neededcmd:
        cpath = await run_cmd(["sudo", "which", cmd])
        if not cpath:
            logging.error("Error: Command {} is not available.".format(cmd))
            return False, "Error: Command {} is not available.".format(cmd)
    return True,""


def load_plugins(needed=None):
    """Load plugins

        :param needed: Name of the plugins to load.
        :type iface: list
        :returns: dictionary of plugin objects, key is the name
        :rtype: dict

    """
    dir_path = os.path.join(os.path.dirname(__file__),'plugins')
    # import parent module / namespace
    sys.path.append(os.path.dirname(__file__))
    importlib.import_module('plugins')
    loplugins = {}
    for filename in os.listdir(dir_path):
        name, ext = os.path.splitext(filename)
        if needed is None or name in needed:
            if ext.endswith(".py"):
                try:
                    mod = importlib.import_module("."+name, package="plugins")
                    logging.debug("Loading plugin "+mod.PluginObject.name)
                    loplugins[mod.PluginObject.name]=mod.PluginObject
                except:
                    logging.error("Plugin {} could not be loaded.".format(name))

    return loplugins



class IoTProvision(object):

    def __init__(self,ssid, psk="", manager=NMWiFiManager()):
        """Create a IoTProvision object

        :param ssid: The SSID to connect the device to
        :type ssid: str
        :param psk: The shared secret to connect to SSID
        :type psk: str
        :returns: IoTProvision object.
        :rtype: IoTProvision
        """
        self.ssid = ssid
        self.ssid_encrypt = None
        self.psk = psk
        self.user = ""
        self.passw = ""
        self.cells = {}
        self.iface=None
        self.is_shared = False
        self.interfaces = {}
        self.wifimanager = manager

    def set_secure(self, user, passw):
        """Set the username and password to secure the device with.

        Individual plugins decide whether or not to use this

        :param user: The user
        :type user: str
        :param passw: The password
        :type passw: str
        :returns: Nothong.
        :rtype: None
        """
        self.user = user
        self.passw = passw

    async def gather_netinfo(self, iface=None,cells_too=True):
        """Coroutine to retrieve all relevant information about network interfaces and wifi cells available

            :param iface: Limit to the given interface
            :type iface: str
            :param cell_too: Whether or not to look for Wifi cells
            :type cell_too: bool
            :returns: The parsed output of "ip addr"
            :rtype: dict

        """
        if iface:
            self.interfaces = await run_cmd(["sudo", "/sbin/ip", "addr", "show", "dev", iface], parse_ifaces)
        else:
            self.interfaces = await run_cmd(["sudo", "/sbin/ip", "addr"], parse_ifaces)

        if cells_too:
            self.cells = await self.wifimanager.gather_cellinfo(self.interfaces)
        return self.interfaces



    def select_iface(self,interfaces,cells):
        """Select a wirelless interface.

        This will try to find a wireless interface that is not configured. Failing
        that it will simply pick the first one.

            :param interfaces: A dictionary describing the interfaces
            :type interfaces: dict
            :param cells: A dictionary describing the wifi cells
            :type cells: dict
            :returns: An interface and whether or not this interface was configured
            :rtype: 2-uple

        """
        self.iface = None
        self.is_shared = False

        for iface in cells:
            if "ip" in interfaces[iface] or "ip6" in interfaces[iface]:
                continue
            #OK, This interface does not have an IP address
            self.iface = iface
            break

        if not self.iface:
            self.iface = [x for x in cells.keys()][0]
            #We will need to restore things at the end
            self.is_shared = True

        return self.iface != None




    async def wifi_connect(self, ssid, psk=None,is_wep=False):
        """Connect to the given wifi network.

            :param ssid: Name of the cell to connect to
            :type ssid: str
            :param psk: Key to use
            :type psk: str
            :returns: id of the network
            :rtype: int

        """
        return await self.wifimanager.wifi_connect(self.iface, ssid, psk, is_wep)

    async def wifi_disconnect(self, netid):
        """Connect to the given wifi network.

            :param netid: Network id, Got when connecting
            :type netid: int
            :returns: None
            :rtype: None

        """
        await self.wifimanager.wifi_disconnect(self.iface,netid)

    async def wifi_reset(self):
        """Connect to the given wifi network.

            :returns: None
            :rtype: None

        """
        await self.wifimanager.wifi_reset(self.iface, self.ssid, self.psk)


    async def provision(self,plugins=None,options={}):
        """Connect to the given wifi network.

            :param plugins: List of plugins to load. None means all.
            :type plugins: str
            :returns: List of returned info from the provisioning phase
            :rtype: list

        """
        result={}
        loplugins = load_plugins(plugins)
        if self.ssid_encrypt == None:
            for cdef in self.cells[self.iface]:
                if cdef["ssid"] ==self.ssid:
                    self.ssid_encrypt = cdef["encryption"]
                    break
        if self.ssid_encrypt == None:
            self.ssid_encrypt="none"
        for aplug in loplugins.values():
            cando = aplug.can_handle([x["ssid"] for x in self.cells[self.iface]])
            #
            #logging.debug("==> {}".format(self.cells))
            for acell in cando:
                for cdef in self.cells[self.iface]:
                    if cdef["ssid"] == acell:
                        cencrypt = cdef["encryption"]
                        mac = cdef["bssid"]
                        break
                currcnt=1
                myplug = aplug(mac)
                while myplug.go_on:
                    if currcnt == 1 or (currcnt%2 and self.is_shared):
                        #Only connects if really needed
                        netid = await self.wifi_connect(acell,cando[acell]["passwd"],cencrypt=="wep")
                    xx = await aio.sleep(5)
                    if cando[acell]["ip"] or cando[acell]["ipv6"]:
                        if cando[acell]["ip"]:
                            xx= await run_cmd(["sudo", "/sbin/ip","addr","add",cando[acell]["ip"],"dev",self.iface])
                        if cando[acell]["ipv6"]:
                            xx= await run_cmd(["sudo", "/sbin/ip", "-6", "addr","add",cando[acell]["ip"],"dev",self.iface])
                        ifaceinfo = await self.gather_netinfo(self.iface,False)
                    else:
                        cnt = 5
                        while cnt:
                            cnt-=1
                            ifaceinfo = await self.gather_netinfo(self.iface,False)
                            logging.debug(ifaceinfo)
                            if "ip" in ifaceinfo[self.iface]:
                                break
                            xx = await aio.sleep(1)

                        if "ip" not in ifaceinfo[self.iface]:
                            logging.error("Warning: Did not get an IP address from {}. Bailing out.".format(acell))
                            xx = await self.wifi_disconnect(netid)
                            break

                    xx = await myplug.secure(self.user,self.passw)
                    if myplug.name in options:
                        xx = await myplug.set_options(options[myplug.name])
                    presu = await myplug.provision(ifaceinfo[self.iface]["ip"][0],self.ssid,self.psk,self.ssid_encrypt)
                    if not myplug.go_on or not self.is_shared:
                        xx = await self.wifi_disconnect(netid)
                    if not myplug.go_on:
                        result.update(presu)
                    currcnt +=1
        if self.is_shared:
            await self.wifi_reset()
        return result
