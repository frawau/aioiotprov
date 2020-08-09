# aioiotprov

A library/utility to provision IoT devices

[![PyPI version fury.io](https://badge.fury.io/py/aioiotprov.svg)](https://pypi.python.org/pypi/aioiotprov)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-licen)
[![GITHUB-BADGE](https://github.com/frawau/aioiotprov/workflows/black/badge.svg)](https://github.com/psf/black)

This is early day.  Currently it can provision TP-Link smartplugs, Broadlink IR blasters,  Sonoff switches running
the Tasmota firmware, Shelly devices and E-Trix power monitors

This uses nmcli or wpa_cli to control and configure WIFI access. This means this will work only with
Linux, and then again not all. It is working on a RaspberryPi running Debian Stretch (No NetworkManager) and works on a laptop ruunning Ubuntu 18.10

When using nmcli, it is possible to use a connected WiFi adapter, this has not yet been tested with wpa_cli


# Installation

We are on PyPi so

    pip3 install aioiotprov


# Running

You can just run it by doing

    python3 -m aioiotprov "My SSID" "My Secret Key"

If you want to set user, password and for sonoff, MQTT, do something like

    python3 -m aioiotprov -u user -p password "My SSID" "My Secret Key" \
    -o "sonoff::mqtt==on||user=mqttuser||password=mqttpass||host=somehost||port=1883||client=DVES_XXXXXX||topic=sonoff-XXXXXX||full topic=blabla/%prefix%/%topic%/"

For Shellies,

    python3 -m aioiotprov -u user -p password "My SSID" "My Secret Key" \
    -o "shelly::mqtt==on||user==mqttuser||password==mqttpass||host==somehost||port==1883"

For Tasmota,

    python3 -m aioiotprov -d -u user -p passwd -o 'tasmota::mqtt==on||template=={"NAME":"Sonoff T1 3CH","GPIO":[17,255,255,255,23,22,18,19,21,56,0,0,0],"FLAG":0,"BASE":30}||host==somehost||user==mqttuser||password==mqttpasswd'
    -- SSID KEY


Setting option will only works with plugins that can handle those. Use '::' after name of the plugin. Use '==' to set value
and use '||' to separate options

## Plugins

### broadlink

This is a plugin to provision [Broadlink](http://www.ibroadlink.com/) devices, like the A1 sensor or the RM4 Mini IR blaster.

The device cannot be secured (no user/password setting) nor is any option available for this plugin.

### e-trix

This is a plugin to provision [E-Trix](https://creativepowerthai.com/intro/) electrix metering devices.

The device cannot be secured (no user/password setting) nor is any option available for this plugin.

### shelly

This is a plugin to provision [Shelly](https://shelly.cloud/) devices.

If you set the user and the password, the device will be secured with those.

The plugin supports the following options:

    mqtt:    on or off Use MQTT or not
        host: mqtt host URI (with port if needed) (only if mqtt=='on'
        user: mqtt username
        password: mqtt password


### tasmota

This is a plugin to provision devices running the [Tasmota](https://tasmota.github.io/docs/) software.

If you set the user and the password, the device will be secured with those.

The plugin supports the following options:

    module:  The index of the module to use (e.g. 29 is for Sonoff T1 2CH)
    template: A device template. See the Tasmota documentation for details.
    mqtt:    on or off Use MQTT or not
        host: mqtt host (only if mqtt=='on'
        user: mqtt username
        password: mqtt password
        port: mqtt port
        client: see tasmota documentation for details
        topic: define the device unique id for MQTT
        full topic: : full topic e.g. mystuff/%prefix%/%topic%

    For 'client', 'topic' and 'full topic'  the string '{mac}' in the value will be replaced by
    the last 6 hexadigits of the MAC address in lowercase format.

### tp-link

This is a plugin to provision [TP-Link](https://www.kasasmart.com/us/products/smart-plugs) smart plugs devices. It may work with other smart home devices, but this has not been tested.
The device cannot be secured (no user/password setting) nor is any option available for this plugin.

# How it works

Mostly each plugin knows what SSID to look for. If one of the needed SSID is found, aioiotprov will connect
to the SSID and hand over provisioning duties to the plugin.
