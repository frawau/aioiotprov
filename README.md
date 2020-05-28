# aioiotprov

A library/utility to provision IoT devices

This is early day.  Currently it can provision TP-Link smartplugs, Broadlink IR blasters,  Sonoff switches running
the Tasmota firmware, Shelly devices and E-Trix power monitors

This uses nmcli or wpa_cli to control and configure WIFI access. This means this will work only with
Linux, and then again not all. It is working on a RaspberryPi running Debian Stretch (No NetworkManager) and works on a laptop ruunning Ubuntu 18.10

When using nmcli, it is possible to use a connected WiFi adapter, this has not yet been tested with wpa_cli

I hope to add soon: Lifx, Tuya

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

    Note: Avoid setting "topic" at this time, it changes the SSID name
    
Setting option will only works with plugins that can handle those. Use '::' after name of the plugin. Use '==' to set value
and use '||' to separate options

# How it works

Mostly each plugin knows what SSID to llok for. If one of the needed SSID is found, aioiotprov will connect
to the SSID and hand over provisioning duties to the plugin.
