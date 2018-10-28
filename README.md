# aioiotprov

A library/utility to provision IoT devices

This is early day.  Currently it can provision TP-Link smartplugs, Broadlink IR blasters and Sonoff switches running
the Tasmota firmware.

This uses wla_cli to control and configure WIFI access. This means this will work only with
Linux, and then again not all. It is working on a RaspberryPi running Debian Stretch.

I hope to get it to work when the Wifi adapter is being used, but this has not been tested yet.

I hope to add soon: Lifx, Tuya (This one is tricky)

# Installation

Later

# Running

You can just run it by doing

    python3 -m aioiotprov "My SSID" "My Secret Key"
