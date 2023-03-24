Utilities for working with Metanoia/Proscend VDSL2 SFP Modems.

## Related Links

 * VDSL2 SFP Modem:
    * [Metanoia MT-V5311](https://metanoia-comm.com/products/xdsl/vdsl2-sfp/) - seems to be the OEM
    * [Proscend 180-T](https://www.proscend.com/en/product/VDSL2-SFP-Modem-Telco/180-T.html)
    * [ALLNET ALL4781-VDSL2-SFP](https://www.allnet.de/en/allnet-brand/produkte/modems-router/sfp-vdsl2-bridge-modem)
 * Useful non-official public materials regarding the modem:
    * [Proscend SOS/ROC Firmware Update](https://youtu.be/fdCl3nxgEyA)
    * Duxtel:
       * [PS180-T - recommended applications and limitations](https://shop.duxtel.com.au/help/en-gb/11-product-advisory/38-ps180-t-recommended-applications-and-limitations)
       * [Notice regarding upcoming SOS/ROC problems](https://www.facebook.com/duxtel/posts/if-you-use-proscend-ps180-t-vdsl-modem-on-nbn-services-you-may-already-be-aware-/1907876142708182/)
    * Forums:
       * [User experience - ALLNET ALL4781-VDSL2-SFP / Switch Modul (Mini-GBIC), VDSL2](https://forum.turris.cz/t/user-experience-allnet-all4781-vdsl2-sfp-switch-modul-mini-gbic-vdsl2/)
       * [Proscend 180-t vdsl2 SFP Support](https://forum.netgate.com/topic/165393/proscend-180-t-vdsl2-sfp-support/)

# Utilities

## Wireshark

To use a basic Ethernet Boot & Management (EBM) protocol dissector:

    sudo tcpdump -n -i eth0 'ether proto 0x6120' -w - -U | tee dump.pcap | tcpdump -r - -n -v
    wireshark -X lua_script:dissector.lua dump.pcap

**N.B.** [`dissector.lua`](./dissector.lua) contains my notes on the protocol

### Sample Data

[`dump-soc.txt.gz`](./dump-soc.txt.gz) is the output of the "Dump SOC" button whilst [`dump-soc.pcap.gz`](./dump-soc.pcap.gz) is a packet capture during running it.

**N.B** packet capture includes connecting to the SFP and having 'Port Status' section open and running for a while

It looks like the "Dump SOC" starts at (roughly) frame number 409 with the value of `xdslTwConfig` being in frame 426.

## SNMP

**N.B.** WORK IN PROGRESS, NOT COMPLETE, NOT USABLE

An extension to [Net-SNMP](http://www.net-snmp.org/) in the form of a [MIB-Specific Extension using `pass_persist`](http://www.net-snmp.org/docs/man/snmpd.conf.html#lbBB).

Where possible the following MIBs are supported:

 * [RFC 5650](https://datatracker.ietf.org/doc/html/rfc5650) - Definitions of Managed Objects for Very High Speed Digital Subscriber Line 2 (VDSL2)
 * [RFC 3728](https://datatracker.ietf.org/doc/html/rfc3728) - Definitions of Managed Objects for Very High Speed Digital Subscriber Lines (VDSL)
    * [RFC 4070](https://datatracker.ietf.org/doc/html/rfc4070) - Definitions of Managed Object Extensions for Very High Speed Digital Subscriber Lines (VDSL) Using Multiple Carrier Modulation (MCM) Line Coding
 * [RFC 2662](https://www.rfc-editor.org/rfc/rfc2662) - Definitions of Managed Objects for the ADSL Lines

To set up your OS, run:

 * **Debian (and probably Ubuntu):**

       sudo apt install --no-install-recommends snmpd lua5.1

   If your distro provides [`lua-posix` 35.1 or later (for `AF_PACKET support)](https://github.com/luaposix/luaposix/releases/tag/v35.1) then you may run:

       sudo apt install --no-install-recommends lua-posix

   Otherwise you will need to run:

       sudo apt install --no-install-recommends liblua5.1-dev luarocks
       sudo luarocks install luaposix

 * **OpenWRT:**

       opkg install snmpd lua lua-posix

   **N.B.** consider yourselves lucky, I normally would have written this SNMP extension in Perl, but as this is likely to be useful to the OpenWRT community I have purposely targeted easy to meet and low disk space usage dependencies (including supporting Lua 5.1)

Now run:

    mkdir -p /opt/mt5311
    cd /opt/mt5311
    wget https://raw.githubusercontent.com/jimdigriz/mt5311/main/snmp.lua
    # alternatively use 'luarocks install luastruct'
    wget https://raw.githubusercontent.com/iryont/lua-struct/master/src/struct.lua

Now configure `snmpd` to use the Lua script by doing the following but replacing `IFACE` with the name of the interface the VDSL2 SFP is connected to, and `MACADDR` with the MAC address of the VDSL2 SFP:

 * **Debian/ (and probably Ubuntu):**

    1. create the file `/etc/sudoers.d/snmp` and add the following line:

           Debian-snmp ALL=(ALL) NOPASSWD:/usr/bin/lua /opt/mt5311/snmp.lua

    1. edit `/etc/snmp/snmpd.conf` and add the following line:

           pass_persist .1.3.6.1.4.1.59084.6969 sudo /usr/bin/lua /opt/mt5311/snmp.lua IFACE MACADDR

 * **OpenWRT:**

    1. edit `/etc/snmp/snmpd.conf` and add the following line:

           pass_persist .1.3.6.1.4.1.59084.6969 /usr/bin/env lua /opt/mt5311/snmp.lua IFACE MACADDR

If `snmpd` does not run as `root` (eg. Debian) then you will need to use instead:

    pass_persist .1.3.6.1.4.1.59084.6969 sudo /usr/bin/env lua /opt/mt5311/snmp.lua



## Official

You can see a [video of the official tools in use](https://youtu.be/fdCl3nxgEyA), but below explains how to use the tools.

**N.B.** below worked fine for me on a Windows 10 VM running under QEMU (using the install media `Win10_22H2_English_x64.iso`)

### DSLmonitor

 1. click on 'Connect' (second icon down on the left)
 1. use only 'Port 1'
 1. Local MAC: set to MAC address of your local NIC
     * `ipconfig /all` from the command prompt to obtain this
 1. Device MAC: set to the MAC address printed on your SFP
 1. click on 'OK'
     * if it errors claiming '`DSLAK.dll` not found' I was able to resolve the problem by running DSLmanager first (this may have due to running the installer for WinPCAP)
 1. select the statistics window (third icon down on the left)

### DSLmanager

 1. install [*both* x64 and x86 version of VS C++](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
 1. ...
 1. I used the latest `*_8463` named image
 1. ...
 1. after upgrade, power cycle SFP (unplug, put it back in)
     * `shutdown` and `no shutdown`ing the switch interface may not be enough
