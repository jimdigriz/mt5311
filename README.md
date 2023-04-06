Utilities for working with Metanoia/Proscend VDSL2 SFP Modems.

## Related Links

 * VDSL2 SFP Modem:
    * [Metanoia MT-V5311](https://web.archive.org/web/20220524112417/https://metanoia-comm.com/products/xdsl/vdsl2-sfp/) - seems to be the OEM
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
    * [Dumping the EEPROM](https://github.com/TheSkorm/Proscend--180-T/wiki)

# Utilities

## SNMP

**N.B.** WORK IN PROGRESS, NOT COMPLETE, NOT USABLE

An extension to [Net-SNMP](http://www.net-snmp.org/) in the form of a [MIB-Specific Extension using `pass_persist`](http://www.net-snmp.org/docs/man/snmpd.conf.html#lbBB).

Where possible the following MIBs are supported:

 * [RFC 5650](https://datatracker.ietf.org/doc/html/rfc5650) - Definitions of Managed Objects for Very High Speed Digital Subscriber Line 2 (VDSL2)
    * [RFC 3728](https://datatracker.ietf.org/doc/html/rfc3728) - Definitions of Managed Objects for Very High Speed Digital Subscriber Lines (VDSL)
    * [RFC 4070](https://datatracker.ietf.org/doc/html/rfc4070) - Definitions of Managed Object Extensions for Very High Speed Digital Subscriber Lines (VDSL) Using Multiple Carrier Modulation (MCM) Line Coding
    * [RFC 4706](https://datatracker.ietf.org/doc/html/rfc4706) - Definitions of Managed Objects for Asymmetric Digital Subscriber Line 2 (ADSL2)
        * [RFC 2662](https://www.rfc-editor.org/rfc/rfc2662) - Definitions of Managed Objects for the ADSL Lines
 * [RFC 2863](https://datatracker.ietf.org/doc/html/rfc2863) - The Interfaces Group MIB

To set up your OS, run:

 * **Debian (and probably Ubuntu):**

       sudo apt install --no-install-recommends lua5.1 snmpd sudo

   Now depending on:

    * If your distro provides [`lua-posix` 35.1 or later (for `AF_PACKET` support)](https://github.com/luaposix/luaposix/releases/tag/v35.1), then run:

          sudo apt install --no-install-recommends lua-posix

    * Otherwise, run:

          sudo apt install --no-install-recommends build-essential liblua5.1-dev luarocks
          sudo luarocks install luaposix

 * **OpenWRT:**

       opkg install lua lua-posix snmpd

   **N.B.** consider yourselves lucky, I normally would have written this all in Perl, but as this is likely to be useful to the OpenWRT community I have purposely targeted easy to meet and low disk space usage dependencies (including supporting Lua 5.1)

Now run:

    git clone https://github.com/jimdigriz/mt5311.git /opt/mt5311
    luarocks install lua-struct		# (*with* hyphen)

If you are constrained on disk space, you may prefer to use:

    mkdir -p /opt/mt5311
    cd /opt/mt5311
    wget https://raw.githubusercontent.com/jimdigriz/mt5311/main/snmp-agentx.lua
    wget https://raw.githubusercontent.com/jimdigriz/mt5311/main/agentx.lua
    wget https://raw.githubusercontent.com/jimdigriz/mt5311/main/ebm.lua
    # alternatively use 'luarocks install lua-struct' (*with* hyphen)
    wget https://raw.githubusercontent.com/iryont/lua-struct/master/src/struct.lua

Check the tool is working by running as `root`:

    lua /opt/mt5311/snmp.lua IFACE MACADDR -g .1.3.6.1.4.1.59084.6969.1

Where:

 * **`IFACE`:** name of the host network interface (for example `eth1`) the VDSL2 SFP is connected to
    * this must be the untagged (native/non-VLANed) interface to the SFP
 * **`MACADDR`:** MAC address of the VDSL2 SFP
    * case insensitive and accepts the formats `001122334455`, `00:11:22:33:44:55` and `00-11-22-33-44-55`

It should output almost immediately:

    ...

**N.B.** `snmp.lua` also supports the non-persist plain `pass` mode of operation which exists in this tool as it is useful for debugging, look to the SNMP manpage for more information on how to use it

Now configure `snmpd` to use the Lua script by doing the following (remember to replace `IFACE` and `MACADDR`):

 * **Debian/ (and probably Ubuntu):**

    1. create the file `/etc/sudoers.d/snmpd` and add the following line:

           Cmnd_Alias MT5311SNMP = /usr/bin/lua /opt/mt5311/snmp.lua [a-zA-Z0-9][a-zA-Z0-9.]* [0-9a-fA-F][0-9a-fA-F\:-]*
           Defaults!MT5311SNMP !requiretty, !lecture
           Debian-snmp ALL = (root) NOPASSWD:NOEXEC: MT5311SNMP

    1. edit `/etc/snmp/snmpd.conf` and add the following line:

           view systemonly included .1.3.6.1.4.1.59084.6969
           pass_persist .1.3.6.1.4.1.59084.6969 /usr/bin/sudo /usr/bin/lua /opt/mt5311/snmp.lua IFACE MACADDR

 * **OpenWRT:**

    1. edit `/etc/snmp/snmpd.conf` and add the following line:

           pass_persist .1.3.6.1.4.1.59084.6969 /usr/bin/env lua /opt/mt5311/snmp.lua IFACE MACADDR

## Wireshark

To use a basic Ethernet Boot & Management (EBM) protocol dissector:

    sudo tcpdump -n -i eth0 'ether proto 0x6120' -w - -U | tee dump.pcap | tcpdump -r - -n -v
    wireshark -X lua_script:dissector.lua dump.pcap

**N.B.** [`dissector.lua`](./dissector.lua) contains my notes on the protocol

### Sample Data

[`dump-soc.txt.gz`](./dump-soc.txt.gz) is the output of the "Dump SOC" button whilst [`dump-soc.pcap.gz`](./dump-soc.pcap.gz) is a packet capture during running it; [`register.map`](./register.map) is a listing of the register addresses and their purpose manually derived from these two files.

**N.B** packet capture includes connecting to the SFP and having 'Port Status' section open and running for a while

It looks like the "Dump SOC" starts at (roughly) frame number 409 with the value of `xdslTwConfig` being in frame 426.

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
