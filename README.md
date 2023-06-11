Utilities for working with Metanoia/Proscend VDSL2 SFP Modems.

## Review

I personally am happy with the two 180-T's I purchased; one plugged into a [Mikrotik hAP ac](https://mikrotik.com/product/RB962UiGS-5HacT2HnT) and the other into a [Cisco WS-C3560X-24P](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3560-x-series-switches/data_sheet_c78-584733.html). I received very similar VDSL2 sync speeds to a 'regular' router on both lines (70Mbps and 40Mbps respectively) even on the original firmware supplied.

Unfortunately since obtaining FTTP, BT Openreach will no longer allow me to continue any FTTC service and so it is difficult for me to significantly continue development of this project. I do welcome contributions from others and even bug reports.

## Related Links

 * VDSL2 SFP Modem:
    * [Metanoia MT-V5311](https://web.archive.org/web/20220524112417/https://metanoia-comm.com/products/xdsl/vdsl2-sfp/) - seems to be the OEM
    * [Proscend 180-T](https://www.proscend.com/en/product/VDSL2-SFP-Modem-Telco/180-T.html)
    * [ALLNET ALL4781-VDSL2-SFP](https://www.allnet.de/en/allnet-brand/produkte/modems-router/sfp-vdsl2-bridge-modem)
 * Useful non-official public materials regarding the modem:
    * [Proscend SOS/ROC Firmware Update](https://youtu.be/fdCl3nxgEyA)
    * [RevK®'s ramblings - VDSL SFP and FireBrick](https://www.revk.uk/2018/01/vdsl-sfp-and-firebrick.html)
    * Duxtel:
       * [PS180-T - recommended applications and limitations](https://shop.duxtel.com.au/help/en-gb/11-product-advisory/38-ps180-t-recommended-applications-and-limitations)
       * [Notice regarding upcoming SOS/ROC problems](https://www.facebook.com/duxtel/posts/if-you-use-proscend-ps180-t-vdsl-modem-on-nbn-services-you-may-already-be-aware-/1907876142708182/)
    * Forums:
       * [User experience - ALLNET ALL4781-VDSL2-SFP / Switch Modul (Mini-GBIC), VDSL2](https://forum.turris.cz/t/user-experience-allnet-all4781-vdsl2-sfp-switch-modul-mini-gbic-vdsl2/)
       * [Proscend 180-t vdsl2 SFP Support](https://forum.netgate.com/topic/165393/proscend-180-t-vdsl2-sfp-support/)
    * GitHub Projects
       * [ALLNET ALL4781-VDSL2-SFP inofficial documentation and software repository](https://github.com/renne/all4781)
       * [Dumping the EEPROM](https://github.com/TheSkorm/Proscend--180-T/wiki)

# Utilities

I have used Lua (compatible with version 5.1) in the hope this work may be found to be useful to the OpenWRT community, a group that benefits from software with low disk space usage dependencies.

To set up your OS to run any of the utilities below, run:

 * **Debian (and probably Ubuntu):**

       sudo apt install --no-install-recommends lua5.1 luarocks

   Now depending on:

    * If your distro provides [`lua-posix` 35.1 or later (for `AF_PACKET` support)](https://github.com/luaposix/luaposix/releases/tag/v35.1), then run:

          sudo apt install --no-install-recommends lua-posix

    * Otherwise, run:

          sudo apt install --no-install-recommends build-essential liblua5.1-dev
          sudo luarocks install luaposix

 * **OpenWRT:**

       opkg install lua lua-posix luarocks

Now run:

    luarocks install lua-struct		# (*with* hyphen)

Now fetch the project using:

    git clone https://github.com/jimdigriz/mt5311.git /opt/mt5311

## EBM Read

A one shot utility to query the SFP for information.

To use it, run as `root`:

    # lua /opt/mt5311/ebm-read.lua eth1 00:11:22:33:44:55 xdsl2LineStatusAttainableRateUs xdsl2LineStatusAttainableRateDs xdsl2LineStatusElectricalLength
    reg	hex	int	str
    xdsl2LineStatusAttainableRateUs	001a19	6681	...
    xdsl2LineStatusAttainableRateDs	00af60	44896	..`
    xdsl2LineStatusElectricalLength	0000b8	184	...

The output is in TSV (tab separated variable) format.

You should look at the [`register.map`](./register.map) file for other registers that you can read, but as well as the names you can provide the register address (integer or hexadecimal) directly.

### Scanning

You can use this tool to scan all the register space:

    seq 0x7000 0x7fff | xargs -n1 printf "0x%x\n" | sudo xargs -n 20 lua /opt/mt5311/ebm-read.lua eth1 00:11:22:33:44:55

**N.B.** this may brick your device, I have no idea what all the registers do, so I suggest you stick to ranges covered in [`register.map`](./register.map)

## SNMP

**N.B.** WORK IN PROGRESS AND NOT COMPLETE

An [AgentX subagent](https://datatracker.ietf.org/doc/html/rfc2741) that where possible implements the following MIBs:

 * [RFC 5650](https://datatracker.ietf.org/doc/html/rfc5650) - Definitions of Managed Objects for Very High Speed Digital Subscriber Line 2 (VDSL2)
    * [RFC 3728](https://datatracker.ietf.org/doc/html/rfc3728) - Definitions of Managed Objects for Very High Speed Digital Subscriber Lines (VDSL)
    * [RFC 4070](https://datatracker.ietf.org/doc/html/rfc4070) - Definitions of Managed Object Extensions for Very High Speed Digital Subscriber Lines (VDSL) Using Multiple Carrier Modulation (MCM) Line Coding
    * [RFC 4706](https://datatracker.ietf.org/doc/html/rfc4706) - Definitions of Managed Objects for Asymmetric Digital Subscriber Line 2 (ADSL2)
        * [RFC 2662](https://www.rfc-editor.org/rfc/rfc2662) - Definitions of Managed Objects for the ADSL Lines
 * [RFC 2863](https://datatracker.ietf.org/doc/html/rfc2863) - The Interfaces Group MIB

To set up your OS, in additional to the steps above, run:

 * **Debian (and probably Ubuntu):**

       sudo apt install --no-install-recommends snmpd

   Now edit `/etc/snmp/snmpd.conf` and add the following line:

       # mib-2 interfaces
       view   systemonly  included   .1.3.6.1.2.1.2
       # IF-MIB
       view   systemonly  included   .1.3.6.1.2.1.31
       # VDSL2-LINE-MIB
       view   systemonly  included   .1.3.6.1.2.1.10.251

   Restart `snmpd` with:

       sudo systemctl restart snmpd

 * **OpenWRT:**

       opkg install snmpd

Check the install was correctly done by running the following as `root`:

    lua /opt/mt5311/snmp-agentx.lua IFACE MACADDR

Where:

 * **`IFACE`:** name of the host network interface (for example `eth1`) the VDSL2 SFP is connected to
    * this must be the untagged (native/non-VLANed) interface to the SFP
 * **`MACADDR`:** MAC address of the VDSL2 SFP
    * set to the MAC address printed on your SFP
    * case insensitive and accepts the formats `001122334455`, `00:11:22:33:44:55` and `00-11-22-33-44-55`

If there is no error it means everything is are working, otherwise recheck that you followed the installation instructions so far correctly.

...

TODO include `systemd`/`service` integration

### SNMP Client

Assuming that you have your SNMP client and MIBs correctly set up on your workstation (`apt get install --no-install-recommends snmp snmp-mibs-downloader`), you should be able to see the EBM 'interface' appear using something like the following commands (you may need to adjust your authentication settings):

    snmptable -m ALL -Ci -Cw ${COLUMNS:-80} -v 2c -c public 192.0.2.1 IF-MIB::ifTable
    snmptable -m ALL -Ci -Cw ${COLUMNS:-80} -v 2c -c public 192.0.2.1 IF-MIB::ifXTable
    snmpwalk  -m ALL                        -v 2c -c public 192.0.2.1 VDSL2-LINE-MIB::xdsl2LineTable
    snmptable -m ALL -Ci -Cw ${COLUMNS:-80} -v 2c -c public 192.0.2.1 VDSL2-LINE-MIB::xdsl2LineBandTable
    snmpwalk  -m ALL                        -v 2c -c public 192.0.2.1 VDSL2-LINE-MIB::xdsl2ChannelStatusTable
    snmpwalk  -m ALL                        -v 2c -c public 192.0.2.1 VDSL2-LINE-MIB::xdsl2LineInventoryTable
    snmpwalk  -m ALL                        -v 2c -c public 192.0.2.1 VDSL2-LINE-MIB::xdsl2PMLineCurrTable

**N.B.** you may need to adjust your `/etc/snmp/snmpd.conf` on your router for this to work, in particularly the parameters `agentaddress` and `rocommunity`/`rouser`

**N.B.** [ignore the warnings `Wrong Type (should be BITS): Opaque: 1234`](https://github.com/jimdigriz/mt5311/issues/1)

### LibreNMS

To use this you will need to enable the 'xDSL' module for both 'Discovery' and 'Poller' in the 'Global Settings' menu.

As a recommendation, you should also index your interfaces based on `ifName` which is stable, and not `ifIndex`.

## Wireshark

To use a basic Ethernet Boot & Management (EBM) protocol dissector:

    sudo tcpdump -n -i eth0 'ether proto 0x6120' -w - -U | tee dump.pcap | tcpdump -r - -n -v
    wireshark -X lua_script:dissector.lua dump.pcap

**N.B.** [`dissector.lua`](./dissector.lua) contains my notes on the protocol

If it works, it looks like:

![Screenshot of Wireshark having opened dump-soc.pcap.gz using the EBM dissector](./wireshark.jpeg)

### Sample Data

Included are several PCAPs capturing interactions with the SFP using DSLmonitor:

 * output of using the "Dump SOC" button available in DSLmonitor ([`register.map`](./register.map) is a listing of the register addresses and their purpose manually derived from these samples):
     * version 8570 - supposedly actually implements ROC and SOS support:
         * files:
             * [`dump-soc.v8570.txt.gz`](./samples/dump-soc.v8570.txt.gz)
             * [`dump-soc.v8570.pcap.gz`](./samples/dump-soc.v8570.pcap.gz)
         * packet capture includes connecting to the SFP
     * version 8463 - ignores CO requesting ROC and SOS support:
         * files:
             * [`dump-soc.v8463.txt.gz`](./samples/dump-soc.v8463.txt.gz)
             * [`dump-soc.v8463.pcap.gz`](./samples/dump-soc.v8463.pcap.gz)
         * packet capture includes connecting to the SFP
     * version 8255:
         * files:
             * [`dump-soc.v8255.txt.gz`](./samples/dump-soc.v8255.txt.gz)
             * [`dump-soc.v8255.pcap.gz`](./samples/dump-soc.v8255.pcap.gz)
         * packet capture includes connecting to the SFP and having the 'Port Status' section open and running for a while
         * "Dump SOC" starts at (roughly) frame number 409 with the value of `xdslTwConfig` being in frame 426
  * [capture of the SFP disconnecting us when another client connects](./samples/booted-off.pcap.gz)
  * [clicking the 'Disconnect' button in DSLmonitor whilst the 'Port Status' section open, waiting a while, clicking 'Connect' and then waiting till showtime](./samples/reconnect.pcap.gz)

#### Acronyms

 * **CO:** Central Office (ie. DSLAM/exchange)
     * elsewhere referred to as 'xTU-C' (central) and 'Ot'
 * **CPE:** Customer Premises Equipment (ie. user modem)
     * elsewhere referred to as 'xTU-R' (remote) and 'Rt'
 * **SOS (Save Our Showtime):** rapidly responds to spontaneous changes in copper network conditions which would typically result in a dropout
 * **ROC (Robust Overhead Channel):** complementary feature to SOS which enables CO to maintain connectivity with your modem in the event of spontaneous changes in copper network conditions

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

To flash your SFP you follow the process:

 1. install [*both* x64 and x86 version of VS C++](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
 1. run `WinPcap_4_1_3.exe`
 1. run `DSLmanager.exe`
 1. select the NIC that the SFP is plugged into
 1. set the 'Device MAC' to the MAC address printed on your SFP
 1. click on the 'EBM' button
 1. you will be asked to select a `.b` binary firmware file
      * firmwares I have used:
          * `SFP_180-T_SOS_ROC.b` (aka version 8570) with the SHA256 `00c5b9a93d2ef09b19470a53cb8eb4f390f51bc8264fbb761e5dc9853dd4e699`
          * `180T-L4TA-8463.b` with the SHA256 `2e7a927d4d545c029510522dde6f6e27a047cd494295899cb3b8d43ed6baa9fb`
      * `8463` refers to the version number, bigger is (usually) better
 1. now wait as the flashing takes place
      * this will not take long (a minute or so) but do not worry as the window remains unresponsive for the duration
      * scroll to the bottom of the log window and wait for it to display a "Upgrade Flash Success"
         * if it fails, I have seen this once and your mileage may vary, *unplug* the SFP and reseat it, close `DSLmanager.exe` and repeat the process
 1. close DSLmanager
 1. after upgrade, power cycle SFP (unplug, put it back in)
     * `shutdown` and `no shutdown`ing the switch interface is not enough to power cycle it
