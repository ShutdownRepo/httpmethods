#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          :
# Author             :
# Date created       :
# Date last modified :
# Python Version     : 3.*

import argparse
from concurrent.futures import ThreadPoolExecutor
import requests
from rich.console import Console
from rich import box
from rich.table import Table
import urllib3
import json

methods = [
    'CHECKIN', 'CHECKOUT', 'CONNECT', 'COPY', 'DELETE', 'GET', 'HEAD', 'INDEX',
    'LINK', 'LOCK', 'MKCOL', 'MOVE', 'NOEXISTE', 'OPTIONS', 'ORDERPATCH',
    'PATCH', 'POST', 'PROPFIND', 'PROPPATCH', 'PUT', 'REPORT', 'SEARCH',
    'SHOWMETHOD', 'SPACEJUMP', 'TEXTSEARCH', 'TRACE', 'TRACK', 'UNCHECKOUT',
    'UNLINK', 'UNLOCK', 'VERSION-CONTROL'
]

class Logger:
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet

    def debug(self, message):
        if self.verbosity == 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)


def get_options():
    description = "This Python script can be used for HTTP verb tampering to bypass forbidden access, and for HTTP " \
                  "methods enumeration to find dangerous enabled methods like PUT "

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument('-u', "--url", required=True, help="e.g. https://example.com:port/path")
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="verbosity level (-v for verbose, -vv for debug)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Show no informations at all",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        dest="verify",
        action="store_false",
        default=True,
        required=False,
        help="Allow insecure server connections when using SSL (default: False)",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        dest="wordlist",
        action="store",
        default=None,
        required=False,
        help="HTTP methods wordlist (default is a builtin wordlist)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        action="store",
        type=int,
        default=5,
        required=False,
        help="Number of threads (default: 5)",
    )
    parser.add_argument(
        "-j",
        "--jsonfile",
        dest="jsonfile",
        default=None,
        required=False,
        help="Save results to specified JSON file.",
    )
    options = parser.parse_args()
    return options


def methods_from_http_options(url, verify):
    methods = []
    logger.verbose("Pulling available methods from server with an OPTIONS request")
    r = requests.options(url=options.url, verify=options.verify)
    if r.status_code == 200:
        logger.verbose("URL accepts OPTIONS")
        logger.debug(r.headers)
        if "Allow" in r.headers:
            logger.info("URL answers with a list of options: {}".format(r.headers["Allow"]))
            for method in r.headers["Allow"].replace(" ", "").split(","):
                if method not in methods:
                    logger.debug(f"Adding new method {method} to methods")
                    methods.append(method)
                else:
                    logger.debug(f"Method {method} already in known methods, passing")
        else:
            logger.verbose("URL doesn't answer with a list of options")
    else:
        logger.verbose("URL rejects OPTIONS")
    return methods


def test_method(method, url, verify, results):
    r = requests.request(
        method=method,
        url=url,
        verify=verify, # this is to set the client to accept insecure servers
        stream=True    # this is to prevent the download of huge files, focus on the request, not on the data
    )
    logger.debug(f"Obtained results: {method}, {str(r.status_code)}, {r.reason}")
    results[method] = {"status_code": r.status_code, "reason": r.reason[:100]}


def main(options, logger, console):
    logger.info("Starting HTTP verb enumerating and tampering")
    global methods
    # Retreiving methods from wordlist
    if options.wordlist != None:
        with open(options.wordlist, "r") as infile:
            methods += infile.read().split()
    results = {}
    methods += methods_from_http_options(options.url, options.verify)

    # Waits for all the threads to be completed
    with ThreadPoolExecutor(max_workers=min(options.threads, len(methods))) as tp:
        for method in methods:
            tp.submit(test_method, method, options.url, options.verify, results)
    # It is blocking until all the threads are completed

    # Sorting the results by method name
    results = {key: results[key] for key in sorted(results)}

    # Parsing and print results
    table = Table(show_header=True, header_style="bold blue", border_style="blue", box=box.SIMPLE)
    table.add_column("Method")
    table.add_column("Status code")
    table.add_column("Reason")
    for result in results.items():
        if result[1]["status_code"] == 200:  # This means the method is accepted
            style = "green"
        elif result[1]["status_code"] == 502:  # This probably means the method is accepted but request was malformed
            style = "yellow4"
        elif (500 <= result[1]["status_code"] <= 599) and result[1]["status_code"] != 502:  # This means the method is not implemented in most cases
            style = "orange3"
        elif 400 <= result[1]["status_code"] <= 499:  # This means the method is disabled in most cases
            style = "red"
        else:
            style = None
        table.add_row(result[0], str(result[1]["status_code"]), result[1]["reason"], style=style)
    console.print(table)

    # Export to JSON if specified
    if options.jsonfile != None:
        f = open(options.jsonfile, "w")
        f.write(json.dumps(results, indent=4)+"\n")
        f.close()



if __name__ == '__main__':
    try:
        print("HTTP Methods Tester, v1.0.1\n")
        options = get_options()
        logger  = Logger(options.verbosity, options.quiet)
        console = Console()
        if options.verify == False:
            # Disable warings of insecure connection for invalid cerificates
            requests.packages.urllib3.disable_warnings()
            # Allow use of deprecated and weak cipher methods
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            except AttributeError:
                pass
        main(options, logger, console)
    except KeyboardInterrupt:
        logger.info("Terminating script...")
        raise SystemExit
