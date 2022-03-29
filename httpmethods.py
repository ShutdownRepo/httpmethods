#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import requests
from rich.console import Console
from rich import box
from rich.table import Table
import json
from http.cookies import SimpleCookie

banner = "[~] HTTP Methods Tester, v1.1.3\n"

methods = [
    'CHECKIN', 'CHECKOUT', 'CONNECT', 'COPY', 'DELETE', 'GET', 'HEAD', 'INDEX',
    'LINK', 'LOCK', 'MKCOL', 'MOVE', 'NOEXISTE', 'OPTIONS', 'ORDERPATCH',
    'PATCH', 'POST', 'PROPFIND', 'PROPPATCH', 'PUT', 'REPORT', 'SEARCH',
    'SHOWMETHOD', 'SPACEJUMP', 'TEXTSEARCH', 'TRACE', 'TRACK', 'UNCHECKOUT',
    'UNLINK', 'UNLOCK', 'VERSION-CONTROL', 'BAMBOOZLE'
]


class Logger(object):
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
    description = "This Python script can be used for HTTP verb tampering to bypass forbidden access, and for HTTP methods enumeration to find dangerous enabled methods like PUT "

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "url",
        help="e.g. https://example.com:port/path"
    )
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
        help="Show no information at all",
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
        "-L",
        "--location",
        dest="redirect",
        action="store_true",
        default=False,
        required=False,
        help="Follow redirects (default: False)",
    )
    parser.add_argument(
        '-s',
        '--safe',
        action="store_true",
        default=None,
        dest='safe',
        help="Use only safe methods for requests (default: False)"
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
    parser.add_argument(
        '-x',
        '--proxy',
        action="store",
        default=None,
        dest='proxy',
        help="Specify a proxy to use for requests (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        '-b', '--cookies',
        action="store",
        default=None,
        dest='cookies',
        help='Specify cookies to use in requests. (e.g., --cookies "cookie1=blah;cookie2=blah")'
    )
    parser.add_argument(
        '-H',
        '--header',
        default=[],
        dest='headers',
        action='append',
        required=False,
        help='Specify headers to use in requests. (e.g., --header "Header1: Value1" --header "Header2: Value2")'
    )
    options = parser.parse_args()
    return options


def methods_from_wordlist(wordlist):
    logger.verbose(f"Retrieving methods from wordlist {wordlist}")
    try:
        with open(options.wordlist, "r") as infile:
            methods += infile.read().split()
    except Exception as e:
        logger.error(f"Had some kind of error loading the wordlist ¯\_(ツ)_/¯: {e}")


def methods_from_http_options(console, options, proxies, headers, cookies):
    options_methods = []
    logger.verbose("Pulling available methods from server with an OPTIONS request")
    try:
        r = requests.options(
            url=options.url,
            proxies=proxies,
            cookies=cookies,
            headers=headers,
            verify=options.verify
        )
    except requests.exceptions.ProxyError:
        logger.error("Invalid proxy specified ")
        raise SystemExit
    if r.status_code == 200:
        logger.verbose("URL accepts OPTIONS")
        logger.debug(r.headers)
        if "Allow" in r.headers:
            logger.info("URL answers with a list of options: {}".format(r.headers["Allow"]))
            include_options_methods = console.input(
                "[bold orange3][?][/bold orange3] Do you want to add these methods to the test (be careful, some methods can be dangerous)? [Y/n] ")
            if not include_options_methods.lower() == "n":
                for method in r.headers["Allow"].replace(" ", "").split(","):
                    if method not in options_methods:
                        logger.debug(f"Adding new method {method} to methods")
                        options_methods.append(method)
                    else:
                        logger.debug(f"Method {method} already in known methods, passing")
            else:
                logger.debug("Methods found with OPTIONS won't be added to the tested methods")
        else:
            logger.verbose("URL doesn't answer with a list of options")
    else:
        logger.verbose("URL rejects OPTIONS")
    return options_methods


def test_method(options, method, proxies, cookies, headers, results):
    try:
        r = requests.request(
            method=method,
            url=options.url,
            verify=options.verify,  # this is to set the client to accept insecure servers
            proxies=proxies,
            cookies=cookies,
            headers=headers,
            allow_redirects=options.redirect,
            stream=True,  # this is to prevent the download of huge files, focus on the request, not on the data
        )
    except requests.exceptions.ProxyError:
        logger.error("Invalid proxy specified ")
        raise SystemExit
    logger.debug(f"Obtained results: {method}, {str(r.status_code)}, {str(len(r.text))}, {r.reason}")
    results[method] = {"status_code": r.status_code, "length": len(r.text), "reason": r.reason[:100]}


def print_results(console, results):
    logger.verbose("Parsing & printing results")
    table = Table(show_header=True, header_style="bold blue", border_style="blue", box=box.SIMPLE)
    table.add_column("Method")
    table.add_column("Length")
    table.add_column("Status code")
    table.add_column("Reason")
    for result in results.items():
        if result[1]["status_code"] == 200:  # This means the method is accepted
            style = "green"
        elif 300 <= result[1]["status_code"] <= 399:
            style = "cyan"
        elif 400 <= result[1]["status_code"] <= 499:  # This means the method is disabled in most cases
            style = "red"
        elif (500 <= result[1]["status_code"] <= 599) and result[1]["status_code"] != 502:  # This means the method is not implemented in most cases
            style = "orange3"
        elif result[1]["status_code"] == 502:  # This probably means the method is accepted but request was malformed
            style = "yellow4"
        else:
            style = None
        table.add_row(result[0], str(result[1]["length"]), str(result[1]["status_code"]), result[1]["reason"], style=style)
    console.print(table)


def json_export(results, json_file):
    f = open(json_file, "w")
    f.write(json.dumps(results, indent=4) + "\n")
    f.close()


def main(options, logger, console):
    logger.info("Starting HTTP verb enumerating and tampering")
    global methods
    results = {}

    # Verifying the proxy option
    if options.proxy:
        try:
            proxies = {
                "http": "http://" + options.proxy.split('//')[1],
                "https": "http://" + options.proxy.split('//')[1]
            }
            logger.debug(f"Setting proxies to {str(proxies)}")
        except (IndexError, ValueError):
            logger.error("Invalid proxy specified ")
            sys.exit(1)

    else:
        logger.debug("Setting proxies to 'None'")
        proxies = None

    # Parsing cookie option
    if options.cookies:
        cookie = SimpleCookie()
        cookie.load(options.cookies)
        cookies = {key: value.value for key, value in cookie.items()}
    else:
        cookies = {}

    if options.headers:
        headers = {h.split(':', 1)[0]: h.split(':', 1)[1].strip() for h in options.headers}
    else:
        headers = {}

    if options.wordlist is not None:
        methods += methods_from_wordlist(options.wordlist)
    methods += methods_from_http_options(console, options, proxies, headers, cookies)

    # Sort uniq
    methods = [m.upper() for m in methods]
    methods = sorted(list(set(methods)))

    # Filtering for dangerous methods
    filtered_methods = []
    for method in methods:
        if method in ["DELETE", "COPY", "PUT", "PATCH", "UNCHECKOUT"]:
            if not options.safe:
                test_dangerous_method = console.input(
                    f"[bold orange3][?][/bold orange3] Do you really want to test method {method} (can be dangerous)? \[y/N] ")
                if not test_dangerous_method.lower() == "y":
                    logger.verbose(f"Method {method} will not be tested")
                else:
                    logger.verbose(f"Method {method} will be tested")
                    filtered_methods.append(method)
        else:
            filtered_methods.append(method)
    methods = filtered_methods[:]
    del filtered_methods

    # Waits for all the threads to be completed
    with ThreadPoolExecutor(max_workers=min(options.threads, len(methods))) as tp:
        for method in methods:
            tp.submit(test_method, options, method, proxies, cookies, headers, results)

    # Sorting the results by method name
    results = {key: results[key] for key in sorted(results)}

    # Parsing and print results
    print_results(console, results)

    # Export to JSON if specified
    if options.jsonfile is not None:
        json_export(results, options.jsonfile)


if __name__ == '__main__':
    try:
        print(banner)
        options = get_options()
        logger = Logger(options.verbosity, options.quiet)
        console = Console()
        if not options.verify:
            # Disable warnings of insecure connection for invalid cerificates
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
