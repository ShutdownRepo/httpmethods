# HTTP Methods Tester

With this script, you can test various HTTP methods against an URL. This can be useful to look for HTTP verb tampering vulnerabilities and dangerous HTTP methods.

![example](assets/example.gif)

## Setup

```sh
pipx install git+https://github.com/ShutdownRepo/httpmethods
```
or
```sh
uv tool install git+https://github.com/ShutdownRepo/httpmethods
```

## Usage

```sh
httpmethods http://www.example.com/
```

Multiple targets can be tested by giving a file with one URL per line (empty lines and lines starting with `#` are ignored, use `-` to read from stdin):

```sh
httpmethods -f urls.txt
cat urls.txt | httpmethods -f - -y
```

You can find here a complete list of options :

```
[~] HTTP Methods Tester, v1.1.3

usage: httpmethods.py [-h] [-v] [-q] [-k] [-L] [-s] [-w WORDLIST] [-t THREADS] [-j JSONFILE] [-x PROXY] [-b COOKIES] [-H HEADERS] [-y] [-n] (-f URLS_FILE | url)

This Python script can be used for HTTP verb tampering to bypass forbidden access, and for HTTP methods enumeration to find dangerous enabled methods like PUT 

positional arguments:
  url                   e.g. https://example.com:port/path

optional arguments:
  -h, --help            show this help message and exit
  -f URLS_FILE, --file URLS_FILE
                        File containing a list of target URLs, one per line (use - for stdin)
  -v, --verbose         verbosity level (-v for verbose, -vv for debug)
  -q, --quiet           Show no information at all
  -k, --insecure        Allow insecure server connections when using SSL (default: False)
  -L, --location        Follow redirects (default: False)
  -s, --safe            Use only safe methods for requests (default: False)
  -w WORDLIST, --wordlist WORDLIST
                        HTTP methods wordlist (default is a builtin wordlist)
  -t THREADS, --threads THREADS
                        Number of threads (default: 5)
  -j JSONFILE, --jsonfile JSONFILE
                        Save results to specified JSON file.
  -x PROXY, --proxy PROXY
                        Specify a proxy to use for requests (e.g., http://localhost:8080)
  -b COOKIES, --cookies COOKIES
                        Specify cookies to use in requests. (e.g., --cookies "cookie1=blah;cookie2=blah")
  -H HEADERS, --header HEADERS
                        Specify headers to use in requests. (e.g., --header "Header1: Value1" --header "Header2: Value2")
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
