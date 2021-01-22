# HTTP Methods Tester

With this script, you can test various HTTP methods against an URL. This can be useful to look for HTTP verb tampering vulnerabilities and dangerous HTTP methods.

![example](assets/example.gif)

## Setup

Clone the repository and install the dependencies :

```sh
git clone https://github.com/apache-strike/httpmethods
cd httpmethods
python3 setup.py install
```

## Usage

```sh
httpmethods -u http://www.example.com/
```

You can find here a complete list of options :

```
HTTP Methods Tester, v1.0.2
usage: httpmethods.py [-h] -u URL [-v] [-q] [-k] [-w WORDLIST]
                              [-t THREADS] [-j JSONFILE]

This Python script can be used for HTTP verb tampering to bypass forbidden access, and for HTTP methods enumeration to find dangerous enabled methods like PUT

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     e.g. https://example.com:port/path
  -v, --verbose         verbosity level (-v for verbose, -vv for debug)
  -q, --quiet           Show no informations at all
  -k, --insecure        Allow insecure server connections when using SSL (default: False)
  -w WORDLIST, --wordlist WORDLIST
                        HTTP methods wordlist (default: default_wordlist.txt)
  -t THREADS, --threads THREADS
                        Number of threads (default: 5)
  -j JSONFILE, --jsonfile JSONFILE
                        Save results to specified JSON file.
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
