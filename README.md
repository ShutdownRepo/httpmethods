# HTTP Methods Tester

With this script, you can test various HTTP methods against an URL. This can be useful to look for HTTP verb tampering vulnerabilities for example.

## Setup

Clone the repository and install the dependencies :

```sh
git clone https://github.com/apache-strike/HTTP-verb-tempering.git && cd HTTP-verb-tempering
python3 -m pip install requirements.txt
```

## Usage

```sh
python3 http_verb_tempering.py -u http://www.example.com/
```

You can find here a complete list of options :

```
$ ./http_verb_tempering.py -h
HTTP Methods Tester, v1.0.1
usage: http_verb_tempering.py [-h] -u URL [-v] [-q] [-k] [-w WORDLIST]
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
