> A simple SHA-2 implementation in python which gives hash for string or a file.
> Suported hashing algorithms: SHA56, SHA512

[![PyPI version](https://img.shields.io/pypi/v/hashed.svg)](https://pypi.org/project/hashed/)


## CLI Tool Usage

* Example

```python
python src/cli.py -s "Hello World!!" --sha256
```

* For help
```python
usage: Hashing Library [-h] [--sha256] [--sha512] [-s STRING] [-f FILE] [-fb BINARY_FILE] [-t] [-p] [-b]

Provides secured hashes for given data

options:
  -h, --help            show this help message and exit
  --sha256              Generates SHA-256 for given input (default: False)
  --sha512              Generates SHA-512 for given input (default: False)
  -s STRING, --string STRING
                        String to be hashed (default: None)
  -f FILE, --file FILE  File to be hashed (default: None)
  -fb BINARY_FILE, --binary_file BINARY_FILE
                        Binary file to be hashed (default: None)
  -t, --test            Test accuracy of algorithm (default: False)
  -p, --perf            Log performance of the algorithm (default: False)
  -b, --bits            Returns size of hashed message in bytes (default: False)

Currently supported hashes [SHA256, SHA512]
```


## Package Usage

```python
from hashed import HashLib
h = HashLib('sha256').hasher_class()
h.hex_digest("Hello World")
```

## Functions Supported

- hex_digest
- file_digest
- digest
- hashed_bits
- digest_size

## For Algo refer: [SHA-256 Wiki](https://en.wikipedia.org/wiki/SHA-2)

## For more refer:

- https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
- https://github.com/mukund26/softwareEnggGuide/blob/main/sha256-384-512.pdf
