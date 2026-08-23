"""Enables `python -m pcap_analyzer <capture>`."""

import sys

from pcap_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
