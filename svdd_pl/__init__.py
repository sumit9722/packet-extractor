"""PS side of pynq-pl: the packet extractor, preprocessing and Deep SVDD all run in the PL.

The PS only moves bytes: pcap data goes to the PL in chunks (stream.py), and one
128-byte record per finished flow comes back (records.py). driver.py talks to the
AXI DMA on the board; reference.py runs the svdd_ps software pipeline for checks.
"""
