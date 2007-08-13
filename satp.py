#! /usr/bin/env python

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy import *

class SATP(Packet):
    name = "SATP"
    fields_desc = [
            IntField("seq", None),
            ShortField("id", None)
            ]

layer_bonds += [ ( UDP, SATP, { "sport" : 4444, "dport" : 4444 }) ]

for l in layer_bonds:
    bind_layers(*l)
del(l)


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on v3.14")

