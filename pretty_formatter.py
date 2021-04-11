from rich.console import Console
from rich.table import Table
from rich import box
from rich import print
from rich.panel import Panel

import pdb

console = Console()

def createTable(layer_two, layer_three, layer_four, packet):
    sourceMac       = layer_two['sourceMac']
    destMac          = layer_two['destMac']
    ethernetType     = layer_two['ethernetType']
    sourceIp         = layer_three['sourceIp']
    destIp           = layer_three['destIp']
    protocol         = layer_four['protocol']
    
    print(Panel.fit("Packet [red]{}".format(packet)))

    table = Table(show_header=True, header_style="bold white", box=box.MINIMAL)
    table.add_column("Identifier", style="green", width=28)
    table.add_column("Value",  style="dim", width=28)

    table.add_row('Destination Mac Address', destMac)
    table.add_row("Source Mac Address", sourceMac)
    table.add_row('Ethernet Type', ethernetType)
    table.add_row('Destination IP Address', destIp)
    table.add_row('Source IP Address', sourceIp)

    console.print(table)
