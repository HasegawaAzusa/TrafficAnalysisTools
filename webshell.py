from scapy.all import *
from scapy.layers import http
from pathlib import Path
import importlib
import pkgutil
import importlib
from translators.translator import TranslatorInterface
from urllib import parse
import json
import click

EPILOG = "Author: qsdz (Email to 531240801@qq.com)"
TRANSLATORS_PATH = "translators"

__translators = {}

for module_info in pkgutil.walk_packages((TRANSLATORS_PATH, ), prefix=TRANSLATORS_PATH + '.'):
    finder, name, ispkg = module_info
    if ispkg:
        continue
    module = importlib.import_module(name)

for translator_class in TranslatorInterface.__subclasses__():
    # Remove the `translator.` at the start
    translator_name = translator_class.__module__[len(TRANSLATORS_PATH)+1:]
    __translators[translator_name] = translator_class

def is_request(packet: http.HTTP) -> bool:
    """
    Check if the packet is a request

    :param packet: http packet
    :return: True if the packet is a request, False otherwise
    """
    return packet.haslayer(http.HTTPRequest)

def is_response(packet: http.HTTP) -> bool:
    """
    Check if the packet is a response

    :param packet: http packet
    :return: True if the packet is a response, False otherwise
    """
    return packet.haslayer(http.HTTPResponse)

def trans_instance(trans_name: str, ctx: dict) -> TranslatorInterface:
    trans = __translators[trans_name]
    kwargs = {}
    for var_name, var_type in trans.__init__.__annotations__.items():
        if var_name == 'return':
            continue
        prompt_str = click.style(f'{trans_name}.{var_name}', fg='blue')
        if var_name in ctx:
            val = ctx[var_name]
            click.echo(prompt_str + f" : {val}")
        else:
            val = click.prompt(
                    prompt_str,
                    type=var_type,
                )
        kwargs[var_name] = val
    return trans(**kwargs)

def ctx_instance(ctx: click.Path) -> dict:
    if ctx is None:
        return dict()
    with open(ctx, 'r') as f:
        ctx_instance = json.load(f)
    if isinstance(ctx_instance, dict):
        return ctx_instance
    return dict()

@click.command(epilog=EPILOG)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='pcap file path', required=True)
@click.option('-t', '--trans', type=click.Choice(__translators.keys()), default='default', help='Translator about encrypted traffic')
@click.option('-c', '--ctx', type=click.Path(exists=True, dir_okay=False), default=None, help='Context of the translator, must be JSON object')
def main(file: click.Path, trans: str, ctx: click.Path):
    ctx: dict = ctx_instance(ctx)
    trans: TranslatorInterface = trans_instance(trans, ctx)

    pcap = sniff(offline=file, session=TCPSession)
    sessions = pcap.sessions()
    for session_id, packets in sessions.items():
        packets: PacketList
        click.echo(
            click.style(f"[+] Session - {session_id}", fg="green")
        )
        for http_packet in filter(lambda p: p.haslayer(http.HTTP), packets):
            if is_request(http_packet):
                click.echo(
                    click.style(f"=== Request ===", fg="blue")
                )
                try:
                    click.echo(trans.request(http_packet))
                except:
                    ...
                click.echo(
                    click.style(f"=== Request ===", fg="blue")
                )
            elif is_response(http_packet):
                click.echo(
                    click.style(f"=== Response ===", fg="blue")
                )
                try:
                    click.echo(trans.response(http_packet))
                except:
                    ...
                click.echo(
                    click.style(f"=== Response ===", fg="blue")
                )
            else:
                click.echo(
                    click.style(f"[x] Unknown", fg="red")
                )

if __name__ == '__main__':
    main()