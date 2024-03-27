from scapy.all import *
from pathlib import Path
from enum import IntFlag
import json
from scapy.layers import usb
import click

EPILOG = "Author: qsdz (Email to 531240801@qq.com)"
URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER = 0x09

class HIDKeyboardKey(NamedTuple):
    """
    HID Keyboard Key Usage
    """
    id: int
    name: str
    value: str = ""
    shift_value: str = ""

class ModifierKeyMask(IntFlag):
    NONE = 0x00
    LCTRL = 0x01
    LSHIFT = 0x02
    LALT = 0x04
    LMETA = 0x08
    RCTRL = 0x10
    RSHIFT = 0x20
    RALT = 0x40
    RMETA = 0x80
    CTRL = LCTRL | RCTRL
    SHIFT = LSHIFT | RSHIFT
    ALT = LALT | RALT
    META = LMETA | RMETA

class MappingKeyId(IntFlag):
    """
    Mapping Key Id, some special keys
    """
    A = 4
    Z = 29
    DELETE = 42
    CAPS = 57

# Modifier keys table
modifier_key_table = {
    ModifierKeyMask.NONE: HIDKeyboardKey(ModifierKeyMask.NONE, "None"),
    ModifierKeyMask.LCTRL: HIDKeyboardKey(ModifierKeyMask.LCTRL, "Left Control"),
    ModifierKeyMask.LSHIFT: HIDKeyboardKey(ModifierKeyMask.LSHIFT, "Left Shift"),
    ModifierKeyMask.LALT: HIDKeyboardKey(ModifierKeyMask.LALT, "Left Alt"),
    ModifierKeyMask.LMETA: HIDKeyboardKey(ModifierKeyMask.LMETA, "Left Meta"),
    ModifierKeyMask.RCTRL: HIDKeyboardKey(ModifierKeyMask.RCTRL, "Right Control"),
    ModifierKeyMask.RSHIFT: HIDKeyboardKey(ModifierKeyMask.RSHIFT, "Right Shift"),
    ModifierKeyMask.RALT: HIDKeyboardKey(ModifierKeyMask.RALT, "Right Alt"),
    ModifierKeyMask.RMETA: HIDKeyboardKey(ModifierKeyMask.RMETA, "Right Meta"),
}

keyboard_values = json.loads(Path('KeyboardValues.json').read_text())
mapping_key_table = {obj["Id"]: HIDKeyboardKey(obj["Id"], obj["Name"], obj['Value'], obj['ShiftValue']) for obj in keyboard_values}

class SimulatedEditBox:
    """
    Simulated EditBox is used to simulate keyboard input

    Attributes:
        value: str, current input value
        is_caps: bool, is caps lock on
    """
    value: str = ""
    is_caps: bool = False

    def input(self, modifier_key: HIDKeyboardKey, mapping_key: HIDKeyboardKey):
        """
        input once

        Args:
            modifier_key: HIDKeyboardKey, modifier key
            mapping_key: HIDKeyboardKey, mapping key
        """
        # First handle special keys
        if mapping_key.id == MappingKeyId.CAPS:
            self.is_caps = not self.is_caps
        elif mapping_key.id == MappingKeyId.DELETE:
            self.value = self.value[:-1]
        else:
            # Handle normal keys
            is_specialed = self.is_caps and MappingKeyId.A <= mapping_key.id <= MappingKeyId.Z
            if modifier_key.id == ModifierKeyMask.NONE:
                self.value += mapping_key.value if not is_specialed else mapping_key.shift_value
            elif modifier_key.id & ModifierKeyMask.SHIFT:
                self.value += mapping_key.shift_value if not is_specialed else mapping_key.value

def usbpcap_unique_id(usbpcap: usb.USBpcap):
    """
    Get unique id from USBpcap
    """
    assert usbpcap.haslayer(usb.USBpcap)
    return f'{usbpcap.bus}-{usbpcap.device}-{usbpcap.endpoint}'


def parse_hiddatas(hiddatas: list[bytes], verbose: int):
    """
    The core function to parse hiddatas
    """
    editbox = SimulatedEditBox()
    for hiddata in hiddatas:
        ### verbose level 2
        if verbose >= 2:
            click.echo(
                click.style(f" ** {hiddata.hex()}", fg='cyan')
            )
        modifier_key = modifier_key_table.get(hiddata[0], None)
        for i in range(2, 8):
            mapping_key = mapping_key_table.get(hiddata[i], None)

            # If modifier key is not found, report and skip this packet
            if not modifier_key:
                click.echo(
                    click.style(f'[x] Could not parse HID data: {hiddata.hex()}', fg='red')
                )
                continue
            
            # If mapping key is not found, skip this packet
            if not mapping_key:
                continue

            ### verbose level 1
            # If verbose, print the parsed data
            if verbose >= 1:
                click.echo(
                    click.style(f" * {modifier_key.name:<13}{mapping_key.name}", fg='cyan')
                )
            
            # Simulate input
            editbox.input(modifier_key, mapping_key)
    
    # Last print the possible input
    click.echo(
        click.style(f'[+] Simulated Input Data: {editbox.value}', fg='green')
    )

@click.command(epilog=EPILOG)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='pcap file path', required=True)
@click.option('-d', '--data', is_flag=True, default=False, help='isdata input')
@click.option('-v', '--verbose', count=True, help='verbose output')
def main(file: click.Path, data: bool, verbose: bool):
    """
    A tool to parse hiddatas from pcap file or extracted data by tshark

    HID data length must be 8 bytes, and the first byte is the modifier key

    Sometimes scapy could not parse hiddatas from pcap file,
    so this tool is used to parse hiddatas from pcap file or extracted data by tshark
    """
    hiddatas: list[bytes] = None
    # For extracted data by tshark, else pcap file
    if data:
        with open(file, 'r') as f:
            filedatas = f.read().splitlines()
        hiddatas = [bytes.fromhex(d.replace(':', '')) for d in filedatas]
        hiddatas = filter(lambda d: len(d) == 8, hiddatas)
        parse_hiddatas(hiddatas, verbose)
    else:
        # Only USB packets with URB function is URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
        packets = list(
                filter(
                    lambda packet: packet.haslayer(usb.USBpcap) and
                    packet.function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
                    sniff(offline=file)
                )
            )
        device_keys = set(usbpcap_unique_id(packet) for packet in packets)
        # Group by bus id and device id
        for device in device_keys:
            group = filter(lambda packet: usbpcap_unique_id(packet) == device,packets)
            click.echo(
                click.style(f"[+] Device: {device}", fg='green')
            )
            hiddatas = [usb_packet.load for usb_packet in group if usb_packet.dataLength == 8]
            parse_hiddatas(hiddatas, verbose)

if __name__ == '__main__':
    main()