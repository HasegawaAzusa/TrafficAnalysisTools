from collections import defaultdict
from enum import IntFlag
from pathlib import Path
from typing import NamedTuple
import click
import json
import pyshark

EPILOG = "Author: qsdz (Email to 531240801@qq.com)"
URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER = 0x0009
USB_KEYBOARD_FILTER = f"(usb.capdata or usbhid.data) and usb.function == {URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER}"


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

keyboard_values = json.loads(Path("KeyboardValues.json").read_text())
mapping_key_table = {
    obj["Id"]: HIDKeyboardKey(obj["Id"], obj["Name"], obj["Value"], obj["ShiftValue"])
    for obj in keyboard_values
}


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
            modifier_key (HIDKeyboardKey): modifier key
            mapping_key (HIDKeyboardKey): mapping key
        """
        # First handle special keys
        if mapping_key.id == MappingKeyId.CAPS:
            self.is_caps = not self.is_caps
        elif mapping_key.id == MappingKeyId.DELETE:
            self.value = self.value[:-1]
        else:
            # Handle normal keys
            is_specialed = (
                self.is_caps and MappingKeyId.A <= mapping_key.id <= MappingKeyId.Z
            )
            if modifier_key.id == ModifierKeyMask.NONE:
                self.value += (
                    mapping_key.value if not is_specialed else mapping_key.shift_value
                )
            elif modifier_key.id & ModifierKeyMask.SHIFT:
                self.value += (
                    mapping_key.shift_value if not is_specialed else mapping_key.value
                )


def parse_hiddatas(hiddatas: list[bytes], verbose: int):
    """
    The core function to parse hiddatas

    Args:
        hiddatas (list[bytes]): hiddatas from usbhid packet
        verbose (int): verbose level
    """
    editbox = SimulatedEditBox()
    for hiddata in hiddatas:
        if len(hiddata) != 8:
            continue
        ### verbose level 2
        if verbose >= 2:
            click.echo(click.style(f" ** {hiddata.hex()}", fg="cyan"))
        modifier_key = modifier_key_table.get(hiddata[0], None)
        for i in range(2, 8):
            mapping_key = mapping_key_table.get(hiddata[i], None)

            # If modifier key is not found, report and skip this packet
            if not modifier_key:
                click.echo(
                    click.style(
                        f"[x] Could not parse HID data: {hiddata.hex()}", fg="red"
                    )
                )
                continue

            # If mapping key is not found, skip this packet
            if not mapping_key:
                continue

            ### verbose level 1
            # If verbose, print the parsed data
            if verbose >= 1:
                click.echo(
                    click.style(
                        f" * {modifier_key.name:<13}{mapping_key.name}", fg="cyan"
                    )
                )

            # Simulate input
            editbox.input(modifier_key, mapping_key)

    # Last print the possible input
    click.echo(click.style(f"[+] Simulated Input Data: {editbox.value}", fg="green"))


@click.command(epilog=EPILOG)
@click.option(
    "-f",
    "--file",
    type=click.Path(exists=True, dir_okay=False),
    help="pcap file path",
    required=True,
)
@click.option("-d", "--data", is_flag=True, default=False, help="isdata input")
@click.option("-v", "--verbose", count=True, help="verbose output")
def main(file: click.Path, data: bool, verbose: bool):
    """
    A tool to parse hiddatas from pcap file or extracted data by tshark

    HID data length must be 8 bytes, and the first byte is the modifier key

    Sometimes scapy could not parse hiddatas from pcap file,
    so this tool is used to parse hiddatas from pcap file or extracted data by tshark
    """
    # usb.src -> data.usb_capdata / data.usbhid_data
    groups: dict[str, list[str]] = defaultdict(list)
    if data:
        with open(file, "r") as f:
            filedatas = f.read().splitlines()
        groups["9.5.210"] = filedatas
    else:
        # Only USB packets with URB function is URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
        capture = pyshark.FileCapture(file, display_filter=USB_KEYBOARD_FILTER)
        for packet in capture:
            try:
                if "usb_capdata" in packet.data.field_names:
                    groups[packet.usb.src].append(packet.data.usb_capdata)
                elif "usbhid_data" in packet.data.field_names:
                    groups[packet.usb.src].append(packet.data.usbhid_data)
            except:
                if verbose >= 1:
                    click.echo(
                        click.style(
                            f"[x] Could not parse packet: {packet.usb.src}", fg="red"
                        )
                    )

    for device, hex_hiddatas in groups.items():
        click.echo(click.style(f"[+] Device: {device}", fg="green"))
        hiddatas = [bytes.fromhex(d.replace(":", "")) for d in hex_hiddatas]
        hiddatas = filter(lambda d: len(d) == 8, hiddatas)
        parse_hiddatas(hiddatas, verbose)


if __name__ == "__main__":
    main()
