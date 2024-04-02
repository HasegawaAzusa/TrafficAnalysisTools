from collections import defaultdict
from enum import IntFlag
from matplotlib import pyplot as plt
import numpy as np
from typing import NamedTuple
import click
import itertools
import pyshark
import struct

EPILOG = "Author: qsdz (Email to 531240801@qq.com)"
URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER = 0x0009
USB_KEYBOARD_FILTER = f"(usb.capdata or usbhid.data) and usb.function == {URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER}"


class ButtonMask(IntFlag):
    MOVE = 0x00
    LEFT = 0x01
    RIGHT = 0x02
    MIDDLE = 0x04


BUTTON_MASKS = {
    ButtonMask.MOVE: "Move",
    ButtonMask.LEFT: "Left",
    ButtonMask.RIGHT: "Right",
    ButtonMask.MIDDLE: "Middle",
}

class ParseMode(IntFlag):
    MICE_LOG = 0x03
    SHORT_HID = 0x04,
    LONG_HID = 0x08,

PARSE_MODE = {
    0x03: ParseMode.MICE_LOG,
    0x04: ParseMode.SHORT_HID,
    0x08: ParseMode.LONG_HID,
}

MODE_PATTERN = {
    ParseMode.MICE_LOG: ">Bbb",
    ParseMode.SHORT_HID: ">Bbbx",
    ParseMode.LONG_HID: ">Bxhhxx",
}


class OutputMode(IntFlag):
    LEFT = 0x01
    RIGHT = 0x02
    MIDDLE = 0x04
    MOVE = 0x10


output_mode_mapping = {
    "left": OutputMode.LEFT,
    "right": OutputMode.RIGHT,
    "middle": OutputMode.MIDDLE,
    "move": OutputMode.MOVE,
}


class SimulatedPaint:
    """
    Simulated paint is used to simulate mouse input

    Attributes:
        current_x: int, cursor current x position
        current_y: int, cursor current y position
        traces: list[Trace], cursor traces
    """

    class Trace(NamedTuple):
        button: ButtonMask
        x: int
        y: int

    current_x: int
    current_y: int
    traces: list[Trace]

    def __init__(self):
        self.current_x = 0
        self.current_y = 0
        self.traces = []

    def input(self, button: ButtonMask, offset_x: int, offset_y: int):
        """
        input once

        Args:
            button (ButtonMask): button mask for mouse
            offset_x (int): cursor offset x
            offset_y (int): cursor offset y
        """
        self.current_x += offset_x
        self.current_y += offset_y
        # Record trace
        self.traces.append(
            SimulatedPaint.Trace(button, self.current_x, -self.current_y)
        )

    def output(self, filename: str, output_mode: OutputMode):
        """
        output to file

        Args:
            filename (str): output filename
            output_mode (OutputMode): output mode
        """
        fig = plt.figure()
        ax = fig.add_subplot(111)
        for button, group in itertools.groupby(self.traces, lambda trace: trace.button):
            points = np.array([(ele.x, ele.y) for ele in group])
            if output_mode & OutputMode.LEFT and button == ButtonMask.LEFT:
                ax.plot(points[:, 0], points[:, 1])
            elif output_mode & OutputMode.RIGHT and button == ButtonMask.RIGHT:
                ax.plot(points[:, 0], points[:, 1])
            elif output_mode & OutputMode.MOVE and button == ButtonMask.MOVE:
                ax.plot(points[:, 0], points[:, 1], linestyle="--")
        fig.savefig(filename + ".png")

def parse_hiddatas(
    hiddatas: list[bytes], verbose: int, device: str, output_mode: OutputMode
):
    """
    The core function to parse hiddatas
    """
    mode = PARSE_MODE.get(len(hiddatas[0]), ParseMode.LONG_HID)
    pattern = MODE_PATTERN[mode]
    paint = SimulatedPaint()
    for hiddata in hiddatas:
        if len(hiddata) != int(mode):
            continue
        ### verbose level 2
        if verbose >= 2:
            click.echo(click.style(f" ** {hiddata.hex()}", fg="cyan"))
        button, offset_x, offset_y = struct.unpack(pattern, hiddata)
        if button not in BUTTON_MASKS:
            click.echo(
                click.style(f"[x] Could not parse HID data: {hiddata.hex()}", fg="red")
            )
            continue
        button = ButtonMask(button)

        ### verbose level 1
        # If verbose, print the parsed data
        if verbose >= 1:
            click.echo(
                click.style(
                    f" * {BUTTON_MASKS[button]:<7}{offset_x:<6}{offset_y}", fg="cyan"
                )
            )

        paint.input(button, offset_x, offset_y)
    paint.output(device, output_mode)
    click.echo(click.style(f"[+] Output filename: {device}.png", fg="green"))


@click.command(epilog=EPILOG)
@click.option(
    "-f",
    "--file",
    type=click.Path(exists=True, dir_okay=False),
    help="pcap file path",
    required=True,
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(list(output_mode_mapping.keys())),
    multiple=True,
    default=[
        "left",
    ],
    show_default=True,
    help="output options",
)
@click.option("-d", "--data", is_flag=True, default=False, help="isdata input")
@click.option("-v", "--verbose", count=True, help="verbose output")
def main(file: click.Path, output: list[str], data: bool, verbose: bool):
    """
    A tool to parse hiddatas from pcap file or extracted data by tshark

    HID data length must be 8 bytes or 4 bytes, and the first byte is the button mask

    Other support Linux micelog.

    Sometimes scapy could not parse hiddatas from pcap file,
    so this tool is used to parse hiddatas from pcap file or extracted data by tshark
    """
    groups: dict[str, list[str]] = defaultdict(list)
    output_mode = OutputMode(0)
    for mode in output:
        output_mode |= output_mode_mapping[mode]
    # For extracted data by tshark, else pcap file
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
        hiddatas = [bytes.fromhex(d.replace(":", "")) for d in hex_hiddatas]
        parse_hiddatas(hiddatas, verbose, device, output_mode)


if __name__ == "__main__":
    main()
