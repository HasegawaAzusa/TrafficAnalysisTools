from scapy.all import *
from enum import IntFlag
from scapy.layers import usb
from matplotlib import pyplot as plt
import numpy as np
import itertools
import click
import struct

EPILOG = "Author: qsdz (Email to 531240801@qq.com)"
URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER = 0x09

class ButtonMask(IntFlag):
    MOVE = 0x00
    LEFT = 0x01
    RIGHT = 0x02
    MIDDLE = 0x04

BUTTON_MASKS = {
    ButtonMask.MOVE: "Move",
    ButtonMask.LEFT: "Left",
    ButtonMask.RIGHT: "Right",
    ButtonMask.MIDDLE: "Middle"
}

class ParseMode(IntFlag):
    MICE_LOG = 0x03
    SHORT_HID = 0x04
    LONG_HID = 0x08

MODE_PATTERN = {
    ParseMode.MICE_LOG: ">Bbb",
    ParseMode.SHORT_HID: ">Bbbx",
    ParseMode.LONG_HID: ">Bxhhxx"
}

class OutputMode(IntFlag):
    LEFT = 0x01
    RIGHT = 0x02
    MIDDLE = 0x04
    MOVE = 0X10

output_mode_mapping = {
    "left": OutputMode.LEFT,
    "right": OutputMode.RIGHT,
    "middle": OutputMode.MIDDLE,
    "move": OutputMode.MOVE
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
            button: ButtonMask, button mask for mouse
            offset_x: int, cursor offset x
            offset_y: int, cursor offset y
        """
        self.current_x += offset_x
        self.current_y += offset_y
        # Record trace
        self.traces.append(SimulatedPaint.Trace(button, self.current_x, -self.current_y))

    def output(self, filename: str, output_mode: OutputMode):
        """
        output to file

        Args:
            filename: str, output filename
            output_mode: OutputMode, output mode
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
                ax.plot(points[:, 0], points[:, 1], linestyle='--')
        fig.savefig(filename)

def usbpcap_unique_id(usbpcap: usb.USBpcap):
    """
    Get unique id from USBpcap
    """
    assert usbpcap.haslayer(usb.USBpcap)
    return f'{usbpcap.bus}-{usbpcap.device}-{usbpcap.endpoint}'

def parse_hiddatas(hiddatas: list[bytes], verbose: int, device: str, output_mode: OutputMode):
    """
    The core function to parse hiddatas
    """
    mode = ParseMode(len(hiddatas[0]) if hiddatas else ParseMode.LONG_HID)
    pattern = MODE_PATTERN[mode]
    paint = SimulatedPaint()
    for hiddata in hiddatas:
        ### verbose level 2
        if verbose >= 2:
            click.echo(
                click.style(f" ** {hiddata.hex()}", fg='cyan')
            )
        button, offset_x, offset_y = struct.unpack(pattern, hiddata)
        if button not in BUTTON_MASKS:
            click.echo(
                click.style(f'[x] Could not parse HID data: {hiddata.hex()}', fg='red')
            )
            continue
        button = ButtonMask(button)

        ### verbose level 1
            # If verbose, print the parsed data
        if verbose >= 1:
            click.echo(
                click.style(f" * {BUTTON_MASKS[button]:<7}{offset_x:<6}{offset_y}", fg='cyan')
            )

        paint.input(button, offset_x, offset_y)
    paint.output(device, output_mode)
    click.echo(
        click.style(f'[+] Output filename: {device}.png', fg='green')
    )

@click.command(epilog=EPILOG)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='pcap file path', required=True)
@click.option('-o', '--output',
              type=click.Choice(list(output_mode_mapping.keys())),
              multiple=True,
              default=["left", ],
              show_default=True,
              help='output options'
            )
@click.option('-d', '--data', is_flag=True, default=False, help='isdata input')
@click.option('-v', '--verbose', count=True, help='verbose output')
def main(file: click.Path, output: list[str], data: bool, verbose: bool):
    hiddatas: list[bytes] = None
    output_mode = OutputMode(0)
    for mode in output:
        output_mode |= output_mode_mapping[mode]
    # For extracted data by tshark, else pcap file
    if data:
        with open(file, 'r') as f:
            filedatas = f.read().splitlines()
        hiddatas = [bytes.fromhex(d.replace(':', '')) for d in filedatas]
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
            group = list(
                filter(lambda packet: usbpcap_unique_id(packet) == device, packets)
            )
            click.echo(
                click.style(f"[+] Device: {device}", fg='green')
            )
            # 8 bytes HID data
            hiddatas = [usb_packet.load for usb_packet in group if usb_packet.dataLength == 8]
            if not hiddatas:
                # or 4 bytes HID data
                hiddatas = [usb_packet.load for usb_packet in group if usb_packet.dataLength == 4]

            # print(hiddatas)
            parse_hiddatas(hiddatas, verbose, device, output_mode)

if __name__ == '__main__':
    main()