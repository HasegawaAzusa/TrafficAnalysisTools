# TrafficAnalysisTools

## 简介

为流量分析编写的一些工具脚本。

仅支持 Python >= 3.8。

使用前请安装依赖包。

```bash
pip install -r requirements.txt
```

## 使用

脚本统一使用 `click` 作为命令行工具库，使用 `python scripts.py --help` 即可查看帮助。

### keyboard

`keyboard.py` 是为了方便快速处理 USB-IF 标准编码下的键盘流量数据，包括尝试模拟输入得到结果。

仅能处理标准 8 字节数据

| 偏移 | 0      | 1    | 2       | 3       | 4       | 5       | 6       | 7       |
| ---- | ------ | ---- | ------- | ------- | ------- | ------- | ------- | ------- |
| 值   | 修饰键 | 保留 | 映射键1 | 映射键2 | 映射键3 | 映射键4 | 映射键5 | 映射键6 |

对于标准数据或标准数据包，通过 `-f` 参数输入文件

```bash
python keyboard.py -f data.dat -d
```

对于非标准数据，或者是 `scapy` 无法提取的数据，请使用 `tshark` 或其他工具提取并预处理数据后，使用 `-d` 参数输入。

例如

```bash
tshark -r file.pcap -T fields -e usb.capdata > data.dat
tshark -r file.pcap -Y "usb.device_address == 1" -T fields -e usb.capdata
```

然后

```bash
python keyboard.py -f data.dat -d
```



### mouse

`mouse.py` 是为了方便快速处理鼠标流量数据，包括尝试模拟输入得到结果。

仅能处理标准 8 字节数据或 4 字节数据。

| 偏移 | 0        | 1    | 2:4        | 4:6        | 7            | 8            |
| ---- | -------- | ---- | ---------- | ---------- | ------------ | ------------ |
| 值   | 按键掩码 | 保留 | x 轴偏移量 | y 轴偏移量 | 垂直滚轮偏移 | 水平滚轮偏移 |

| 偏移 | 0        | 1          | 2          | 3            |
| ---- | -------- | ---------- | ---------- | ------------ |
| 值   | 按键掩码 | x 轴偏移量 | y 轴偏移量 | 垂直滚轮偏移 |

特别地，处理后可以支持 Linux 的 micelog

| 偏移 | 0        | 1          | 2          |
| ---- | -------- | ---------- | ---------- |
| 值   | 按键掩码 | x 轴偏移量 | y 轴偏移量 |

同 `keyboard.py`，对于纯数据使用 `-d` 参数。



### KeyboardValues

`KeyboardValues.json` 记录了映射键的对应值，其中

- `Id` - 映射键的 ID
- `Name` - 映射键的名字
- `Value` - 映射键输入值
- `ShiftValue` - 映射键伴随 Shift 修饰键的输入值

可以自由修改，也可以复制使用。

> 值来源 USB-IF 组织发布的 HID Usage Tables v1.5。



### webshell

用于自动化解析常见 WebShell 流量包中的编码/加密数据。

> 暂时还没写完，目前只有少量功能。
>
> `-f` 参数输入流量包，`-t` 选择解析用翻译器（`Translator`）
>
> 比如说对于 AntSword 流量示例
>
> ```bash
> python .\webshell.py -f .\webshell_test\antsword.pcapng -t antsword
> ```
>
> 推荐以 JSON 形式输入上下文相关量，不同翻译器需求不同相关量（参数 `-c`），示例
>
> ```bash
> python .\webshell.py -f .\webshell_test\antsword.pcapng -t antsword -c ctx.json > rst.txt
> ```
>
> 对于 Behinder 流量
>
> ```bash
> python .\webshell.py -f .\webshell_test\behinder.pcapng -t behinder.xor_base64 -c ctx.json > rst.txt
> ```
>
> `ctx.json` 示例
>
> ```json
> {
>     "password": "qsdzyyds",
>     "encoder": "base64",
>     "decoder": "base64",
>     "key": "e45e329feb5d925b"
> }
> ```

目标是能够自动化分析出流量包中的默认 WebShell 流量，并且分析其行为

> 进行模板比对得知行为。
>
> 不过还未实现。

 需要注意的是，目前 `scapy` 解析 HTTP 流量时会有一定 BUG，目前考虑是否转为 PyShark。



