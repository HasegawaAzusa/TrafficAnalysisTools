from ..translator import *
from .xor import behinder_xor
from urllib import parse
import base64
import itertools

def brute_response(s: str):
    rst = ''
    for i, j in itertools.product(range(2, 16), repeat=2):
        try:
            rst = base64.b64decode(s[i:-j])
            yield rst
        except:
            ...

class XORBase64Translator(TranslatorInterface):
    key: str
    def __init__(self, key: str) -> None:
        self.key = key

    def request(self, packet: http.HTTP) -> str:
        load = parse.unquote(packet.load)
        data = base64.b64decode(load)
        rst = behinder_xor(data, self.key)
        return rst.decode(errors="ignore")
    
    def response(self, packet: http.HTTP) -> str:
        load = parse.unquote(packet.load)
        data = base64.b64decode(load)
        rst = behinder_xor(data, self.key)
        return rst.decode(errors="ignore")