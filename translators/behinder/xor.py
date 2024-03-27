from ..translator import *
import itertools

def behinder_xor(data: bytes, key: str):
    key = key[1:] + key[:1]
    return bytes([x ^ ord(y) for x, y in zip(data, itertools.cycle(key))])

class XORBase64Translator(TranslatorInterface):
    key: str
    def __init__(self, key: str) -> None:
        self.key

    def request(self, packet: http.HTTP) -> str:
        ...
    
    def response(self, packet: http.HTTP) -> str:
        ...