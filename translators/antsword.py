from .translator import *
from urllib import parse
import itertools
import click
import base64

ENCODER_NAMES = ['default', 'base64']
DECODER_NAMES = ['default', 'base64']
SAMPLE_NUMBER = 10

def decoder_base64(x: str):
    rst = ''
    for i, j in itertools.product(range(2, 16), repeat=2):
        try:
            rst = base64.b64decode(x[i:-j]).decode()
            break
        except:
            ...
    return rst

encoders = {
    'default': lambda x: x,
    'base64': lambda x: base64.b64decode(x).decode(),
}

decoders = {
    'default': lambda x: x,
    'base64': decoder_base64,
}

class AntSwordTranslator(TranslatorInterface):
    password: str
    encoder: str
    decoder: str
    def __init__(self, password: str, 
                 encoder: click.Choice(ENCODER_NAMES, case_sensitive=False),
                 decoder: click.Choice(DECODER_NAMES, case_sensitive=False)):
        self.password = password
        self.encoder = encoder
        self.decoder = decoder

    def request(self, packet: http.HTTP) -> str:
        load = parse.parse_qs(packet.load)
        pass_arg = load.get(self.password, [''])
        main_arg = max((val[0].decode() for val in load.values() if len(val) == 1),
                       key=len
                    )
        return encoders[self.encoder](main_arg)
    
    def response(self, packet: http.HTTP) -> str:
        return decoders[self.decoder](packet.load)