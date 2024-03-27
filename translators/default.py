from .translator import *

class DefaultTranslator(TranslatorInterface):
    def __init__(self) -> None:
        ...

    def request(self, packet: http.HTTP) -> str:
        # load = parse.parse_qs(packet.load)
        # return '\n'.join([f'{k}: {v}' for k, v in load.items()])
        return parse.unquote(packet.load)
    
    def response(self, packet: http.HTTP) -> str:
        return parse.unquote(packet.load)