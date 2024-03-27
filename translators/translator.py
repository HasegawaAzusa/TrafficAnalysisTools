from typing import Protocol
from scapy.layers import http

class TranslatorInterface(Protocol):
    def request(self, packet: http.HTTP) -> str:
        """
        Translate the request packet
        """
        ...
    
    def response(self, packet: http.HTTP) -> str:
        """
        Translate the response packet
        """
        ...
