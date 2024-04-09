from __future__ import annotations
from abc import ABC, abstractmethod

class Hash(ABC):
    
    @abstractmethod
    def __init__(self):
        super().__init__()
        self.H = []
        self.K = []
        self.digest_val = ''
        self.HASHED_BITS = 0
        self.BLOCK_SIZE = 0
        self.DIGEST_SIZE = 0
        self.MOD = 0
    
    @abstractmethod
    def digest(self, msg):
        pass
    
    @abstractmethod
    def hex_digest(self, msg):
        pass
    
    @abstractmethod
    def update(self):
        pass
    
    @abstractmethod
    def file_digest(self, filename, isBinary):
        pass
    
    def digest_size(self):
        return self.DIGEST_SIZE
    
    @property
    def hashed_bits(self):
        return self.HASHED_BITS
    