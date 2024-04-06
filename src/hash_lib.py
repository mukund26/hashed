from sha256 import SHA256
from sha512 import SHA512

class HashLib():
    
    def __init__(self, digest_algo):
        if digest_algo == 'sha256':
            self.hasher = SHA256()
        elif digest_algo == 'sha512':
            self.hasher = SHA512()
            
    def hasher_class(self):
        return self.hasher