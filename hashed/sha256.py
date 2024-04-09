import os
from hashed.hash import Hash
from hashed.common import get_file_size, read_string_msg, right_rotate, right_shift

class SHA256(Hash):
    
    def __init__(self):
        super().__init__()
        self.set_H()
        self.K =  [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.MOD = 0xFFFFFFFF
        self.BLOCK_SIZE = 512
        self.HASHED_BITS = 0
        self.DIGEST_SIZE= 32
        
        
    def set_H(self): 
        self.H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
    
    def add_padding(self, binary_data, length = 0):
        orig_len = len(binary_data) * 8  # Length in bits
        binary_data.append(0x80)  # Append 1 bit  
        no_of_zeros = ((self.BLOCK_SIZE - (len(binary_data) * 8 + 64) % self.BLOCK_SIZE) % self.BLOCK_SIZE) // 8
        binary_data.extend(bytearray(no_of_zeros))
        if length:
            binary_data.extend(length.to_bytes(8, 'big'))
        else:
            binary_data.extend(orig_len.to_bytes(8, 'big'))
        
       
    def create_message_schedule(self, block):
        w = [int.from_bytes(block[i * 4 : i * 4 + 4], 'big') for i in range(0, 16)]
            
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ right_shift(w[i - 15], 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ right_shift(w[i - 2], 10)
            ans = (w[i - 16] + s0 + w[i - 7] + s1) & self.MOD
            w.append(ans)
            
        return w


    def compression(self, w):
        a, b, c, d, e, f, g, h = self.H   
            
        for i in range(0, 64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + self.K[i] + w[i]) & self.MOD
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & self.MOD
            
            h = g
            g = f
            f = e
            e = (d + temp1) & self.MOD
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & self.MOD
            
        self.H = [
            (self.H[0] + a) & self.MOD,
            (self.H[1] + b) & self.MOD,
            (self.H[2] + c) & self.MOD,
            (self.H[3] + d) & self.MOD,
            (self.H[4] + e) & self.MOD,
            (self.H[5] + f) & self.MOD,
            (self.H[6] + g) & self.MOD,
            (self.H[7] + h) & self.MOD
        ]
    
    
    def update(self, binary_data, length = 0, last_chunk = True):
        if last_chunk:
            self.add_padding(binary_data, length)

        assert (len(binary_data) * 8) % self.BLOCK_SIZE == 0
        
        blocks = [binary_data[ i : i + 64 ] for i in range(0, len(binary_data), 64)]
        
        for block in blocks:
            w = self.create_message_schedule(block)
            self.compression(w)
        
        self.HASHED_BITS = length if length else len(binary_data)
        
        
    def digest(self, msg):
        binary_data = read_string_msg(msg)
        self.HASHED_BITS = 0
        self.update(binary_data)
        FINAL_H = self.H
        self.set_H()
        return b''.join(x.to_bytes(4, 'big') for x in FINAL_H)  
        
    
    def hex_digest(self, msg):
        binary_data = read_string_msg(msg)
        self.HASHED_BITS = 0
        self.update(binary_data)
        FINAL_H = self.H
        self.set_H()
        return b''.join(x.to_bytes(4, 'big') for x in FINAL_H).hex()
        
        
    def file_digest(self, filename, isBinary):
        self.HASHED_BITS = 0
        length = get_file_size(filename)
        pos = 0
        with open(filename, 'rb' if isBinary else 'r') as f:
            while True:
                data = f.read(64)
                pos += len(data)
                if not data:
                    break
                byte_data = bytearray(data) if isBinary else bytearray(data, 'ascii')
                last_chunk = pos >= length
                self.update(byte_data, length * 8, last_chunk)
        FINAL_H = self.H
        self.set_H()
        return b''.join(x.to_bytes(4, 'big') for x in FINAL_H).hex()    
            