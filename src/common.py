def right_rotate(num, val, size = 32):
    return num >> val | num << (size - val)

def right_shift(num, val):
    return num >> val

def string_to_binary(msg):
    binary = []
    for ch in msg:
        binary.append(bin(ord(ch))[2:].zfill(8))
    return ''.join(binary)

def binaries_to_binary_string(binary_data):
    binary_string = ''.join(format(byte, '08b') for byte in binary_data)
    return binary_string

def create_blocks(binary_string, block_size = 512):
    blocks = []
    for i in range(0, len(binary_string), block_size):
        blocks.append(binary_string[i : i + block_size])
    return blocks

def string_to_int(binary_str):
    return int(binary_str, 2)
