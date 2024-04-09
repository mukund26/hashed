import os

def right_rotate(num, val, size = 32):
    return num >> val | num << (size - val)

def right_shift(num, val):
    return num >> val

def get_file_size(file_path):
        size = os.path.getsize(file_path)
        return size

def read_string_msg(msg):
    if isinstance(msg, str):
        return bytearray(msg, 'ascii')
    elif not isinstance(msg, bytearray):
        raise TypeError("Invalid message type")
     