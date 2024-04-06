from hashed.sha256 import SHA256
import pytest

def test_sha256_digest():
    # Create an instance of SHA256
    hasher = SHA256()
    
    # Test digest method with a string input
    result = hasher.digest('Hello, world!')
    assert result == b'1_[\xdbv\xd0x\xc4;\x8a\xc0\x06NJ\x01da+\x1f\xcew\xc8i4[\xfc\x94\xc7X\x94\xed\xd3'
    
    # Test hex_digest method with a string input
    result_hex = hasher.hex_digest('Hello, world!')
    assert result_hex == '315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3'
    
    # Test file_digest method with a file containing a string
    filename = 'test/test_file.txt'
    with open(filename, 'w') as f:
        f.write('This is a test file.')
    
    result_file = hasher.file_digest(filename, isBinary=False)
    assert result_file == 'f29bc64a9d3732b4b9035125fdb3285f5b6455778edca72414671e0ca3b2e0de'


def test_digest_with_non_bytearray():
    sha256 = SHA256()
    msg = 123  # Invalid input, not a string or bytearray
    
    with pytest.raises(TypeError) as e:
        sha256.digest(msg)
    
    assert str(e.value) == "Invalid message type"
    
    with pytest.raises(TypeError) as e:
        sha256.hex_digest(msg)
    
    assert str(e.value) == "Invalid message type"