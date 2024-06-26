from hashed.hash_lib import HashLib
import pytest

def test_sha512_digest():
    # Create an instance of SHA512
    hasher = HashLib('sha512').hasher_class()
    
    # Test digest method with a string input
    result = hasher.digest('Hello, world!')
    assert result == b'\xc1R|\xd8\x93\xc1$w=\x81\x19\x11\x97\x0c\x8f\xe6\xe8W\xd6\xdf]\xc9"k\xd8\xa1`aL\x0c\xd9c\xa4\xdd\xea+\x94\xbb}6\x02\x1e\xf9\xd8e\xd5\xce\xa2\x94\xa8-\xd4\x9a\x0b\xb2i\xf5\x1fnzW\xf7\x94!'
    assert hasher.digest_size() == 64
    assert hasher.hashed_bits == 128
    
    # Test hex_digest method with a string input
    result_hex = hasher.hex_digest('Hello, world!')
    assert result_hex == 'c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421'
    
    # Test file_digest method with a file containing a string
    filename = 'test/test_file.txt'
    with open(filename, 'w') as f:
        f.write('This is a test file.')
    
    result_file = hasher.file_digest(filename, isBinary=False)
    assert result_file == 'b1df216b5b05e3965c469492744a5de0c945e0b103c42eb1e57476fbed8f1d489f5cae9b792db37c5d823bc0c6c7d06b056176d6abe5ce076eeadaed414e17a3'

    # Test file_digest method with a file containing image - binary
    filename = 'test/WALDON-LIVING-ROOM.jpg'
    result_file = hasher.file_digest(filename, isBinary=True)
    assert result_file == '3788312ce602fa9ec4b8ed2a6592b1750afc093e0fabf1acce9d088a299cf73658d89a7508d4ba0d8bb700896b1afa19beb29e5dd3f9b1cfe21d2b518e6428bc'
    
    # Invalid input
    msg = 123  # Invalid input, not a string or bytearray
    
    with pytest.raises(TypeError) as e:
        hasher.digest(msg)
    
    assert str(e.value) == "Invalid message type"
    
    with pytest.raises(TypeError) as e:
        hasher.hex_digest(msg)
    
    assert str(e.value) == "Invalid message type"