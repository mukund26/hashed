import argparse
from hash_lib import HashLib
import time

def setup_args():
    parser = argparse.ArgumentParser(
                    prog='Hashing Library',
                    description='Provides secured hashes for given data',
                    epilog='Currently supported hashes [SHA256, SHA512]',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("--sha256", action='store_true', help="Generates SHA-256 for given input")
    parser.add_argument("--sha512", action='store_true', help="Generates SHA-512 for given input")
    parser.add_argument("-s", "--string", help="String to be hashed")
    parser.add_argument("-f", "--file", help="File to be hashed")
    parser.add_argument("-fb", "--binary_file", help='Binary file to be hashed')
    parser.add_argument("-t", "--test", action='store_true', help='Test accuracy of algorithm')
    parser.add_argument("-p", "--perf", action='store_true', help='Log performance of the algorithm')
    parser.add_argument("-b", "--bits", action='store_true', help='Returns size of hashed message in bytes')
    return parser


if __name__ == '__main__':
    parser = setup_args()
    args = vars(parser.parse_args())
    
    if args['sha256']:
        start_time = time.time()
        h = HashLib('sha256').hasher_class()
        if args['string']:
            print('Hash: ', h.hex_digest(args["string"]))
            end_time = time.time()
        if args['file']:
            print('Hash: ', h.file_digest(args["file"], False))
            end_time = time.time()
        if args['binary_file']:
            print('Hash: ', h.file_digest(args['binary_file'], True))
            end_time = time.time()
        if args['bits']:
            print("Bytes Hashed: ", h.hashed_bits/8)
        if args['perf']:
            print(f'Time Taken: {end_time - start_time} seconds')
            
    elif args['sha512']:
        start_time = time.time()
        h = HashLib('sha512').hasher_class()
        if args['string']:
            print('Hash: ', h.hex_digest(args["string"]))
            end_time = time.time()
        if args['file']:
            print('Hash: ', h.file_digest(args["file"], False))
            end_time = time.time()
        if args['binary_file']:
            print('Hash: ', h.file_digest(args['binary_file'], True))
            end_time = time.time()
        if args['bits']:
            print("Bytes Hashed: ", h.hashed_bits/8)
        if args['perf']:
            print(f'Time Taken: {end_time - start_time} seconds')
            
    else:
        parser.print_help()