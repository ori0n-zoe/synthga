
import multiprocessing, time, logging
from secrets import token_bytes
from coincurve import PublicKey
from sha3 import keccak_256


item_types = ['WEAPON', 'CHEST', 'HEAD', 'WAIST', 'FOOT', 'HAND', 'NECK', 'RING']

difficulty = 8           # set this to 8 to find a snyth GA for all 8 items
numworkers = 22
numiter = int(1e20)      # set this to an infinite number to search forever or a small # to see 
                         # the rate you search at

logpath = "./found.txt"

def check_addr(addr):
    suffix = None
    for item_type in item_types[:difficulty]:
        b = bytes(item_type, 'utf-8') + addr
        rand = int.from_bytes(keccak_256(b).digest(), 'big', signed=False)
        greatness = rand % 21
        if greatness > 14:
            if suffix is not None:
                suffix_new = rand % 16 + 1
                if suffix_new != suffix:
                    return False
            else:
                suffix = rand % 16 + 1
        else:
            return False
    return True

def worker():
    for i in range(numiter):
        private_key = keccak_256(token_bytes(64)).digest()
        public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
        addr = keccak_256(public_key).digest()[-20:]
        if(check_addr(addr)):
            info =\
f"""
difficulty : {difficulty}
private key: {private_key.hex()}
eth addr   : {addr.hex()}
"""
            print(info)
            with open(logpath,'a') as f:
                f.write(info)

if __name__ == '__main__':
    jobs = []
    beg = time.time()
    for i in range(numworkers):
        p = multiprocessing.Process(target=worker)
        jobs.append(p)
        p.start()
    for j in jobs:
        j.join()
    print(f'searched {numworkers*numiter/(time.time()-beg)} wallets / second')
