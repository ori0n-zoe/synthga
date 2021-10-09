
import multiprocessing, time, logging
from secrets import token_bytes
from coincurve import PublicKey
from sha3 import keccak_256


item_types = ['WEAPON', 'CHEST', 'HEAD', 'WAIST', 'FOOT', 'HAND', 'NECK', 'RING']
item_types_b = [bytes(item_type, 'utf-8') for item_type in item_types]

difficulty = 8        # set this to 8 to find a snyth GA for all 8 items
numworkers = 22       # number of processes to 
numiter = int(1e20)   # set this to an infinite number to search forever or a small # to see 
                      # the rate you search at

reportat = int(1e7)   # worker #000 will print to console

logpath = "./found.txt"

def check_addr(addr):
    suffix = None
    for item_type in item_types_b[:difficulty]:
        rand = int.from_bytes(keccak_256(item_type+addr).digest(), 'big', signed=False)
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
    name = multiprocessing.current_process().name
    for i in range(numiter):
        if i % reportat == 0 and name == '000':
            print(f'worker {name}: {i*numworkers:,.0f}')
        private_key = keccak_256(token_bytes(32)).digest()
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
        p = multiprocessing.Process(target=worker, name=str(i).zfill(3))
        jobs.append(p)
        p.start()
    for j in jobs:
        j.join()
    print(f'searched {numworkers*numiter/(time.time()-beg)} wallets / second')
