import argparse
from ecdsa import SigningKey, VerifyingKey, NIST192p
from pathlib import Path
import ecdsa as ed
import hashlib
from ellipticcurve.ecdsa import Ecdsa

parser = argparse.ArgumentParser(
    description="Generate key pairs and e-signature for binary file and appends signature as well")
parser.add_argument("-genkey", type=str,
                    help="Generating public.bin and private.bin files")
parser.add_argument("-Dir", type=str,
                    help="Provide Output path to store files")
parser.add_argument("-Hashgen", type=str,
                    help="Generating Hash value for binary image")
parser.add_argument("-i", type=str,
                    help="Provide Input Binary Image path")
parser.add_argument("-gensign", type=str,
                    help="Generate signature file")
parser.add_argument("-Privatekey", type=str,
                    help="Generate signature file")

parser.add_argument("-verify", type=str,
                    help="Generate signature file")
parser.add_argument("-Publickey", type=str,
                    help="Generate signature file")
args = parser.parse_args()
# Generating Public and Private Key
if args.genkey == "Keypair" and args.Dir != None:
    Prk = SigningKey.generate(curve=NIST192p)  # Generating Private key
    Prk_string = Prk.to_string()
    Puk = Prk.verifying_key  # Generating public key
    Puk_string = Puk.to_string()
    vk2 = VerifyingKey.from_string(Puk_string, curve=NIST192p)
    if Path(args.Dir).is_dir():
        print()
    else:
        Path(args.Dir).mkdir(parents=True, exist_ok=False)
    f = open(args.Dir + "\\Private_key.bin", "wb")  # creating private.bin file
    f.write(Prk_string)
    f.close()

    f1 = open(args.Dir + "\\Public_key.bin", "wb")  # creating public.bin file
    f1.write(Puk_string)
    f1.close()
    print('''INFO:root:*** Generating key-pair. ***
    INFO:root:--- Key-pair successfully generated. ---''')

# Generating Hash Value for Binary image
hash_value = list()

if (args.Hashgen == "hash" and args.i != None) or (args.gensign == "sign"):
    try:
        f2 = open(args.i, "rb")
        data = f2.read()  # read entire file as bytes
        readable_hash = hashlib.sha256(data).hexdigest()
        if args.gensign != "sign":
            print("Hash_value: ", readable_hash)
        hash_value.append(readable_hash)
        f2.close()
    except FileNotFoundError:
        print('File does not exist, Please provide the correct path')

# Generating Signature
if args.gensign == "sign" and args.Dir != None and args.Privatekey != None:
    e_sign = bytes(hash_value[0], "utf-8")  # converting hex to bytes

    f5 = open(args.Privatekey,"rb")
    f6 = f5.read()
    Prk = SigningKey.generate(curve=NIST192p)
    print(type(Prk))
    Prk1 = SigningKey.from_string(string=f6)  # REGenerates priva
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print(Prk1)
    print("***************************************8")
    signature = Prk1.sign(e_sign)  # takes input as bytes
    L = signature.hex()
    if Path(args.Dir).is_dir():
        print()
    else:
        Path(args.Dir).mkdir(parents=True, exist_ok=False)
    f2 = open(args.Dir + "\\Signature.bin", "w")
    f2.write(L)
    f2.close()
    print("Signature is Generated ")


# # Verification
# if args.verify == "Verify"
# Verify = Puk.verify(signature, e_sign)
# if Verify == True:
#     print("Ok, Verified")
# print("Verification is Done ")
