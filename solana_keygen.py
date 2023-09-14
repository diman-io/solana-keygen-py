import base58
import ed25519
import hashlib
import hmac
import mnemonic
import struct

BIP32_HARDEN = 0x80000000
ED25519_BIP32_SEED = b'ed25519 seed'
ENGLISH_MNEMONIC = mnemonic.Mnemonic('English')

def extended_key_from_seed(seed):
    hash = hmac.new(ED25519_BIP32_SEED, seed, hashlib.sha512).digest()
    return (hash[:32], hash[32:]) # (secret_key, chain_code)

def extended_key_to_child(secret_key, chain_code, index):
    if index < BIP32_HARDEN: # only for HARDENED
        i = index + BIP32_HARDEN
    else:
        i = index
    data = b'\0' + secret_key + struct.pack(">L", i) 
    hash = hmac.new(chain_code, data, hashlib.sha512).digest()
    return (hash[:32], hash[32:]) # (secret_key, chain_code)

def key_from_seed(seed, path=[44, 501, 0, 0]):
    (secret_key, chain_code) = extended_key_from_seed(seed)
    for index in path:
        (secret_key, chain_code) = extended_key_to_child(secret_key, chain_code, index)
    sk = ed25519.SigningKey(secret_key)
    assert secret_key == sk.to_bytes()[:32]
    return (secret_key, sk.to_bytes()[32:]) 

def key_from_phrase(phrase, path=[44, 501, 0, 0]):
    seed = ENGLISH_MNEMONIC.to_seed(phrase)
    return key_from_seed(seed, path)

def key_from_entropy(entropy, path=[44, 501, 0, 0]):
    phrase = ENGLISH_MNEMONIC.to_mnemonic(entropy)
    return key_from_phrase(phrase, path)
