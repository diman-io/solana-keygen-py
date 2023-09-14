import base58
import solana_keygen

mnemonic = "issue shiver before yard minor casual bone puzzle craft reflect wise adapt"
path = [44, 501, 0, 0]

private_key, public_key = solana_keygen.key_from_phrase(mnemonic, path)
address = base58.b58encode(public_key).decode()
print(address)
print([b for b in private_key + public_key])
