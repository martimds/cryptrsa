import rsa

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(1024)
    with open("chaves/pubkey.pem", "wb") as f:
        f.write(pubKey.save_pkcs1("PEM"))

    with open("chaves/privkey.pem", "wb") as f:
        f.write(privKey.save_pkcs1("PEM"))

def load_keys():
    with open("chaves/pubkey.pem", "rb") as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open("chaves/privkey.pem", "rb") as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode("ascii"), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode("ascii")
    except:
        return False

def sign_sha1(msg, key):
    return rsa.sign(msg.encode("ascii"), key, "SHA-1")

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode("ascii"), signature, key) == "SHA-1"
    except:
        return False

generate_keys()
pubKey, privKey = load_keys()

mensagem = input("Digite uma mensagem: ")
ciphertext = encrypt(mensagem, pubKey)

signature = sign_sha1(mensagem, privKey)

plaintext = decrypt(ciphertext, privKey)

print(f"Texto criptografado: {ciphertext}")
print(f"Assinatura: {signature}")

if plaintext:
    print(f"Texto original: {plaintext}")
else:
    print("Não foi possível descriptografar")

if verify_sha1(plaintext, signature, pubKey):
    print("Assinatura verificada")
else:
    print("Assinatura não pode ser verificada")

