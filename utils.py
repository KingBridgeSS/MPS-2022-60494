from Crypto.Cipher import AES
from hashlib import md5

default_salt = b'abcde'

BS = 16


def EVP_BytesToKey(password, salt, key_len, iv_len):
    dtot = md5(password + salt).digest()
    d = [dtot]
    while len(dtot) < (iv_len + key_len):
        d.append(md5(d[-1] + password + salt).digest())
        dtot += d[-1]
    return dtot[:key_len], dtot[key_len:key_len + iv_len]


def pad(data):
    padding = BS - len(data) % BS
    return data + (padding * chr(padding)).encode()


def unpad(data):
    return data[0:-data[-1]]


def decrypt(hex_data, password):
    key, iv = EVP_BytesToKey(password, b'', 24, 16)
    data = bytes.fromhex(hex_data)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(data)).decode("u tf-8")


def encrypt(data, password):
    key, iv = EVP_BytesToKey(password, b'', 24, 16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(data)).hex()


def encode_token(uid, plain):
    plain = str(uid) + '|' + plain
    return encrypt(plain.encode(), default_salt)


def decode_token(et):
    de = decrypt(et, default_salt).split('|')[1]
    return de


if __name__ == '__main__':
    # foo   90809dc9677e1a50aebfe4e2d4a95abd
    encrypted = encrypt(b'foo', default_salt)  # str
    print(encrypted)
    decrypted = decrypt(encrypted, default_salt)
    print(decrypted)
