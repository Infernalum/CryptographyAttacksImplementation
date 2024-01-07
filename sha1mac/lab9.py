import base64
from sha1 import sha1
import binascii
import requests
import json


# breaks SHA1 hash into 5 32-bit registers
def get_internal_state(sha1_decimal_digest):
    a = sha1_decimal_digest >> 128
    b = (sha1_decimal_digest >> 96) & 0xffffffff
    c = (sha1_decimal_digest >> 64) & 0xffffffff
    d = (sha1_decimal_digest >> 32) & 0xffffffff
    e = sha1_decimal_digest & 0xffffffff
    return [a, b, c, d, e]


# slightly modified copy of padding code from sha1.py
# pads message with (1 + 0s + length of message)
def glue_padding(message):
    length = len(message) * 8
    bytes = ""
    for n in range(len(message)):
        bytes += '{0:08b}'.format(ord(message[n]))
    # append the bit '1' to the message
    bits = bytes + "1"
    pBits = bits
    # pad w '0's until length equals 448 mod 512
    while len(pBits) % 512 != 448:
        pBits += "0"
    # append the length of the message
    pBits += '{0:064b}'.format(length)
    # convert from binary to ASCII
    n = int(pBits, 2)
    return binascii.unhexlify('%x' % n)


# forged_message = "A"*keylen || original message || glue padding || new message
# get_internal_state = breaks original message digest into [5] 32-bit registers
# forged_digest = SHA-1 digest under secret key for our forged message
def forge_message(message, message_digest, keylen, new_message):
    forged_message = glue_padding("A" * keylen + message.decode()) + new_message
    # remove key from our forged message (it's not the correct key anyways)
    forged_message = forged_message[keylen:]

    decimal_digest = int(message_digest, 16)
    h = get_internal_state(decimal_digest)
    # call SHA1 directly with fixated registers & additional data to forge
    forged_digest = sha1(new_message, h[0], h[1], h[2], h[3], h[4], (keylen + len(forged_message)) * 8)

    return (forged_message, forged_digest)


URL = f'http://localhost:8080/api/Sha1Mac/Infernalum/'
COUNTER = 2
HTTP_HEADERS = {'Content-Type': 'application/json'}
MAC_MESSAGE = b'user=Infernalum;'
with requests.Session() as session:
    r = session.get(URL + str(COUNTER) + '/mac')
    message_digest = r.text
    # Перебор длины до 32 как в оригинале результатов не дал, так что ключ явно длиннее
    for i in range(1, 64):
        m, d = forge_message(MAC_MESSAGE, message_digest, i, b';admin=true')
        address = URL + str(COUNTER) + '/' + d + f'/verify'

        encoded = base64.b64encode(m).decode()
        x = session.post(address, data=json.dumps(encoded), headers=HTTP_HEADERS)
        if x.text == 'Wellcome to SecretNet!':
            print('Key length: ', i)
            print('Modified msg: ',base64.b64decode(encoded))
            print(x.text)