from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

def prepare_key(key: str) -> bytes:
    key = key.encode('utf-8')
    if len(key) < 16:
        key = key + b'0' * (16 - len(key))
    return key[:16]

def aes_encrypt_cbc(plain_text: str, key: str) -> str:
    key_bytes = prepare_key(key)
    iv = os.urandom(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode('utf-8')

def aes_decrypt_cbc(encrypted_b64: str, key: str) -> str:
    key_bytes = prepare_key(key)
    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode('utf-8')

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt_post():
    data = request.get_json()
    message = data.get('message', '')
    key = data.get('key', '')
    try:
        encrypted = aes_encrypt_cbc(message, key)
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt_post():
    data = request.get_json()
    encrypted = data.get('encrypted', '')
    key = data.get('key', '')
    try:
        decrypted = aes_decrypt_cbc(encrypted, key)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)})
app = Flask(__name__)

# Şifreleme fonksiyonları


@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    try:
        encrypted = aes_encrypt_cbc(data['message'], data['key'])
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    try:
        decrypted = aes_decrypt_cbc(data['encrypted'], data['key'])
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)})
        

# Ana sayfa
@app.route('/')
def ana_sayfa():
    return render_template('index_Version13.html')

# Şifreleme endpoint'i
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    try:
        encrypted = aes_encrypt(data['message'], data['key'])
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)})

# Deşifre endpoint'i
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    try:
        decrypted = aes_decrypt(data['encrypted'], data['key'])
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':

    app.run(debug=True)

