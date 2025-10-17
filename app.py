from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# Şifreleme fonksiyonları
def aes_encrypt(plain_text, key):
    key = key.encode('utf-8')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plain_text.encode('utf-8'), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    key = key.encode('utf-8')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted = unpad(cipher.decrypt(encrypted_bytes), 16)
    return decrypted.decode('utf-8')

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