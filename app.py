from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

def prepare_key(key: str) -> bytes:
    """"Girilen key'i 16 byte'a tamamlar."""
    key = key.encode('utf-8')
    if len(key) < 16:
        key = key + b'0' * (16 - len(key))
    return key[:16]

def aes_encrypt_cbc(plain_text: str, key: str) -> str:
    """"CBC modunu kullanarak metni şifreler."""
    key_bytes = prepare_key(key)
    iv = os.urandom(16)  # rastgele bir başlatma vektörü (IV) oluştur
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    # IV ve şifreli metni birleştirerek gönder
    return base64.b64encode(iv + encrypted_text).decode('utf-8')

def aes_decrypt_cbc(encrypted_b64: str, key: str) -> str:
    """CBC modunu kullanarak metni deşifreler."""
    key_bytes = prepare_key(key)
    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]  # Başlatma vektörünü (IV) ayıklayın
    encrypted_text = encrypted_data[16:]  # Şifreli metni ayıklayın
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(encrypted_text)
    decrypted_text = unpad(decrypted_padded_text, AES.block_size)
    return decrypted_text.decode('utf-8')

@app.route('/')
def ana_sayfa():
    """Ana sayfayı göster."""
    return render_template('index_Version13.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_post():
    """POST isteğiyle gelen mesajı şifreler."""
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
    """POST isteğiyle gelen şifreli mesajı deşifreler."""
    data = request.get_json()
    encrypted = data.get('encrypted', '')
    key = data.get('key', '')
    try:
        decrypted = aes_decrypt_cbc(encrypted, key)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)

