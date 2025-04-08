from flask import Flask, render_template, request, jsonify
from modules.shellcode import ShellcodeGenerator
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
        encoding = data.get('encoding', 'base64')
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

            shellcode = shellcode_gen.generate_reverse_shell(host, port)

        elif shellcode_type == 'bind_shell':
            port = data.get('port')
            if not port:
                return jsonify({'error': 'Port is required for bind shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be an integer'}), 400

            shellcode = shellcode_gen.generate_bind_shell(port)

        elif shellcode_type == 'exec':
            command = data.get('command')
            if not command:
                return jsonify({'error': 'Command is required for exec shellcode'}), 400

            shellcode = shellcode_gen.generate_exec(command)

        else:
            return jsonify({'error': 'Invalid shellcode type'}), 400

        if shellcode is None:
            return jsonify({'error': 'Failed to generate shellcode'}), 500

        encoded_shellcode = shellcode_gen.encode_shellcode(shellcode, encoding)

        if encoded_shellcode is None:
            return jsonify({'error': 'Failed to encode shellcode'}), 500

        filename = shellcode_gen.save_shellcode(shellcode)

        return jsonify({
            'success': True,
            'shellcode': encoded_shellcode.decode() if isinstance(encoded_shellcode, bytes) else encoded_shellcode,
            'filename': filename,
            'encoding': encoding
        })

    except Exception as e:
        return jsonify({'error': f'Unexpected server error: {str(e)}'}), 500

@app.route('/decode', methods=['POST'])
def decode_shellcode():
    try:
        data = request.get_json()
        encoded_shellcode = data.get('shellcode')
        encoding = data.get('encoding', 'base64')

        if not encoded_shellcode:
            return jsonify({'error': 'No shellcode provided'}), 400

        shellcode = shellcode_gen.decode_shellcode(encoded_shellcode, encoding)

        if shellcode is None:
            return jsonify({'error': 'Failed to decode shellcode'}), 500

        return jsonify({
            'success': True,
            'shellcode': shellcode.hex()
        })

    except Exception as e:
        return jsonify({'error': f'Unexpected server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
