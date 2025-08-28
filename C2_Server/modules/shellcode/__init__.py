"""
Shellcode generation and injection module
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shellcode_generator import ShellcodeGenerator

__all__ = ['ShellcodeGenerator'] 