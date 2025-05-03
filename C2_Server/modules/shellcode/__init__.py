"""Shellcode generation and injection module"""
from .generator import ShellcodeGenerator
from .injector import inject_shellcode

__all__ = ['ShellcodeGenerator', 'inject_shellcode'] 