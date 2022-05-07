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
