target=10.10.10.10

ports=$(nmap -p- --min-rate=1000 -T4 $target | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

nmap -p$ports -sC -sV $target
