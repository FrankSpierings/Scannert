import subprocess
import re
import xml.etree.ElementTree as ET
import argparse
import string
import os
from selenium import webdriver

SCRIPTS = "all and (not broadcast and not dos and not external and not fuzzer) and not http-slowloris-check"
NMAP_CUSTOM_PASSWORDS = '/tmp/nmap_passwords.txt'

def parse_ports(nmap_xml_file):
    result = {}
    try:
        xml = ET.parse(nmap_xml_file)
    except:
        return result
    ports = xml.findall('.//ports/port')
    for port in ports:
        portid = port.attrib['portid']
        service = ''
        ssl = False
        try:
            if (port.find('.//state').attrib['state'] == 'open'):
                try:
                    service = port.find('.//service').attrib['name']
                except:
                    pass
                try:        
                    if (port.find('.//service').attrib['tunnel'] == 'ssl'):
                        ssl = True
                except:
                    pass
                result[portid] = {}
                result[portid]['service'] = service
                result[portid]['ssl'] = ssl
        except:
            pass
    print "[+] Parseports: %s" % repr(result)
    return result

def nmap_prepare_passwords(out_file, nmap_password_file='/usr/share/nmap/nselib/data/passwords.lst', my_password_file='/home/frank/Passwords/custom.lst'):
    mypasswords = []
    nmap_passwords = []
    with open(nmap_password_file) as f:
        l = f.read().split('\n')
        #Remove comments.
        nmap_passwords = [i for i in l if (len(i) > 0 and i[0]!='#')]
        
    with open(my_password_file) as f:
        l = f.read().split('\n')
        #Remove comments.
        mypasswords = [i for i in l if (len(i) > 0 and i[0]!='#')]

    passwords = sorted(set(nmap_passwords +  mypasswords))
    with open(out_file, 'w') as f:
        f.write('\n'.join(passwords))
        f.write('\n')

def screenshot_http(target, port, ssl=False, path='/tmp'):
    output='%s/screenshot_http__%s_%s.png' % (path, target_to_filename(target), port)
    if (ssl==True):
        url='https://'
    else:
        url='http://'
    url += "%s:%s/" % (target, port)
    print "[+] Screenshot '%s'" % url
    try:
        driver = webdriver.Firefox()
    except:
        print "[!] Could not instantiate Selenium for Firefox"
    try:
        driver.get(url)
    except:
        print "[!] Could not browse to given url; %s" % url
    try:
        driver.save_screenshot(output)
    except:
        print "[!] Could not screenshot given url; %s" % url
        url = 'view-source:%s' % url 
        print "[+] Trying view-source variant url; %s" % url
        try:
            driver.get(url)
            driver.save_screenshot(output)
        except:
            print "[!] Even that failed... going home.."
    try:
        driver.close();
    except:
        pass
def scan_nikto_http(target, port, ssl=False, path='/tmp'):
    output='%s/nikto__%s_%s' % (path, target_to_filename(target), port)
    if (ssl==True):
        cmdline = "nikto -Format txt -output %s -Save %s -ssl -host %s:%s" % (output, path, target, port)
    else:
        cmdline = "nikto -Format txt -output %s -Save %s -host %s:%s" % (output, path, target, port)        
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)

def target_to_filename(target):
    return re.sub('[^a-zA-Z0-9-_.]', '', target)

def scan_tcp_ports(target, ports='-', path='/tmp'):
    output='%s/nmap__%s__tcp_ports' % (path, target_to_filename(target))
    cmdline = 'nmap -T5 -sT -Pn -p "%s" -sV -oA "%s" --reason --open --traceroute --max-retries 1 -d -v %s' \
              % (ports, output, target)
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_tcp_services(target, ports='-', path='/tmp', scripts=SCRIPTS):
    output='%s/nmap__%s__tcp_services' % (path, target_to_filename(target))
    cmdline = 'nmap -T4 -sT -Pn -p "%s" -sV --script "%s" --script-args="passdb=%s" -oA "%s" --reason --open --traceroute -O -d -v %s' \
              % (ports, scripts, NMAP_CUSTOM_PASSWORDS, output, target)
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_udp_ports(target, ports='-', topports=None, path='/tmp'):
    output='%s/nmap__%s__udp_ports' % (path, target_to_filename(target))
    if (topports is None):
        cmdline = 'nmap -T5 -sU -Pn -p "%s" -sV -oA "%s" --reason --open --min-rate 500 --max-retries 1 -d -v %s' \
                  % (ports, output, target)
    else:
        cmdline = 'nmap -T5 -sU -Pn --top-ports %s -sV -oA "%s" --reason --open --min-rate 500 --max-retries 1 -d -v %s' \
                  % (topports, output, target)
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_udp_services(target, ports='-', topports=None, path='/tmp', scripts=SCRIPTS):
    output='%s/nmap__%s__udp_services' % (path, target_to_filename(target))
    if (topports is None):
        cmdline = 'nmap -T4 -sU -Pn -p "%s" -sV -oA "%s" --script "%s" --script-args="passdb=%s" --reason --open --min-rate 500 --max-retries 1 -d -v %s' \
                  % (ports, output, scripts, NMAP_CUSTOM_PASSWORDS, target)
    else:
        cmdline = 'nmap -T4 -sU -Pn --script "%s" --script-args="passdb=%s" --top-ports %s -sV -oA "%s" --reason --open --min-rate 500 --max-retries 1 -d -v %s' \
                  % (ports, output, scripts, NMAP_CUSTOM_PASSWORDS, target)                 
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_whois(target, path='/tmp'):
    output='%s/nmap__%s__whois' % (path, target_to_filename(target))
    cmdline = 'nmap -T5 -Pn -sn -oA "%s" --script "whois-domain,whois-ip" --script-args "whodb=arin+ripe+afrinic" -d -v %s' \
              % (output, target)
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)

def scan_tls(target, port=443, path='/tmp'):
    output = '%s/testssl__%s_%s' % (path, target_to_filename(target), port)
    cmdline = '/usr/local/share/testssl.sh/testssl.sh' \
              ' --openssl /usr/local/share/testssl.sh/bin/openssl.Linux.x86_64' \
              ' --wide --color 0' \
              ' --logfile=%s' \
              ' %s:%s' % (output, target, port)
    print "[+] Command: %s" %(cmdline)
    #subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(cmdline, shell=True)

def scan_arachni_http(target, port, ssl=False, path='/tmp'):
    output1='%s/arachni__%s_%s.bin' % (path, target_to_filename(target), port)
    output2='%s/arachni__%s_%s.html.zip' % (path, target_to_filename(target), port)
    if (ssl==True):
        cmdline = "arachni https://%s:%s --report-save-path %s" % (target, port, output1)
    else:
        cmdline = "arachni http://%s:%s --report-save-path %s" % (target, port, output1)
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)
    cmdline = "arachni_reporter %s --reporter=html:outfile=%s" %(output1, output2)    
    print "[+] Command: %s" %(cmdline)
    subprocess.call(cmdline, shell=True)

#Orchestration of a scan
def scan(target, path='/tmp'):
    if not os.path.exists(path):
            os.makedirs(path)

    nmap_path = os.path.join(path, 'nmap')
    if not os.path.exists(nmap_path):
            os.makedirs(nmap_path)

    testssl_path = os.path.join(path, 'testssl')
    if not os.path.exists(testssl_path):
            os.makedirs(testssl_path)

    screenshot_path = os.path.join(path, 'screenshots')
    if not os.path.exists(screenshot_path):
            os.makedirs(screenshot_path)

    nikto_path = os.path.join(path, 'nikto')
    if not os.path.exists(nikto_path):
            os.makedirs(nikto_path)

    arachni_path = os.path.join(path, 'arachni')
    if not os.path.exists(arachni_path):
            os.makedirs(arachni_path)

    #Prepare custom nmap passwords
    nmap_prepare_passwords(NMAP_CUSTOM_PASSWORDS)

    #WHOIS
    scan_whois(target, path=nmap_path)

    #TCP scan
    resultports = scan_tcp_ports(target, path=nmap_path)
    sslports = [p for p in resultports if resultports[p]['ssl']==True]

    #TLS Scan
    for port in sslports:
        scan_tls(target, port=port, path=testssl_path)
    
    #TCP service scan
    ports = string.join(resultports, ',')
    resultports = scan_tcp_services(target, ports=ports, path=nmap_path)
    serviceports = resultports

    #HTTP(S) Screenshots
    httpports = [p for p in serviceports if 'http' in serviceports[p]['service']]
    for port in httpports:
        screenshot_http(target, port=port, ssl=serviceports[port]['ssl'], path=screenshot_path)

    #UDP scan
    resultports = scan_udp_ports(target, topports=100, path=nmap_path)
    
    #UDP service scan
    ports = string.join(resultports, ',')
    resultports = scan_udp_services(target, ports=ports, path=nmap_path)

    #Nikto http scan
    httpports = [p for p in serviceports if 'http' in serviceports[p]['service']]
    for port in httpports:
        scan_nikto_http(target, port=port, ssl=serviceports[port]['ssl'], path=nikto_path)

    #Arachni http scan
    httpports = [p for p in serviceports if 'http' in serviceports[p]['service']]
    for port in httpports:
        scan_arachni_http(target, port=port, ssl=serviceports[port]['ssl'], path=arachni_path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='hosts input file', default=None)
    parser.add_argument('-t', '--target', help='single target', default=None)
    parser.add_argument('-d', '--destination', help='destination directory', default='/tmp')
    args = parser.parse_args()

    if (args.file):
        with open(args.file, 'r') as f:
            content = f.readlines()
        for line in content:
            target = re.sub('[\r\n]','',line)
            scan(target, args.destination)
    else:
        scan(args.target, args.destination)

if __name__ == "__main__":
    main()