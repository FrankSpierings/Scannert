import subprocess
import xml.etree.ElementTree as ET
import logging
import os, stat
import common

logger = logging.getLogger(__name__)

__DEFAULT_SCRIPTS = 'all and (not broadcast and not dos and not external and not fuzzer) and not http-slowloris-check'
__NMAP_PASSDB     = '/usr/share/nmap/nselib/data/passwords.lst'

def scan_tcp_ports(target, ports='-', path='/tmp'):
    output='{0}/nmap__{1}__tcp_ports'.format(path, common.target_to_filename(target))
    cmdline = 'nmap -T4 -sT -Pn -p "{ports}" -sV -oA "{output}" --reason ' \
              '--open --traceroute --max-retries 1 -d -v {target}' \
              .format(ports=ports, output=output, target=target)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_tcp_services(target, ports='-', path='/tmp', scripts=__DEFAULT_SCRIPTS, passdb=None):
    output='{0}/nmap__{1}__tcp_services'.format(path, common.target_to_filename(target))
    scriptargs_array = []
    if (passdb):
        scriptargs_array += ['passdb={0}'.format(passdb)]
    scriptargs = ','.join(scriptargs_array)
    cmdline = 'nmap -T4 -sT -Pn -p "{ports}" -sV --script "{scripts}" '\
              '--script-args="{scriptargs}" -oA "{output}" --reason --open ' \
              '--traceroute -O -d -v {target}' \
              .format(ports=ports, scripts=scripts, scriptargs=scriptargs, output=output, target=target)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_udp_ports(target, ports='-', topports=None, path='/tmp'):
    output='{0}/nmap__{1}__udp_ports'.format(path, common.target_to_filename(target))
    if (topports):
        cmdline = 'nmap -T4 -sU -Pn --top-ports {topports} -sV -oA "{output}" '\
                  '--reason --open --min-rate 500 --max-retries 1 -d -v {target}' \
                  .format(topports=topports, output=output, target=target)
    else:
        cmdline = 'nmap -T4 -sU -Pn -p "{ports}" -sV -oA "{output}" '\
                  '--reason --open --min-rate 500 --max-retries 1 -d -v {target}'\
                  .format(ports=ports, output=output, target=target)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_udp_services(target, ports='-', topports=None, path='/tmp', scripts=__DEFAULT_SCRIPTS, passdb=None):
    output='{0}/nmap__{1}__udp_services'.format(path, common.target_to_filename(target))
    scriptargs_array = []
    if (passdb):
        scriptargs_array += ['passdb={0}'.format(passdb)]
    scriptargs = ','.join(scriptargs_array)

    if (topports):
        cmdline = 'nmap -T4 -sU -Pn --top-ports {topports} '\
                  '-sV -oA "{output}" --reason '\
                  '--script "{scripts}" --script-args="{scriptargs}" '\
                  '--open --min-rate 500 --max-retries 1 -d -v {target}'\
                  .format(topports=topports, output=output, scripts=scripts,\
                          scriptargs=scriptargs, target=target)
    else:
        cmdline = 'nmap -T4 -sU -Pn -p "{ports}" '\
                  '-sV -oA "{output}" --reason '\
                  '--script "{scripts}" --script-args="{scriptargs}" '\
                  '--open --min-rate 500 --max-retries 1 -d -v {target}'\
                  .format(ports=ports, output=output, scripts=scripts,\
                          scriptargs=scriptargs, target=target)

    logging.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    xml = output + ".xml" 
    return parse_ports(xml)

def scan_whois(target, path='/tmp'):
    output='{0}/nmap__{1}__whois'.format(path, common.target_to_filename(target))
    cmdline = 'nmap -T4 -Pn -sn -oA "{output}" '\
              '--script "whois-domain,whois-ip" --script-args="whodb=arin+ripe+afrinic" '\
              '-d -v {target}'\
              .format(output=output, target=target)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)

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
    logger.debug("Parsed ports: {0}".format(result))
    return result

def prepare_passwords(out_file, my_password_file, use_native=True):
    mypasswords = []
    
    if (use_native==True):
        nmap_passwords = []
        with open(__NMAP_PASSDB) as f:
            l = f.read().split('\n')
            #Remove comments.
            nmap_passwords = [i for i in l if (len(i) > 0 and i[0]!='#')]
    else:
        nmap_passwords=[]
        
    with open(my_password_file) as f:
        l = f.read().split('\n')
        #Remove comments.
        mypasswords = [i for i in l if (len(i) > 0 and i[0]!='#')]

    passwords = sorted(set(nmap_passwords + mypasswords))
    logger.debug('Writing {nr_passwords} passwords to {out_file}'\
                 .format(nr_passwords=len(passwords), out_file=out_file))
    fd = os.open(out_file, os.O_WRONLY|os.O_CREAT, stat.S_IWUSR|stat.S_IRUSR)
    os.write(fd, ('\n'.join(passwords)))
    os.write(fd, '\n')
    os.close(fd)