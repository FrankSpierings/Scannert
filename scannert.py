import re
import argparse
import os
import netaddr

import modules.dns as dns
import modules.nmap as nmap
import modules.screenshot as screenshot
import modules.testssl as testssl
import modules.nikto as nikto
import modules.arachni as arachni

import logging
logger = logging.getLogger()


__CUSTOM_PASSWORDS_DB  = '/tmp/nmap_passwords'
__MY_CUSTOM_PASSWORDS  = '/home/frank/Passwords/custom.lst'


#Orchestration of a scan
def orchestrate_scan(target, path='/tmp', disabled_features=[]):
    if not os.path.exists(path):
            os.makedirs(path)

    nmap_path = os.path.join(path, 'nmap')
    if not os.path.exists(nmap_path):
            os.makedirs(nmap_path)


    #Prepare custom nmap passwords
    nmap.prepare_passwords(__CUSTOM_PASSWORDS_DB, __MY_CUSTOM_PASSWORDS)

    #DNS
    if not ('no_dns' in disabled_features):
        dns_path = os.path.join(path, 'dns')
        if not os.path.exists(dns_path):
            os.makedirs(dns_path)
        dns.scan(target, path=dns_path)

    #WHOIS
    if not ('no_whois' in disabled_features):
        nmap.scan_whois(target, path=nmap_path)

    #TCP scan
    dict_result_ports = nmap.scan_tcp_ports(target, path=nmap_path)
    dict_tcp_ports    = dict_result_ports

    #Retrieve sslports and httpports from result
    sslports  = [p for p in dict_tcp_ports if dict_tcp_ports[p]['ssl']==True]
    httpports = [p for p in dict_tcp_ports if 'http' in dict_tcp_ports[p]['service']]

    #TLS Scan
    if not ('no_ssl' in disabled_features):
        testssl_path = os.path.join(path, 'testssl')
        if not os.path.exists(testssl_path):
            os.makedirs(testssl_path)
        for port in sslports:
            testssl.scan(target, port=port, path=testssl_path)
    
    #TCP service scan
    if not ('no_tcp_services' in disabled_features):
        ports = ",".join(dict_result_ports)
        dict_result_ports = nmap.scan_tcp_services(target, ports=ports, path=nmap_path, 
                                             passdb=__CUSTOM_PASSWORDS_DB)
        serviceports = dict_result_ports

    #HTTP(S) Screenshots
    if not ('no_screenshots' in disabled_features):
        screenshot_path = os.path.join(path, 'screenshots')
        if not os.path.exists(screenshot_path):
            os.makedirs(screenshot_path)
        for port in httpports:
            screenshot.browser_target_port(target, port=port, 
                                           ssl=dict_tcp_ports[port]['ssl'], 
                                           path=screenshot_path)
    #UDP scan
    if not ('no_udp' in disabled_features):
        dict_result_ports = nmap.scan_udp_ports(target, topports=100, path=nmap_path)
        dict_udp_ports    = dict_result_ports
    
        #UDP service scan
        if not ('no_udp_service' in disabled_features):
            ports = ",".join(dict_udp_ports)
            dict_result_ports = nmap.scan_udp_services(target, ports=ports, path=nmap_path, 
                                            passdb=__CUSTOM_PASSWORDS_DB)
            dict_udp_services_ports = dict_result_ports

    #Nikto http scan
    if not ('no_nikto' in disabled_features):
        nikto_path = os.path.join(path, 'nikto')
        if not os.path.exists(nikto_path):
                os.makedirs(nikto_path)

        for port in httpports:
            nikto.scan(target, port=port, ssl=dict_tcp_ports[port]['ssl'], path=nikto_path)

    #Arachni http scan
    if not ('no_arachni' in disabled_features):
        arachni_path = os.path.join(path, 'arachni')
        if not os.path.exists(arachni_path):
                os.makedirs(arachni_path)

        for port in httpports:
            arachni.scan(target, port=port, ssl=dict_tcp_ports[port]['ssl'], path=arachni_path)

def main():
    __setup_logger()
    args = __setup_arguments()

    disabled_features = y = [k for k,v in vars(args).items() if k.startswith('no_') and v==True]

    if (args.file):
        with open(args.file, 'r') as f:
            content = f.readlines()
        for line in content:
            target = re.sub('[\r\n]','',line)
            orchestrate_scan(target, args.path, disabled_features)
    elif(args.range):
        net = netaddr.IPNetwork(args.range)
        logger.info('Range is {0:d} hosts large'.format(net.size))
        for ipv4 in net.iter_hosts():
            target = str(ipv4)
            orchestrate_scan(target, args.path, disabled_features)
    elif (args.target):
        orchestrate_scan(args.target, args.path, disabled_features)
    else:
        raise NotImplementedError('Choose another weapon')

def __setup_logger():
    logging.addLevelName(logging.DEBUG,   '\033[1;34m{0}\033[1;0m'.format(logging.getLevelName(logging.DEBUG)))
    logging.addLevelName(logging.WARNING, '\033[1;33m{0}\033[1;0m'.format(logging.getLevelName(logging.WARNING)))
    logging.addLevelName(logging.ERROR,   '\033[1;31m{0}\033[1;0m'.format(logging.getLevelName(logging.ERROR)))
    logging.addLevelName(logging.CRITICAL,'\033[1;41m{0}\033[1;0m'.format(logging.getLevelName(logging.CRITICAL)))
    logger.name = __file__
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[%(asctime)s]-[%(levelname)s]-[%(name)s]: %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def __setup_arguments():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', 
                       help='Target is a hostname or an ip address')
    group.add_argument('-f', '--file', 
                       help='File is a file containing hostnames and/or ip addresses seperated by newlines')
    group.add_argument('-r', '--range', 
                       help='A CIDR notition of hosts to be scanned')
    parser.add_argument('path', metavar='PATH', 
                       help='Directory where the output will be written')
    # parser.add_argument('--passdb', help='Path to the custom passwords list')
    parser.add_argument('--no-tcp-service', help='Disable Nmap TCP service scan', action='store_true')
    parser.add_argument('--no-udp', help='Disable Nmap UDP scan completely', action='store_true')
    parser.add_argument('--no-udp-service', help='Disable Nmap UDP service scan', action='store_true')
    parser.add_argument('--no-dns', help='Disable DNS checks', action='store_true')
    parser.add_argument('--no-whois', help='Disable Nmap WHOIS', action='store_true')
    parser.add_argument('--no-screenshots', help='Disable screenshots', action='store_true')
    parser.add_argument('--no-ssl', help='Disable Testssl.sh', action='store_true')
    parser.add_argument('--no-nikto', help='Disable Nikto', action='store_true')
    parser.add_argument('--no-arachni', help='Disable Arachni', action='store_true')

    args = parser.parse_args()
    logger.debug(args)
    return args

if __name__ == "__main__":
    main()