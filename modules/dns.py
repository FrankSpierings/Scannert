import subprocess
import common
import logging
import socket
logger = logging.getLogger(__name__)


def scan(target, path='/tmp'):
	ip = socket.gethostbyname(target)
	if (target != ip):
		#We have a name
		logger.debug('Target: \"{target}\" has ip: {ip}'.format(target=target, ip=ip))		
		__forward_lookup(target, path=path)
		
		target_array = target.split('.')

		for i in range(0, len(target_array)-1):
			current_target = ".".join(target_array[i:])
			#Do a reverse lookup of the addresses.
			ips = []
			try:
				ips = socket.gethostbyname_ex(current_target)[2]
			except:
				pass
			for ip in ips:
				__reverse_lookup(ip, path=path)

			__dnsrecon(current_target, path=path)
	else:
		logger.debug('Target is an ip: {ip}'.format(ip=ip))
		__reverse_lookup(ip, path=path)

def __reverse_lookup(ip, path='/tmp'):
	output = '{path}/dig__{ip}.txt'\
			 .format(path=path, ip=ip)
	
	cmd     = 'dig -x {ip}'.format(ip=ip)
	#The no append in tee is decision!.
	cmdline = 'echo {cmd} | tee {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmd     = 'dig +short -x {ip}'.format(ip=ip)
	cmdline = 'echo {cmd} | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

def __forward_lookup(target, path='/tmp'):
	output = '{path}/dig__{target}.txt'\
			 .format(path=path, target=common.target_to_filename(target))
	
	cmd     = 'dig ANY {target}'.format(target=target)
	#The no append in tee is decision!.
	cmdline = 'echo {cmd} | tee {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmd     = 'dig +short ANY {target}'.format(target=target)
	cmdline = 'echo {cmd} | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

def __dnsrecon(target, path='/tmp'):
	output = '{path}/dnsrecon__{target}.txt'\
			 .format(path=path, target=common.target_to_filename(target))
	cmd     = 'dnsrecon -a -z -d {target}'.format(target=target)
	#The no append in tee is decision!.
	cmdline = 'echo {cmd} | tee {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)

	cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
	logger.info("Command: {0}".format(cmdline))
	subprocess.call(cmdline, shell=True)
