import subprocess
import common
import logging
logger = logging.getLogger(__name__)

__TESTSSL = '/usr/local/share/testssl.sh/testssl.sh'
__OPENSSL = '/usr/local/share/testssl.sh/bin/openssl.Linux.x86_64'


def scan(target, port=443, path='/tmp'):
    output = '{path}/testssl__{target}_{port}.txt'\
    		 .format(path=path, target=common.target_to_filename(target), port=port)
    cmdline = '"{testssl}" ' \
              '--openssl "{openssl}" ' \
              '--wide --color 0 ' \
              '--logfile="{output}" ' \
              '{target}:{port}'.format(testssl=__TESTSSL, openssl=__OPENSSL,
                                       output=output, target=target, port=port)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)