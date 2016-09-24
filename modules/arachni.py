import subprocess
import common
import logging
logger = logging.getLogger(__name__)

def scan(target, port, ssl=False, path='/tmp'):
    output_bin ='{path}/arachni__{target}_{port}.bin'\
                .format(path=path, target=common.target_to_filename(target), port=port)
    output_html ='{path}/arachni__{target}_{port}.html.zip'\
                .format(path=path, target=common.target_to_filename(target), port=port)
    if (ssl==True):
        cmdline = 'arachni https://{target}:{port} --report-save-path "{output}"'\
                  .format(target=target, port=port, output=output_bin)
    else:
        cmdline = 'arachni http://{target}:{port} --report-save-path "{output}"'\
                  .format(target=target, port=port, output=output_bin)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    cmdline = 'arachni_reporter {bin} --reporter=html:outfile={output}'\
              .format(bin=output_bin, output=output_html)    
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)