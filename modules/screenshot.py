from selenium import webdriver
import common
import logging
logger = logging.getLogger(__name__)

def browser_target_port(target, port, ssl=False, path='/tmp'):
    if (ssl==True):
        url='https://'
    else:
        url='http://'
    url += "{target}:{port}/".format(target=target, port=port)
    browser_url(url, path)

def browser_url(url, path='/tmp'):
    output='{path}/screenshot_{filename}.png' \
            .format(path=path, filename=common.target_to_filename(url))
    logger.info("Screenshot '{url}' to '{output}'".format(url=url, output=output))
    try:
        driver = webdriver.Firefox()
    except:
        logger.error("Could not instantiate Selenium for Firefox")
    try:
        driver.get(url)
    except:
        logger.error("Could not browse to given url: {0}".format(url))
    try:
        driver.save_screenshot(output)
    except:
        logger.error("Could not screenshot given url: {0}".format(url))
        url = 'view-source:%s' % url 
        logger.warn("Trying view-source variant url: {0}".format(url))
        try:
            driver.get(url)
            driver.save_screenshot(output)
        except:
            logger.error("[!] Even that failed... going home..")
    try:
        driver.close();
    except:
        pass