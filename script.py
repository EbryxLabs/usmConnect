import os
import stat
import time
import json
import zipfile
import logging
from urllib3.exceptions import NewConnectionError, MaxRetryError

import requests
import opencrypt

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    StaleElementReferenceException, TimeoutException)
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


def _exit(code, message):

    return {'statusCode': code, 'body': json.dumps({
        'error' if code >= 300 else 'success': message})}


def read_config():

    if not os.environ.get('CONFIG_FILE'):
        return _exit(404, 'No CONFIG_FILE environment variable exists.')

    config_file = os.environ['CONFIG_FILE']
    if config_file.startswith(('http', 'https', 'ftp')):
        logger.info('Config file prefix tells program to fetch it online.')
        logger.info('Fetching config file: %s' % (config_file))
        response = requests.get(config_file)

        if response.status_code < 400:
            ciphertext = response.content
        else:
            return _exit(400, 'Could not fetch config file: '
                         '%s' % (response))
    else:
        logger.info('Config file prefix tells program to search ' +
                    'for it on filesystem.')
        if not os.path.isfile(config_file):
            return _exit(404, 'No Config file on filesystem: '
                         '%s' % (config_file))

        ciphertext = open(config_file, 'rb').read()

    content = opencrypt.decrypt_file(
        ciphertext, write_to_file=False, is_ciphertext=True)
    try:
        config = json.loads(content)
        validation = validate_config(config)

        if validation and validation.get('statusCode'):
            return validation
        return config
    except json.JSONDecodeError as exc:
        return _exit(400, str(exc))


def validate_config(config):

    for key in ['usm_host_url', 'usm_username', 'usm_password',
                'selenium_host']:
        if not config.get(key):
            return _exit(400, 'No `%s` field defined in config.' % (key))

    if not config['selenium_host'].startswith(('http', 'https')):
        config['selenium_host'] = 'http://127.0.0.1:4444/wd/hub'


def get_slack_text(data, config):

    prepared_string = str()
    logger.info(str())
    logger.info('[%d] sensors are found to be disconnected.', len(data))
    if not config.get('slack_hooks', list()):
        logger.info('No webhook is specified. Skipping slack push.')
        return prepared_string

    if not data:
        logger.info('No disconnected sensor detected. Skipping slack push.')
        return prepared_string

    for entry in data:
        if not(entry.get('name') or entry.get('ip')):
            continue

        if entry.get('name') in config.get('whitelist', list()) or \
                entry.get('ip') in config.get('whitelist', list()):
            continue

        prepared_string += '> %s *(%s)*\n' % (
            entry.get('ip', 'N/A'), entry.get('name', 'N/A'))

    if prepared_string:
        prepared_string = 'Following sensors are detected to be ' \
            'disconnected from USM.\n' + prepared_string
    else:
        logger.info('Disconnected sensor(s) were whitelisted. '
                    'Skipping slack push.')

    return prepared_string


def alert_on_slack(text, config):

    if not text:
        logger.info('No text to push to slack.')
        return

    for url in config['slack_hooks']:
        response, _count = (None, 0)
        while not response and _count < 5:
            try:
                response = requests.post(url, json={'text': text})
            except:
                logger.info('Could not send slack request. ' +
                            'Retrying after 10 secs...')
                time.sleep(10)
                _count += 1

        if not response:
            continue

        if response.status_code == 200:
            logger.info('Pushed message to slack successfully.')
        else:
            logger.info('Could not push message to slack: <(%s) %s>' % (
                response.status_code, response.content.decode('utf8')))


def do_login(driver, config):

    logger.info('Logging into the system...')
    email_elem = driver.find_element_by_css_selector(
        'input[placeholder="EMAIL"]')
    email_elem.send_keys(config['usm_username'])

    password_elem = driver.find_element_by_css_selector(
        'input[placeholder="PASSWORD"]')
    password_elem.send_keys(config['usm_password'])

    login_elem = driver.find_element_by_css_selector('button#btn-login')
    login_elem.click()


def wait_for_element(driver, selector, timeout=30, count=1):

    if count > 3:
        return {'exit': True}

    try:
        WebDriverWait(driver, 30).until(
            EC.visibility_of_element_located((
                By.CSS_SELECTOR, selector)))
    except TimeoutException:
        logger.info('Browser timed out while waiting...')
        wait_for_element(driver, selector, timeout=timeout, count=count+1)


def get_disconnected_sensors(driver):

    disconnected = list()
    sensor_rows = driver.find_elements_by_css_selector(
        '#table-sensors-list tr.result-row')

    for row in sensor_rows:
        try:
            text = row.find_element_by_css_selector(
                '.result-column-sensor-status').text

            if text.strip().lower() in ['connection lost']:
                disconnected.append({
                    'name': row.find_element_by_css_selector(
                        '.result-column-sensor-name').text.split('\n')[0],
                    'ip': row.find_element_by_css_selector(
                        '.result-column-sensor-ip').text
                })

        except StaleElementReferenceException:
            return get_disconnected_sensors(driver)

    return disconnected


def main(event, context):

    config = read_config()
    if config.get('statusCode'):
        return config

    logger.info(str())

    options = Options()
    options.headless = True
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    try:
        logger.info('Connecting to selenium: %s', config['selenium_host'])
        driver = webdriver.Remote(
            config['selenium_host'],
            desired_capabilities={'browserName': 'chrome'},
            options=options)
    except (NewConnectionError, MaxRetryError) as exc:
        alert_on_slack(
            '> *Critical:* Could not connect to remote selenium '
            'server: %s' % (config['selenium_host']), config)
        return _exit(500, str(exc))
    try:
        logger.info('Visiting url: %s', config['usm_host_url'])
        driver.get(config['usm_host_url'])

        if 'AlienVault' not in driver.title:
            return _exit(400, 'Unexpected HTML page title at: %s' % (
                config['usm_host_url']))

        do_login(driver, config)

        logger.info('Waiting for dashboard...')
        res = wait_for_element(driver, 'av-header #header')
        if res and res.get('exit'):
            alert_on_slack('Browser timed out after 3rd retry '
                           'of waiting for element.', config)
            return _exit(400, 'Exiting program after 3rd retry...')

        sensor_link = driver.find_element_by_css_selector('a#nav-link-sensors')
        logger.info('Visting sensors page link...')
        driver.get(sensor_link.get_attribute('href'))

        logger.info('Waiting for sensors page...')
        res = wait_for_element(driver, '#table-sensors-list', timeout=15)
        if res and res.get('exit'):
            alert_on_slack('Browser timed out after 3rd retry '
                           'of waiting for element.', config)
            return _exit(400, 'Exiting program after 3rd retry...')

        logger.info('Finding disconnected sensors from page...')
        disconn = get_disconnected_sensors(driver)

        logger.info('Closing webdriver...')
        driver.close()

        text = get_slack_text(disconn, config)
        alert_on_slack(text, config)

    except Exception as exc:
        logger.info('Exception occured in code. Gracefully closing webdriver.')
        driver.close()
        return _exit(500, str(exc))

    return _exit(200, 'Everything executed smoothly.')


if __name__ == "__main__":

    main({}, {})
