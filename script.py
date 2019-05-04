import os
import time
import json
import logging

import requests
import opencrypt

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import StaleElementReferenceException


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


def _exit(code, message, response_only=False):

    response = {'statusCode': code, 'body': json.dumps({
        'error' if code >= 300 else 'success': message})}
    return response if response_only else exit(response)


def read_config():

    if not os.environ.get('CONFIG_FILE'):
        _exit(404, 'No CONFIG_FILE environment variable exists.')

    config_file = os.environ['CONFIG_FILE']
    if config_file.startswith(('http', 'https', 'ftp')):
        logger.info('Config file prefix tells program to fetch it online.')
        logger.info('Fetching config file: %s' % (config_file))
        response = requests.get(config_file)

        if response.status_code < 400:
            ciphertext = response.content
        else:
            _exit(400, 'Could not fetch config file: %s' % (response))

    else:
        logger.info('Config file prefix tells program to search ' +
                    'for it on filesystem.')

        if not os.path.isfile(config_file):
            _exit(404, 'No Config file on filesystem: %s' % (config_file))

        ciphertext = open(config_file, 'rb').read()

    content = opencrypt.decrypt_file(
        ciphertext, write_to_file=False, is_ciphertext=True)
    try:
        config = json.loads(content)
        validate_config(config)
        return config
    except json.JSONDecodeError as exc:
        _exit(400, str(exc))


def validate_config(config):

    for key in ['usm_host_url', 'usm_username', 'usm_password']:
        if not config.get(key):
            _exit(400, 'No `%s` field defined in config.' % (key))


def alert_on_slack(data, config):

    logger.info(str())
    logger.info('[%d] sensors are found to be disconnected.', len(data))
    if not config.get('slack_hooks', list()):
        logger.info('No webhook is specified. Skipping slack push.')
        return

    if not data:
        logger.info('No disconnected sensor detected. Skipping slack push.')
        return

    prepared_string = str()
    for entry in data:
        if not(entry.get('name') or entry.get('ip')):
            continue

        if entry.get('name') in config.get('whitelist', list()) or \
                entry.get('ip') in config.get('whitelist', list()):
            continue

        prepared_string += '> *Sensor :* %s  *IP :* %s\n' % (
            entry.get('name', 'N/A'), entry.get('ip', 'N/A'))

    if prepared_string:
        prepared_string = 'Following sensors are detected to be ' \
            'disconnected from USM.\n' + prepared_string
    else:
        logger.info('Disconnected sensor(s) were whitelisted. '
                    'Skipping slack push.')
        return

    for url in config['slack_hooks']:
        response, _count = (None, 0)
        while not response and _count < 5:
            try:
                response = requests.post(url, json={'text': prepared_string})
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

    options = Options()
    options.headless = True
    driver = webdriver.Chrome('drivers/chromedriver', chrome_options=options)

    try:
        logger.info('Visiting url: %s', config['usm_host_url'])
        driver.get(config['usm_host_url'])

        if 'AlienVault' not in driver.title:
            _exit(400, 'Unexpected HTML page title at: %s' % (
                config['usm_host_url']))

        do_login(driver, config)

        logger.info('Waiting for dashboard...')
        WebDriverWait(driver, 30).until(
            EC.visibility_of_element_located((
                By.CSS_SELECTOR, 'av-header #header')))

        sensor_link = driver.find_element_by_css_selector('a#nav-link-sensors')
        logger.info('Visting sensors page link...')
        driver.get(sensor_link.get_attribute('href'))

        logger.info('Waiting for sensors page...')
        WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((
                By.CSS_SELECTOR, '#table-sensors-list')))

        logger.info('Finding disconnected sensors from page...')
        disconn = get_disconnected_sensors(driver)

        logger.info('Closing webdriver...')
        driver.close()

        alert_on_slack(disconn, config)

    except Exception as exc:
        logger.info('Exception occured in code. Gracefully closing webdriver.')
        driver.close()
        _exit(500, str(exc))

    _exit(200, 'Everything executed smoothly.')


if __name__ == "__main__":

    main({}, {})
