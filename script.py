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


def wait_for_element(driver, selector, timeout=30, state='visible', count=1):

    if count > 3:
        return {'exit': True}

    try:
        if state == 'visible':
            WebDriverWait(driver, timeout).until(
                EC.visibility_of_element_located((
                    By.CSS_SELECTOR, selector)))

        elif state == 'invisible':
            WebDriverWait(driver, timeout).until(
                EC.invisibility_of_element_located((
                    By.CSS_SELECTOR, selector)))
    except TimeoutException:
        logger.info('Browser timed out while waiting...')
        wait_for_element(
            driver, selector, timeout=timeout,
            state=state, count=count+1)


def get_sensors(driver):

    sensors = list()
    sensor_rows = driver.find_elements_by_css_selector(
        '#table-sensors-list tr.result-row')

    for row in sensor_rows:
        try:
            _id = row.get_attribute('id').replace('result-row-', str())
            text = row.find_element_by_css_selector(
                '.result-column-sensor-status').text
            name = row.find_element_by_css_selector(
                '.result-column-sensor-name').text.split('\n')[0]
            ip = row.find_element_by_css_selector(
                '.result-column-sensor-ip').text
            sensors.append({'id': _id, 'name': name, 'text': text, 'ip': ip})

        except StaleElementReferenceException:
            return get_sensors(driver)

    return sensors


def main(event, context):

    config = read_config()
    if config.get('statusCode'):
        logger.info(config)
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
        message = 'Could not connect to remote selenium ' \
            'server: %s' % (config['selenium_host'])
        alert_on_slack('> *Critical:* ' + message, config)
        return _exit(500, str(exc))

    try:
        logger.info('Visiting url: %s', config['usm_host_url'])
        driver.get(config['usm_host_url'])

        if 'AlienVault' not in driver.title:
            message = 'Browser could not retrieve the ' \
                'main page of USM.'
            logger.info(message)
            alert_on_slack('> ' + message, config)
            return _exit(400, 'Unexpected HTML page title at: %s' % (
                config['usm_host_url']))

        do_login(driver, config)

        logger.info('Waiting for dashboard...')
        res = wait_for_element(driver, 'av-header #header')
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack('> ' + message, config)

        driver.find_element_by_css_selector(
            'counter-nav-icon[counter-name="intercom"] '
            '.counter-nav-icon-container').click()

        logger.info('Waiting for intercom to appear...')
        res = wait_for_element(
            driver, 'iframe[title="Intercom live chat messenger"]', timeout=5)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack('> ' + message, config)

        iframe = driver.find_element_by_css_selector(
            'iframe[title="Intercom live chat messenger"]')
        driver.switch_to.frame(iframe)
        logger.info('Switched to intercom iframe.')

        selector = '.intercom-messenger-card-image' \
            '.intercom-messenger-card-image-left + ' \
            '.intercom-messenger-card-list-item-text'

        logger.info('Waiting for status element...')
        res = wait_for_element(driver, selector, timeout=10)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack('> ' + message, config)

        data = {'storage': dict()}
        data['status'] = driver.find_element_by_css_selector(selector).text
        driver.switch_to.default_content()
        logger.info('Switched back to default content.')

        sub_link = driver.find_element_by_id('nav-link-my-subscription')
        driver.get(sub_link.get_attribute('href'))

        logger.info('Waiting for subscription page...')
        res = wait_for_element(driver, '#status-my-subscription', timeout=20)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack('> ' + message, config)
        else:
            logger.info('Waiting for subscription data to load...')
            res = wait_for_element(
                driver, 'loading #loading', timeout=15, state='invisible')
            if res and res.get('exit'):
                message = 'Browser timed out after 3rd retry ' \
                    'of waiting for element.'
                logger.info(message)
                alert_on_slack('> ' + message, config)
            else:

                data['storage']['total'] = \
                    driver.find_element_by_css_selector(
                    '.free-space:nth-child(2) span.ng-binding:last-child') \
                    .text
                data['storage']['consumed'] = \
                    driver.find_element_by_css_selector(
                    '.free-space:nth-child(2) span.ng-binding:first-child') \
                    .text
                data['storage']['remaining'] = \
                    driver.find_element_by_css_selector(
                    '.free-space:nth-child(4) span.ng-binding:first-child') \
                    .text
                data['storage']['projected'] = \
                    driver.find_element_by_css_selector(
                    '.free-space:nth-child(6) span.ng-binding:first-child') \
                    .text

        sensor_link = driver.find_element_by_css_selector('a#nav-link-sensors')
        logger.info('Visting sensors page link...')
        driver.get(sensor_link.get_attribute('href'))

        logger.info('Waiting for sensors page...')
        res = wait_for_element(driver, '#table-sensors-list', timeout=15)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack('> ' + message, config)

        logger.info('Finding disconnected sensors from page...')
        data['sensors'] = get_sensors(driver)

        text = get_slack_text([x for x in data['sensors'] if x.get(
            'text', str()).lower() in ['connection lost']], config)
        alert_on_slack(text, config)

        for sensor in data['sensors']:
            if not sensor.get('id') or sensor.get(
                    'text', str()).lower() in ['connection lost']:
                continue

            url = config['usm_host_url'] + '/#/sensor/%s' % (sensor.get('id'))
            logger.info('Visiting sensor page [%s]...', sensor.get('name'))
            driver.get(url)

            logger.info('Waiting for settings table...')
            res = wait_for_element(
                driver, '.av-table-striped.checks', timeout=20)
            if res and res.get('exit'):
                message = 'Browser timed out after 3rd retry ' \
                    'of waiting for element.'
                logger.info(message)
                alert_on_slack('> ' + message, config)

            sensor['network'] = dict()
            sensor['syslog'] = list()

            for row in driver.find_elements_by_css_selector(
                    '.av-table-striped.checks tr.ng-scope'):
                desc = row.find_element_by_css_selector('.ng-binding').text
                status = row.find_element_by_css_selector('td img.icon')
                status = status.get_attribute('src') if status else 'N/A'
                status = 'success' if 'success' in status else \
                    'error' if 'error' in status else status

                sensor['network'][desc] = status

            syslog_tab = driver.find_element_by_id('link-syslog-configuration')
            syslog_tab.click()

            res = wait_for_element(
                driver, '.av-table-striped.syslog', timeout=10)
            if res and res.get('exit'):
                message = 'Browser timed out after 3rd retry ' \
                    'of waiting for element.'
                logger.info(message)
                alert_on_slack('> ' + message, config)

            for row in driver.find_elements_by_css_selector(
                    '.av-table-striped.syslog tr.ng-scope'):
                protocol = row.find_element_by_id('txt-protocol').text
                ip = row.find_element_by_id('txt-management').text
                try:
                    port = int(row.find_element_by_id('txt-port').text)
                except:
                    port = 0
                packets = row.find_element_by_id('txt-packets').text
                sensor['syslog'].append({
                    'ip': ip, 'protocol': protocol,
                    'port': port, 'packets': packets})

        logger.info('Closing webdriver...')
        driver.close()
    except Exception as exc:
        logger.info('Exception occured in code. Gracefully closing webdriver.')
        driver.close()
        alert_on_slack('> Unexpected exception occured.\n'
                       '*`%s`*' % (str(exc)), config)
        logger.info(str(exc))
        return _exit(500, str(exc))

    return _exit(200, 'Everything executed smoothly.')


if __name__ == "__main__":

    main({}, {})
