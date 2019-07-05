import os
import stat
import time
import json
import zipfile
import logging
from urllib.parse import urljoin
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

    if not config.get('usm'):
        return _exit(404, 'No `usm` field defined in config.')

    for key in ['host_url', 'username', 'password']:
        if not config['usm'].get(key):
            return _exit(404, 'No `%s` field defined in config.' % (key))

    if not config.get('selenium_host'):
        return _exit(404, 'No `selenium_host` field defined in config.')

    for key in ['api_url', 'client_id', 'client_secret']:
        if not config['usm'].get(key):
            logger.info('`%s` field not defined. Fetching of sensor '
                        'events via USM API will be skipped', key)
            break

    if not config['selenium_host'].startswith(('http', 'https')):
        config['selenium_host'] = 'http://127.0.0.1:4444/wd/hub'


def get_auth_token(config):

    usm = config['usm']
    url = urljoin(usm.get('api_url'), 'oauth/token')
    logger.info('Retrieving OAUTH token for USM...')
    res = requests.post(url, data={'grant_type': 'client_credentials'},
                        auth=(usm.get('client_id'), usm.get('client_secret')))

    if res.status_code < 300:
        return res.json().get('access_token')

    logger.info('Unexpected response returned: %s', res)
    return None


def get_usm_events(config, token, sensors):

    usm = config['usm']
    curr_time = str(time.time()).replace('.', str())[:13]
    prev_time = str(int(curr_time) - (int(usm.get(
        'sensor_interval', '60')) * 60 * 1000))
    params = ['sort=timestamp_occured,desc',
              'timestamp_occured_gte=' + prev_time,
              'size=5']

    for sensor in sensors:
        if not sensor.get('id'):
            continue

        url = urljoin(usm.get('api_url'), 'events?%s&sensor_uuid=%s' % (
            '&'.join(params), sensor.get('id')))
        logger.info('Retrieving USM sensor events [%s]...', sensor.get('name'))
        res = requests.get(url, headers={'Authorization': 'Bearer ' + token})
        if res.status_code < 300:
            sensor['events'] = {
                'timestamps': [
                    x.get('timestamp_received_iso8601') for x in
                    res.json().get('_embedded', dict()).get(
                        'eventResourceList', list())
                ]}
            sensor['events']['count'] = res.json().get(
                'page', dict()).get('totalElements', 0)
            logger.info('[%d] events fetched from '
                        'USM.', len(sensor['events']))
        else:
            logger.info('Unexpected response returned: %s', res)


def push_slack_text(config, data):

    slack_text = str()
    logger.info(str())

    if not config.get('slack_hooks', list()):
        logger.info('No webhook is specified. Skipping slack push.')
        return slack_text
    if not data:
        logger.info('No disconnected sensor detected. Skipping slack push.')
        return slack_text

    disconns = [
        x for x in data['sensors']
        if 'connection lost' in x.get('text').lower()
        if x.get('ip') not in config.get('whitelist', list())
        if x.get('name') not in config.get('whitelist', list())]
    logger.info('[%d] sensors are found to be disconnected.', len(disconns))
    tick, cross = ':heavy_check_mark:', ':heavy_multiplication_x:'

    symbol = tick if 'all systems operational' in data[
        'status'].lower() else cross
    slack_text += '*Status:*\n> %s %s\n\n' % (
        symbol, data['status'].replace('Status: ', str()).split('\n')[0])

    if not config.get('storage') and data.get('storage'):
        slack_text += '*Storage:*\n> Consumed: *%s/%s*\n' \
            '> Remaining: *%s*\n> Projected: *%s*\n' % (
                data['storage']['consumed'], data['storage']['total'],
                data['storage']['remaining'], data['storage']['projected'])
    elif not data.get('storage'):
        slack_text += '*Storage:*\n' \
            '> %s Details could not be retrieved.\n' % (cross)

    logger.info('Pushing status and storage details to slack...')
    alert_on_slack(config, slack_text)

    if not data['sensors']:
        slack_text += '*Sensors:*\n' \
            '> %s Details could not be retrieved.\n' % (cross)

    for sensor in data['sensors']:
        slack_text = str()
        if not(sensor.get('name') or sensor.get('ip')):
            continue

        if sensor.get('name') in config.get('whitelist', list()) or \
                sensor.get('ip') in config.get('whitelist', list()):
            continue

        slack_text += '\n*(%s)* %s\n' % (
            sensor.get('name', 'N/A'), sensor.get('ip', 'N/A'))

        symbol = cross if 'connection lost' in \
            sensor.get('text').lower() else tick
        slack_text += '> \t%s %s\n' % (symbol, sensor['text'])

        slack_text += '> \t*Events:*\n> \t\tLatest: *`%s`*\n' \
            '> \t\tCount: *`%s`*\n' % ((sensor.get('events', dict()).get(
                'timestamps', list()) or ['N/A'])[-1], sensor.get(
                    'events', dict()).get('count', 0))

        if sensor.get('network'):
            slack_text += '> \t*Network:*\n'
            for desc, status in sensor.get('network').items():
                symbol = tick if 'success' in status.lower() else cross
                slack_text += '> \t\t%s %s.\n' % (symbol, desc)
        else:
            slack_text += '> \t*Network:*\n' \
                '> \t\t%s Details could not be retrieved.\n' % (cross)

        if sensor.get('syslog'):
            slack_text += '> \t*Syslog:*\n'
            for entry in sensor.get('syslog'):
                symbol = tick if entry.get('packets') is not '0' else cross
                slack_text += '> \t\t%s *%s* packets received.' \
                    '\t*`%s:%s`*\n' % (
                        symbol, entry.get('packets'), entry.get(
                            'protocol').split(' ')[-1], entry.get('port'))
        else:
            slack_text += '> \t*Syslog:*\n' \
                '> \t\t%s Details could not be retrieved.\n' % (cross)

        logger.info('Pushing sensor (%s) details to '
                    'slack...', sensor.get('name'))
        alert_on_slack(config, slack_text)


def alert_on_slack(config, text):

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


def do_login(config, driver):

    logger.info('Logging into the system...')
    email_elem = driver.find_element_by_css_selector(
        'input[placeholder="EMAIL"]')
    email_elem.send_keys(config['usm']['username'])

    password_elem = driver.find_element_by_css_selector(
        'input[placeholder="PASSWORD"]')
    password_elem.send_keys(config['usm']['password'])

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

        elif state == 'clickable':
            WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((
                    By.CSS_SELECTOR, selector)))
    except TimeoutException:
        logger.info('Browser timed out while waiting...')
        wait_for_element(
            driver, selector, timeout=timeout,
            state=state, count=count+1)


def get_sensors_status(config, driver, skip_page=False):

    sensors = list()

    if not skip_page:
        sensor_link = driver.find_element_by_css_selector('a#nav-link-sensors')
        logger.info('Visting sensors page link...')

        driver.get(sensor_link.get_attribute('href'))
        logger.info('Waiting for sensors page...')

        res = wait_for_element(driver, '#table-sensors-list', timeout=15)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            return sensors

    logger.info('Finding disconnected sensors from page...')
    for row in driver.find_elements_by_css_selector(
            '#table-sensors-list tr.result-row'):
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
            return get_sensors_status(config, driver, skip_page=True)

    return sensors


def get_system_status(config, driver):

    logger.info('Waiting for intercom container to be clickable...')
    wait_for_element(driver, '#nav-tab-intercom', state='clickable')
    driver.find_element_by_css_selector('#nav-tab-intercom').click()

    logger.info('Waiting for intercom to appear...')
    res = wait_for_element(
        driver, 'iframe[title="Intercom live chat messenger"]', timeout=5)
    if res and res.get('exit'):
        message = 'Browser timed out after 3rd retry ' \
            'of waiting for element.'
        logger.info(message)

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

    status = driver.find_element_by_css_selector(selector).text
    driver.switch_to.default_content()
    logger.info('Switched back to default content.')
    return status


def get_subscription_details(config, driver):

    sub_link = driver.find_element_by_id('nav-link-my-subscription')
    driver.get(sub_link.get_attribute('href'))

    storage = dict()
    logger.info('Waiting for subscription page...')
    res = wait_for_element(driver, '#status-my-subscription', timeout=20)
    if res and res.get('exit'):
        message = 'Browser timed out after 3rd retry ' \
            'of waiting for element.'
        logger.info(message)
        return storage

    else:
        logger.info('Waiting for subscription data to load...')
        res = wait_for_element(
            driver, 'loading #loading', timeout=15, state='invisible')
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            return storage
        else:

            storage['total'] = \
                driver.find_element_by_css_selector(
                '.free-space:nth-child(2) span.ng-binding:last-child') \
                .text
            storage['consumed'] = \
                driver.find_element_by_css_selector(
                '.free-space:nth-child(2) span.ng-binding:first-child') \
                .text
            storage['remaining'] = \
                driver.find_element_by_css_selector(
                '.free-space:nth-child(4) span.ng-binding:first-child') \
                .text
            storage['projected'] = \
                driver.find_element_by_css_selector(
                '.free-space:nth-child(6) span.ng-binding:first-child') \
                .text

            return storage


def populate_sensor_details(config, driver, sensors):

    for sensor in sensors:
        if not sensor.get('id') or sensor.get(
                'text', str()).lower() in ['connection lost']:
            continue

        url = config['usm']['host_url'] + \
            '/#/sensor/%s' % (sensor.get('id'))
        logger.info('Visiting sensor page [%s]...', sensor.get('name'))
        driver.get(url)

        logger.info('Waiting for network table...')
        res = wait_for_element(
            driver, '.av-table-striped.checks', timeout=20)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)

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

        logger.info('Waiting for syslog table...')
        res = wait_for_element(
            driver, '.av-table-striped.syslog', timeout=10)
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)

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
    options.add_argument('--window-size=1920x1080')

    try:
        logger.info('Connecting to selenium: %s', config['selenium_host'])
        driver = webdriver.Remote(
            config['selenium_host'],
            desired_capabilities={'browserName': 'chrome'},
            options=options)
    except (NewConnectionError, MaxRetryError) as exc:
        message = 'Could not connect to remote selenium ' \
            'server: %s' % (config['selenium_host'])
        alert_on_slack(config, '> *Critical:* ' + message)
        return _exit(500, str(exc))

    try:
        logger.info('Visiting url: %s', config['usm']['host_url'])
        driver.get(config['usm']['host_url'])

        if 'AlienVault' not in driver.title:
            message = 'Browser could not retrieve the ' \
                'main page of USM.'
            logger.info(message)
            alert_on_slack(config, '> ' + message)
            return _exit(400, 'Unexpected HTML page title at: %s' % (
                config['usm_host_url']))

        do_login(config, driver)

        logger.info('Waiting for dashboard...')
        res = wait_for_element(driver, 'av-header #header')
        if res and res.get('exit'):
            message = 'Browser timed out after 3rd retry ' \
                'of waiting for element.'
            logger.info(message)
            alert_on_slack(config, '> ' + message)

        data = dict()
        data['status'] = get_system_status(config, driver)
        data['storage'] = get_subscription_details(config, driver)
        data['sensors'] = get_sensors_status(config, driver)
        populate_sensor_details(config, driver, data['sensors'])

        logger.info('Closing webdriver...')
        driver.close()

        token = get_auth_token(config)
        if not token:
            logger.info('Could not retrieve OAUTH token for '
                        'USM API. Skipping sensor events...')
        else:
            get_usm_events(config, token, data['sensors'])

        push_slack_text(config, data)

    except Exception as exc:
        logger.info('Exception occured in code. Gracefully closing webdriver.')
        driver.close()
        alert_on_slack(config, '> Unexpected exception occured.\n'
                       '*`%s`*' % (str(exc)))
        logger.info(str(exc))
        return _exit(500, str(exc))

    return _exit(200, 'Everything executed smoothly.')


if __name__ == "__main__":

    main({}, {})
