#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attendance Checker and Reminder for IITK CSE
--------------------------------------------

Checks both on Kendra and Pingala

The command can be added as a cron job. Run the command `crontab -e` and add
the following line at the end, for running the script at 5pm, 8pm and 11pm.

```
    0 17,20,23 * * * <path_to_python3> <path_to_the_script>
```
Requirements
------------
* requests
* python-gnupg
* beautifulsoup4

@author: Hrishikesh Terdalkar
"""

import os
import json
import getpass
import smtplib
import logging
import datetime
import argparse
import traceback

from email.message import EmailMessage

import requests
from bs4 import BeautifulSoup

try:
    import gnupg
    GNUPG_FOUND = True
except ImportError:
    GNUPG_FOUND = False

###############################################################################

LOGGER = logging.getLogger(__name__)
FORMATTER = logging.Formatter(
    fmt='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

if not GNUPG_FOUND:
    LOGGER.warning("Could not find GnuPG, using plaintext storage.")

###############################################################################

CONTEXT = {
    'login': None,
    'attendance_list': None,
    'details': None
}

###############################################################################


def setup_gnupg():
    """Setup GnuPG Encryption"""

    home_dir = os.path.expanduser('~')
    gpg_home = os.path.join(home_dir, '.gnupg')
    gpg_agent = os.path.join(gpg_home, 'S.gpg-agent')

    # ----------------------------------------------------------------------- #

    # GPG agent information
    os.environ['GPG_AGENT_INFO'] = f'{gpg_agent}:0:1'

    try:
        gpg = gnupg.GPG(gnupghome=gpg_home, use_agent=True)
        keys = gpg.list_keys()
        if len(keys) == 0:
            print("No GPG keys found. generating ...")
            user_email = input("Email for GPG Key: ")
            passphrase = getpass.getpass("Passphrase for GPG Key: ")
            key_input = gpg.gen_key_input(user_email, passphrase)
            print(
                "We need to generate a lot of random bytes. It is a good idea "
                "to perform some other action (type on the keyboard, move the "
                "mouse, utilize the disks) during the prime generation; this "
                "gives the random number generator a better chance to gain "
                "enough entropy."
            )
            gpg.gen_key(key_input)
    except Exception:
        return None

    # ----------------------------------------------------------------------- #

    return gpg


def configure(fresh=False, secure=GNUPG_FOUND):
    '''Get or Set Configuration'''

    decrypt = lambda x: x
    encrypt = lambda x: x

    if secure:
        gpg = setup_gnupg()
        if gpg is None:
            LOGGER.warning("Could not setup GnuPG, using plaintext storage.")
        else:
            keys = gpg.list_keys()
            key = keys[0]['keyid']
            decrypt = lambda x: str(gpg.decrypt(x))
            encrypt = lambda x: str(gpg.encrypt(x, key))

    # ----------------------------------------------------------------------- #

    home_dir = os.path.expanduser('~')
    attendance_dir = os.path.join(home_dir, '.attendance')
    secure_config_file = os.path.join(attendance_dir, 'config.secure')
    unsafe_config_file = os.path.join(attendance_dir, 'config.unsafe')

    config_file = secure_config_file if secure else unsafe_config_file
    log_file = os.path.join(attendance_dir, 'log')

    # ----------------------------------------------------------------------- #

    os.makedirs(attendance_dir, exist_ok=True)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(FORMATTER)
    LOGGER.addHandler(file_handler)

    # ----------------------------------------------------------------------- #

    config = {}
    if os.path.isfile(config_file) and not fresh:
        LOGGER.info("Reading from config file ...")
        try:
            with open(config_file, 'r') as f:
                config = json.loads(decrypt(f.read()))
        except Exception:
            LOGGER.error("Couldn't read configuration file.")

    if not config:
        LOGGER.info("Initiating fresh config ...")

        config = {'smtp': {}, 'kendra': {}, 'pingala': {}}

        config['pingala']['username'] = ''
        config['pingala']['password'] = ''
        config['pingala']['check'] = True

        config['kendra']['username'] = ''
        config['kendra']['password'] = ''
        config['kendra']['check'] = True

        config['smtp']['username'] = ''
        config['smtp']['password'] = ''
        config['smtp']['check'] = False

        username = getpass.getuser()

        for name, details in config.items():
            # --------------------------------------------------------------- #

            prompt = f"'{name}' username (default: {username}): "
            answer = input(prompt)
            if answer == '':
                answer = username
            else:
                username = answer

            details['username'] = answer

            # --------------------------------------------------------------- #

            prompt = f"'{name}' password: "
            answer = getpass.getpass(prompt)

            details['password'] = answer

            # --------------------------------------------------------------- #

        with open(config_file, 'w') as f:
            f.write(encrypt(json.dumps(config)))

    config['pingala']['function'] = get_pingala_attendance
    config['kendra']['function'] = get_kendra_attendance

    return config

###############################################################################
###############################################################################


def get_kendra_attendance(username, password, date):
    '''
    Fetch attendance from Kendra
    '''
    global CONTEXT

    server = 'https://kendra.cse.iitk.ac.in/kendra/pages/'

    login_url = server + 'AuthenticateUser.php'
    logout_url = server + 'Logout.php'
    profile_url = server + 'MyProfile.php'
    attendance_url = server + 'StudentAttendanceReport1.php?'
    attendance_options = 'Select=&val=i&FMonth={}&FYear={}'

    day, month, year = date.split('-')
    attendance_options = attendance_options.format(month, year)

    data = {
        'TR_Username': username,
        'TR_Password': password,
    }

    s = requests.session()
    s.post(login_url, data=data)
    check_response = s.get(profile_url)
    if username in check_response.text:
        LOGGER.info("Kendra login successful.")
        CONTEXT['login'] = True
    else:
        LOGGER.warning("Kendra login failed.")
        CONTEXT['login'] = False
        CONTEXT['details'] = 'Attendance may or may not have been marked.'
        return None

    response = s.get(attendance_url + attendance_options)
    soup = BeautifulSoup(response.text, 'html.parser')
    attendance_element = soup.find('td', {'title': str(int(day))})
    if not attendance_element:
        CONTEXT['attendance_list'] = False
        attendance_status = None
    else:
        CONTEXT['attendance_list'] = True
        attendance_status = attendance_element.text

    s.get(logout_url)
    s.close()

    if attendance_status == "-":
        attendance_status = None

    return attendance_status

###############################################################################


def get_pingala_attendance(username, password, date):
    '''
    Fetch attendance from Pingala
    '''
    global CONTEXT

    server = 'https://pingala.iitk.ac.in/IITK-0/'

    form_url = server + 'login'
    login_url = server + 'j_spring_security_check'
    logout_url = server + 'j_spring_security_logout'
    logincheck_url = server + 'logincheck'
    attendance_url = server + 'listMyAttendanceDetails?from_date={}&to_date={}'

    login_data = {
        'javascriptAbility': 'Disable',
        'username': username,
        'password': password,
        '_csrf': None
    }

    logout_data = {}

    s = requests.Session()
    r = s.get(form_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find('input', {"name": "_csrf"})['value']
    login_data['_csrf'] = csrf

    s.post(login_url, data=login_data)
    check_response = s.get(logincheck_url)
    if username in check_response.text:
        LOGGER.info("Pingala login successful.")

        soup = BeautifulSoup(check_response.text, 'html.parser')
        csrf = soup.find('input', {"name": "_csrf"})['value']
        logout_data['_csrf'] = csrf
        CONTEXT['login'] = True
    else:
        LOGGER.warning("Pingala login failed.")
        CONTEXT['login'] = False
        CONTEXT['details'] = 'Attendance may or may not have been marked.'
        return None

    response = s.get(attendance_url.format(date, date))
    response_dict = json.loads(response.text)
    attendance_details_list = response_dict['listMyAttendanceDetails']

    if len(attendance_details_list) == 0:
        CONTEXT['attendance_list'] = False
        return None

    CONTEXT['attendance_list'] = True

    attendance_details = attendance_details_list[0]
    attendance_status = attendance_details['intime']
    special = attendance_details['status'] in ['Week Off', 'Present']
    if not attendance_status and special:
        attendance_status = attendance_details['status']

    s.post(logout_url, data=logout_data)
    s.close()

    return attendance_status

###############################################################################


def sendmail(smtp_user, smtp_pass, subject='', content=''):
    '''
    Send a notification email using CSE SMTP.
    '''
    # ----------------------------------------------------------------------- #

    smtp_port = 25
    smtp_addr = 'smtp.cse.iitk.ac.in'

    # ----------------------------------------------------------------------- #

    # compose mail
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = subject
    msg['From'] = f'Attendance Reminder <{smtp_user}@cse.iitk.ac.in>'
    msg['To'] = f'{smtp_user}@cse.iitk.ac.in'

    # send mail
    if smtp_pass:
        mailer = smtplib.SMTP(f'{smtp_addr}:{smtp_port}')
        mailer.starttls()
        mailer.login(smtp_user, smtp_pass)
        mailer.send_message(msg)
        mailer.quit()
        LOGGER.info("Reminder e-mail sent.")
    else:
        LOGGER.warnign("Error: no credentials. e-mail was not sent.")

###############################################################################


def main():
    today = datetime.datetime.now().strftime("%d-%m-%Y")

    ###########################################################################

    desc = "Check and Remind if attendance is not marked (Kendra, Pingala)"

    p = argparse.ArgumentParser(description=desc)
    p.add_argument("-d", "--date", help="date dd-mm-yyyy", default=today)
    p.add_argument("-f", "--force", help="force re-configure", action='store_true')
    p.add_argument("--unsafe", help="Store credentials in plaintext", action="store_true")
    p.add_argument("-v", "--verbose", help="Verbose output and logging", action="store_true")

    args = vars(p.parse_args())

    date = args['date']
    fresh = args['force']
    secure = not args['unsafe']
    verbose = args['verbose']

    date_object = datetime.date(*map(int, reversed(date.split('-'))))
    day_of_week = date_object.strftime('%A')
    is_weekday = day_of_week not in ['Saturday', 'Sunday']

    if verbose:
        LOGGER.setLevel(logging.INFO)
        LOGGER.addHandler(logging.StreamHandler())

    ###########################################################################

    config = configure(fresh=fresh, secure=secure)

    smtp_user = config['smtp']['username']
    smtp_pass = config['smtp']['password']

    ###########################################################################

    for name, details in config.items():
        title = name.title()

        if details['check']:
            username = details['username']
            password = details['password']
            fetch_attendance = details['function']

            try:
                attendance_status = fetch_attendance(username, password, date)
            except Exception as e:
                LOGGER.error(e)
                attendance_status = None
                subject = f'Error in fetching attendance from {title}'
                content = traceback.print_exec()
                sendmail(smtp_user, smtp_pass, subject, content)

            # send reminder mail if applicable (not marked and not weekend)
            if attendance_status is None and is_weekday:
                attendance_status = "not marked!"
                LOGGER.info(f"Attendance not marked on {title} for {date}")

                # reminder only for today
                if date == today:
                    subject = f'Mark attendance on {title} for {today}'
                    content = ''

                    # login failed, so uncertain
                    if not CONTEXT['login']:
                        subject = f'Login to {title} failed.'
                    if CONTEXT['details']:
                        content = CONTEXT['details']

                    sendmail(smtp_user, smtp_pass, subject, content)

            attendance_msg = f"{title}: [{date}] {attendance_status}"

            LOGGER.info(attendance_msg)
            print(attendance_msg)

    ###########################################################################


###############################################################################

if __name__ == '__main__':
    main()

###############################################################################
