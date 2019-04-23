#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Hrishikesh Terdalkar

Attendance Checker and Reminder for IITK CSE
Checks both on Kendra and Pingala

You can add the command to cronjob by running the command `crontab -e'
and adding the  following line at the end. (for checking at 5pm, 8pm, 11pm)

    0 17,20,23 * * * python3 <path_to_the_script>

Requirements:
    beautifulsoup4
    python-gnupg

    `pip install python-gnupg`
    `pip install beautifulsoup4`
"""

import os
import json
import gnupg
import getpass
import smtplib
import logging
import requests
import datetime
import argparse

from bs4 import BeautifulSoup
from email.message import EmailMessage

###############################################################################
###############################################################################


def configure(fresh=False):
    '''
    Get or Set Configuration
    '''
    # ----------------------------------------------------------------------- #

    home_dir = os.path.expanduser('~')
    gpg_home = os.path.join(home_dir, '.gnupg')
    gpg = gnupg.GPG(gnupghome=gpg_home, use_agent=True)

    keys = gpg.list_keys()
    if len(keys) == 0:
        print("No GPG keys found. generating ...")
        user_email = input("Email for GPG Key: ")
        passphrase = getpass.getpass("Passphrase for GPG Key: ")
        key_input = gpg.gen_key_input(user_email, passphrase)
        print("We need to generate a lot of random bytes. It is a good idea "
              "to perform some other action (type on the keyboard, move the "
              "mouse, utilize the disks) during the prime generation; this "
              "gives the random number generator a better chance to gain "
              "enough entropy.")
        gpg.gen_key(key_input)
        keys = gpg.list_keys()

    key = keys[0]['keyid']

    # ----------------------------------------------------------------------- #

    attendance_dir = os.path.join(home_dir, '.attendance')
    config_file = os.path.join(attendance_dir, 'config')
    log_file = os.path.join(attendance_dir, 'log')

    logging.basicConfig(filename=log_file,
                        format='[%(asctime)s] %(levelname)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

    # ----------------------------------------------------------------------- #

    if not os.path.isdir(attendance_dir):
        os.mkdir(attendance_dir)

    if os.path.isfile(config_file) and not fresh:
        logging.info("Reading from config file")
        with open(config_file, 'r') as f:
            config = json.loads(str(gpg.decrypt(f.read())))
    else:
        logging.info("Fresh config")

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

        for name, details in config.items():
            # --------------------------------------------------------------- #

            username = getpass.getuser()

            prompt = "'{}' username (default: {}): "
            answer = input(prompt.format(name, username))
            if answer == '':
                answer = username
            details['username'] = answer

            # --------------------------------------------------------------- #

            prompt = "'{}' password: "
            answer = getpass.getpass(prompt.format(name))

            details['password'] = answer

            # --------------------------------------------------------------- #

        with open(config_file, 'w') as f:
            f.write(str(gpg.encrypt(json.dumps(config), key)))

    config['pingala']['function'] = get_pingala_attendance
    config['kendra']['function'] = get_kendra_attendance

    return config

###############################################################################
###############################################################################


def get_kendra_attendance(username, password, date):
    '''
    Fetch attendance from Kendra
    '''
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
        logging.info("Kendra login successful.")
    else:
        logging.warning("Kendra login failed.")
        return None

    response = s.get(attendance_url + attendance_options)
    soup = BeautifulSoup(response.text, 'html.parser')
    attendance_element = soup.find('td', {'title': str(day)})
    attendance_time = attendance_element.text

    s.get(logout_url)
    s.close()

    if attendance_time == "-":
        attendance_time = None

    return attendance_time

###############################################################################


def get_pingala_attendance(username, password, date):
    '''
    Fetch attendance from Pingala
    '''
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
        logging.info("Pingala login successful.")

        soup = BeautifulSoup(check_response.text, 'html.parser')
        csrf = soup.find('input', {"name": "_csrf"})['value']
        logout_data['_csrf'] = csrf
    else:
        logging.warning("Pingala login failed.")
        return None

    response = s.get(attendance_url.format(date, date))
    response_dict = json.loads(response.text)
    attendance_details = response_dict['listMyAttendanceDetails'][0]
    attendance_time = attendance_details['intime']
    week_off = attendance_details['status'] == 'Week Off'

    if week_off:
        attendance_time = attendance_details['status']

    s.post(logout_url, data=logout_data)
    s.close()

    return attendance_time

###############################################################################


def notify(smtp_user, smtp_pass, source, date):
    '''
    Send a notification email using CSE SMTP.
    '''
    # ----------------------------------------------------------------------- #

    smtp_port = 25
    smtp_addr = 'smtp.cse.iitk.ac.in'

    # ----------------------------------------------------------------------- #

    content = ''
    subject = 'Mark attendance on {} for {}'.format(source.title(), date)

    # compose mail
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = subject
    msg['From'] = 'Attendance Reminder <{}@cse.iitk.ac.in>'.format(smtp_user)
    msg['To'] = '{}@cse.iitk.ac.in'.format(smtp_user)

    # send mail
    if smtp_pass:
        mailer = smtplib.SMTP('{}:{}'.format(smtp_addr, smtp_port))
        mailer.starttls()
        mailer.login(smtp_user, smtp_pass)
        mailer.send_message(msg)
        mailer.quit()
        logging.info("Reminder e-mail sent.")
    else:
        logging.warnign("Error: no credentials. e-mail was not sent.")

###############################################################################


def main():
    today = datetime.datetime.now().strftime("%d-%m-%Y")

    ###########################################################################

    desc = "Get Pingala Attendance Time"

    p = argparse.ArgumentParser(description=desc)
    p.add_argument("-d", help="date dd-mm-yyyy", default=today)
    p.add_argument("-f", help="force re-configure", action='store_true')
    args = vars(p.parse_args())
    date = args['d']
    fresh = args['f']

    ###########################################################################

    config = configure(fresh=fresh)

    smtp_user = config['smtp']['username']
    smtp_pass = config['smtp']['password']

    ###########################################################################

    for name, details in config.items():
        title = name.title()
        if details['check']:
            username = details['username']
            password = details['password']
            fetch_attendance = details['function']

            attendance_time = fetch_attendance(username, password, date)
            if attendance_time is None:
                attendance_time = "not marked!"
                logging.info("Attendance not marked on {} for {}".format(title,
                                                                         date))
                if date == today:
                    notify(smtp_user, smtp_pass, title, today)

            attendance_msg = "{}: [{}] {}".format(title, date, attendance_time)

            logging.info(attendance_msg)
            print(attendance_msg)

    ###########################################################################


###############################################################################

if __name__ == '__main__':
    main()

###############################################################################
