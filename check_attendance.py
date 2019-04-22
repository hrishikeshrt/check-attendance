#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Hrishikesh Terdalkar

Attendance Checker and Reminder for IITK CSE
Checks both on Kendra and Pingala
"""

import os
import json
import gnupg
import getpass
import smtplib
import requests
import datetime
import argparse

from bs4 import BeautifulSoup
from email.message import EmailMessage

###############################################################################
###############################################################################
# Edit in configure()


def configure():
    '''
    Configuration
    
    Requirements:
    GnuPG encrypted passwords to be stored in
      ~/.attendance/smtp.gpg
      ~/.attendance/kendra.gpg
      ~/.attendance/pingala.gpg
    '''
    home_dir = os.path.expanduser('~')
    gpg_home = os.path.join(home_dir, '.gnupg/')

    attendance_dir = os.path.join(home_dir, '.attendance')

    config = {'smtp': {}, 'kendra': {}, 'pingala': {}}

    config['pingala']['username'] = ''
    config['pingala']['password'] = ''
    config['pingala']['gpg'] = os.path.join(attendance_dir, 'pingala.gpg')
    config['pingala']['function'] = get_pingala_attendance
    config['pingala']['check'] = True

    config['kendra']['username'] = ''
    config['kendra']['password'] = ''
    config['kendra']['gpg'] = os.path.join(attendance_dir, 'kendra.gpg')
    config['kendra']['function'] = get_kendra_attendance
    config['kendra']['check'] = True

    config['smtp']['username'] = ''
    config['smtp']['password'] = ''
    config['smtp']['gpg'] = os.path.join(attendance_dir, 'smtp.gpg')
    config['smtp']['check'] = False

    for name, details in config.items():
        # ------------------------------------------------------------------- #
        if details['username'] == '':
            details['username'] = getpass.getuser()

        # ------------------------------------------------------------------- #
        # get password if not set
        if details['password'] == '' and os.path.isfile(details['gpg']):
            gpg = gnupg.GPG(gnupghome=gpg_home, use_agent=True)
            with open(details['gpg'], 'rb') as f:
                details['password'] = str(gpg.decrypt(f.read())).strip()

        # ------------------------------------------------------------------- #

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
    # profile_url = server + 'MyProfile.php'
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
    # logout_url = server + 'j_spring_security_logout'
    logincheck_url = server + 'logincheck'
    attendance_url = server + 'listMyAttendanceDetails?from_date={}&to_date={}'

    data = {
        'javascriptAbility': 'Disable',
        'username': username,
        'password': password,
        '_csrf': None
    }

    s = requests.Session()
    r = s.get(form_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find('input', {"name": "_csrf"})['value']
    data['_csrf'] = csrf

    s.post(login_url, data=data)
    s.get(logincheck_url)

    response = s.get(attendance_url.format(date, date))
    response_dict = json.loads(response.text)
    attendance_details = response_dict['listMyAttendanceDetails'][0]
    attendance_time = attendance_details['intime']
    week_off = attendance_details['status'] == 'Week Off'

    if week_off:
        attendance_time = attendance_details['status']

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

    # compose mail
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = f'Mark attendance on {source.title()} for {date}'
    msg['From'] = f'Attendance Reminder <{smtp_user}@cse.iitk.ac.in>'
    msg['To'] = f'{smtp_user}@cse.iitk.ac.in'

    # send mail
    if smtp_pass:
        mailer = smtplib.SMTP(f'{smtp_addr}:{smtp_port}')
        mailer.starttls()
        mailer.login(smtp_user, smtp_pass)
        mailer.send_message(msg)
        mailer.quit()
        print("Reminder e-mail sent.")
    else:
        print("Error: no credentials. e-mail was not sent.")

###############################################################################


def main():
    today = datetime.datetime.now().strftime("%d-%m-%Y")

    config = configure()

    smtp_user = config['smtp']['username']
    smtp_pass = config['smtp']['password']

    ###########################################################################

    desc = "Get Pingala Attendance Time"

    p = argparse.ArgumentParser(description=desc)
    p.add_argument("-d", help="date dd-mm-yyyy", default=today)
    args = vars(p.parse_args())
    date = args['d']

    ###########################################################################

    for name, details in config.items():
        if details['check']:
            username = details['username']
            password = details['password']
            fetch_attendance = details['function']

            attendance_time = fetch_attendance(username, password, date)
            if attendance_time is None:
                attendance_time = "not marked!"

                if date == today:
                    notify(smtp_user, smtp_pass, name, today)

            print(f"{name}: [{date}]: {attendance_time}")

    ###########################################################################


###############################################################################

if __name__ == '__main__':
    main()

###############################################################################
