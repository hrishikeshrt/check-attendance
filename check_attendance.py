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
# Preferences

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".attendance")

SECURE_CONFIG_FILE = os.path.join(CONFIG_DIR, "config.secure")
UNSAFE_CONFIG_FILE = os.path.join(CONFIG_DIR, "config.unsafe")

LOG_FILE = os.path.join(CONFIG_DIR, "log")

# ----------------------------------------------------------------------- #

os.makedirs(CONFIG_DIR, exist_ok=True)

###############################################################################
# Logger

LOGGER = logging.getLogger(__name__)
FORMATTER = logging.Formatter(
    fmt="[%(asctime)s] %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)

FILE_HANDLER = logging.FileHandler(LOG_FILE)
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)

###############################################################################

if not GNUPG_FOUND:
    LOGGER.warning("Could not find GnuPG, using plaintext storage.")

###############################################################################

CONTEXT = {"login": None, "attendance_list": None, "details": None}

###############################################################################


def setup_gnupg():
    """Setup GnuPG Encryption"""
    gpg_home = os.path.join(HOME_DIR, ".gnupg")
    gpg_agent = os.path.join(gpg_home, "S.gpg-agent")

    # ----------------------------------------------------------------------- #

    # GPG agent information
    os.environ["GPG_AGENT_INFO"] = f"{gpg_agent}:0:1"

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

###############################################################################


class Configuration:

    def __init__(self, config=None, secure=GNUPG_FOUND):
        self.gpg = None
        self._config = config or {}

        if secure:
            self.gpg = setup_gnupg()

        if self.gpg is None:
            LOGGER.warning("Could not setup GnuPG.")
            self.secure = False
            self.gnupg_key = None
            self.path = SECURE_CONFIG_FILE
        else:
            keys = self.gpg.list_keys()
            self.gnupg_key = keys[0]["keyid"]
            self.secure = True
            self.path = UNSAFE_CONFIG_FILE

    # ----------------------------------------------------------------------- #

    def get(self, k):
        return self._config.get(k)

    def set(self, k, v):
        self._config[k] = v

    # ----------------------------------------------------------------------- #

    def read(self):
        self._config = {}
        if os.path.isfile(self.path):
            with open(self.path, mode="r", encoding="utf-8") as f:
                self._config = json.load(self.decrypt(f.read()))

        return self._config

    def save(self):
        with open(self.path, mode="w", encoding="utf-8") as f:
            f.write(self.encrypt(json.dumps(self._config)))

    # ----------------------------------------------------------------------- #

    def encrypt(self, s):
        if self.secure:
            return str(self.gpg.encrypt(s, self.gnupg_key))
        return s

    def decrypt(self, s):
        if self.secure:
            return str(self.gpg.decrypt(s))
        return s

    # ----------------------------------------------------------------------- #


###############################################################################


def configure(fresh=False, secure=GNUPG_FOUND):
    """Get or Set Configuration"""

    decrypt = lambda x: x
    encrypt = lambda x: x

    if secure:
        gpg = setup_gnupg()
        if gpg is None:
            LOGGER.warning("Could not setup GnuPG, using plaintext storage.")
        else:
            keys = gpg.list_keys()
            key = keys[0]["keyid"]
            decrypt = lambda x: str(gpg.decrypt(x))
            encrypt = lambda x: str(gpg.encrypt(x, key))

    # ----------------------------------------------------------------------- #

    config_file = SECURE_CONFIG_FILE if secure else UNSAFE_CONFIG_FILE
    config = {}
    if os.path.isfile(config_file) and not fresh:
        LOGGER.info("Reading from config file ...")
        try:
            with open(config_file, "r") as f:
                config = json.loads(decrypt(f.read()))
        except Exception:
            LOGGER.error("Couldn't read configuration file.")

    if not config:
        LOGGER.info("Initiating fresh config ...")

        config = {"smtp": {}, "kendra": {}, "pingala": {}}

        config["pingala"]["username"] = ""
        config["pingala"]["password"] = ""
        config["pingala"]["check"] = True

        config["kendra"]["username"] = ""
        config["kendra"]["password"] = ""
        config["kendra"]["check"] = True

        config["smtp"]["username"] = ""
        config["smtp"]["password"] = ""
        config["smtp"]["check"] = False

        username = getpass.getuser()

        for name, details in config.items():
            # --------------------------------------------------------------- #

            prompt = f"'{name}' username (default: {username}): "
            answer = input(prompt)
            if answer == "":
                answer = username
            else:
                username = answer

            details["username"] = answer

            # --------------------------------------------------------------- #

            prompt = f"'{name}' password: "
            answer = getpass.getpass(prompt)

            details["password"] = answer

            # --------------------------------------------------------------- #

        with open(config_file, "w") as f:
            f.write(encrypt(json.dumps(config)))

    config["pingala"]["function"] = get_pingala_attendance
    config["kendra"]["function"] = get_kendra_attendance

    return config


###############################################################################
###############################################################################
# Session Classes
# NOTE: Currently not used, but worth transitioning to, soon.


class KendraSession:
    """Kendra Session"""

    SERVER = "https://kendra.cse.iitk.ac.in/kendra/pages/"
    SITEMAP = {
        "login": "AuthenticateUser.php",
        "logout": "Logout.php",
        "profile": "MyProfile.php",
        "attendance": "StudentAttendanceReport1.php"
    }

    def __init__(self, username, password):
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.login()

    def url_for(self, option):
        if option in self.SITEMAP:
            return f"{self.SERVER}{self.SITEMAP[option]}"

    def login(self):
        data = {
            "TR_Username": self.username,
            "TR_Password": self.password,
        }

        self.session.post(self.url_for("login"), data=data)
        check_response = self.session.get(self.url_for("profile"))
        self.logged_in = self.username in check_response.text
        if self.logged_in:
            LOGGER.info("Kendra login successful.")
        else:
            LOGGER.error("Kendra login failed.")
        # CONTEXT["login"] = self.logged_in
        return self.logged_in

    def logout(self):
        self.session.get(self.url_for("logout"))

    def get_month_attendance(self, month, year):
        """Fetch attendance for the specified month"""
        if not self.logged_in:
            self.login()

        if not self.logged_in:
            CONTEXT["details"] = "Attendance may or may not have been marked."
            return None

        attendance_options = f"Select=&val=i&FMonth={month}&FYear={year}"
        attendance_url = f"{self.url_for('attendance')}?{attendance_options}"

        response = self.session.get(attendance_url)
        soup = BeautifulSoup(response.text, "html.parser")
        tbody = soup.find("tbody")
        month_attendance = {}
        for td in tbody.find_all("td"):
            if "title" in td.attrs:
                attendance_status = td.text
                if attendance_status == "-":
                    attendance_status = None
                month_attendance[td["title"]] = attendance_status

        return month_attendance

    def get_attendance(self, date):
        """Fetch attendance for the specified date"""
        day, month, year = date.split("-")
        month_attendance = self.get_month_attendance(month, year)
        if not month_attendance:
            CONTEXT["attendance_list"] = False
            attendance_status = None
        else:
            CONTEXT["attendance_list"] = True
            attendance_status = month_attendance.get(day)
        return attendance_status


class PingalaSession:
    """Pingala Session"""

    SERVER = "https://pingala.iitk.ac.in/IITK-0/"
    SITEMAP = {
        "login_form": "login",
        "login": "j_spring_security_check",
        "logout": "j_spring_security_logout",
        "login_check": "logincheck",
        "attendance": "listMyAttendanceDetails"
    }

    def __init__(self, username, password):
        self.session = requests.Session()
        self.username = username
        self.password = password
        self._csrf = None
        self.login()

    def url_for(self, option):
        if option in self.SITEMAP:
            return f"{self.SERVER}{self.SITEMAP[option]}"

    def login(self):
        login_data = {
            "javascriptAbility": "Disable",
            "username": self.username,
            "password": self.password,
            "_csrf": None,
        }
        r = self.session.get(self.url_for("login_form"))
        soup = BeautifulSoup(r.text, "html.parser")
        self._csrf = soup.find("input", {"name": "_csrf"})["value"]
        login_data["_csrf"] = self._csrf

        self.session.post(self.url_for("login"), data=login_data)
        check_response = self.session.get(self.url_for("login_check"))
        self.logged_in = self.username in check_response.text
        if self.logged_in:
            soup = BeautifulSoup(check_response.text, "html.parser")
            self._csrf = soup.find("input", {"name": "_csrf"})["value"]
            LOGGER.info("Pingala login successful.")
        else:
            LOGGER.error("Pingala login failed.")
        # CONTEXT["login"] = self.logged_in
        return self.logged_in

    def logout(self):
        logout_data = {
            "_csrf": self._csrf
        }
        self.session.post(self.url_for("logout"), data=logout_data)

    def get_period_attendance(self, from_date, to_date):
        """Fetch attendance for the specified period"""
        if not self.logged_in:
            self.login()

        if not self.logged_in:
            CONTEXT["details"] = "Attendance may or may not have been marked."
            return None

        attendance_options = f"from_date={from_date}&to_date={to_date}"
        attendance_url = f"{self.url_for('attendance')}?{attendance_options}"

        response = self.session.get(attendance_url)
        response_dict = json.loads(response.text)
        attendance_details_list = response_dict["listMyAttendanceDetails"]

        CONTEXT["attendance_list"] = len(attendance_details_list) > 0
        if not CONTEXT["attendance_list"]:
            return None

        period_attendance = {}
        attendance_details_list = sorted(
            attendance_details_list,
            key=lambda x: x["date"]
        )
        for day_details in attendance_details_list:
            year, month, day = day_details["date"].split("-")
            day_date = "-".join([day, month, year])
            period_attendance[day_date] = {
                "status": day_details["status"],
                "intime": day_details["intime"],
                "device_in": day_details["device_in"]
            }
        return period_attendance

    def get_attendance(self, date):
        """Fetch attendance for the specified date"""
        day, month, year = date.split("-")

        month_attendance = self.get_period_attendance(
            f"01-{month}-{year}",
            f"01-{int(month) % 12 + 1}-{year + (month == '12')}"
        )
        if month_attendance:
            attendance_details = month_attendance.get(date)

        attendance_status = attendance_details["intime"]
        special = attendance_details["status"] in ["Week Off", "Present"]
        if not attendance_status and special:
            attendance_status = attendance_details["status"]

        return attendance_details, attendance_status


###############################################################################
###############################################################################


def get_kendra_attendance(username, password, date):
    """
    Fetch attendance from Kendra
    """

    server = "https://kendra.cse.iitk.ac.in/kendra/pages/"

    login_url = server + "AuthenticateUser.php"
    logout_url = server + "Logout.php"
    profile_url = server + "MyProfile.php"
    attendance_url = server + "StudentAttendanceReport1.php?"
    attendance_options = "Select=&val=i&FMonth={}&FYear={}"

    day, month, year = date.split("-")
    attendance_options = attendance_options.format(month, year)

    data = {
        "TR_Username": username,
        "TR_Password": password,
    }

    s = requests.Session()
    s.post(login_url, data=data)
    check_response = s.get(profile_url)
    if username in check_response.text:
        LOGGER.info("Kendra login successful.")
        CONTEXT["login"] = True
    else:
        LOGGER.error("Kendra login failed.")
        CONTEXT["login"] = False
        CONTEXT["details"] = "Attendance may or may not have been marked."
        return None

    response = s.get(attendance_url + attendance_options)
    soup = BeautifulSoup(response.text, "html.parser")
    attendance_element = soup.find("td", {"title": str(int(day))})
    if not attendance_element:
        CONTEXT["attendance_list"] = False
        attendance_status = None
    else:
        CONTEXT["attendance_list"] = True
        attendance_status = attendance_element.text

    s.get(logout_url)
    s.close()

    if attendance_status == "-":
        attendance_status = None

    return attendance_status


###############################################################################


def get_pingala_attendance(username, password, date):
    """
    Fetch attendance from Pingala
    """

    server = "https://pingala.iitk.ac.in/IITK-0/"

    form_url = server + "login"
    login_url = server + "j_spring_security_check"
    logout_url = server + "j_spring_security_logout"
    logincheck_url = server + "logincheck"
    attendance_url = server + "listMyAttendanceDetails?from_date={}&to_date={}"

    login_data = {
        "javascriptAbility": "Disable",
        "username": username,
        "password": password,
        "_csrf": None,
    }

    logout_data = {}

    s = requests.Session()
    r = s.get(form_url)
    soup = BeautifulSoup(r.text, "html.parser")
    csrf = soup.find("input", {"name": "_csrf"})["value"]
    login_data["_csrf"] = csrf

    s.post(login_url, data=login_data)
    check_response = s.get(logincheck_url)
    if username in check_response.text:
        LOGGER.info("Pingala login successful.")

        soup = BeautifulSoup(check_response.text, "html.parser")
        csrf = soup.find("input", {"name": "_csrf"})["value"]
        logout_data["_csrf"] = csrf
        CONTEXT["login"] = True
    else:
        LOGGER.error("Pingala login failed.")
        CONTEXT["login"] = False
        CONTEXT["details"] = "Attendance may or may not have been marked."
        return None

    response = s.get(attendance_url.format(date, date))
    response_dict = json.loads(response.text)
    attendance_details_list = response_dict["listMyAttendanceDetails"]

    if len(attendance_details_list) == 0:
        CONTEXT["attendance_list"] = False
        return None

    CONTEXT["attendance_list"] = True

    attendance_details = attendance_details_list[0]
    attendance_status = attendance_details["intime"]
    special = attendance_details["status"] in ["Week Off", "Present"]
    if not attendance_status and special:
        attendance_status = attendance_details["status"]

    s.post(logout_url, data=logout_data)
    s.close()

    return attendance_status


###############################################################################


def sendmail(smtp_user, smtp_pass, subject="", content=""):
    """
    Send a notification email using CSE SMTP.
    """
    # ----------------------------------------------------------------------- #

    smtp_port = 587
    smtp_addr = "smtp.cse.iitk.ac.in"

    # ----------------------------------------------------------------------- #

    # compose mail
    msg = EmailMessage()
    msg.set_content(content)
    msg["Subject"] = subject
    msg["From"] = f"Attendance Reminder <{smtp_user}@cse.iitk.ac.in>"
    msg["To"] = f"{smtp_user}@cse.iitk.ac.in"

    # send mail
    if smtp_pass:
        mailer = smtplib.SMTP(f"{smtp_addr}:{smtp_port}")
        mailer.starttls()
        mailer.login(smtp_user, smtp_pass)
        mailer.send_message(msg)
        mailer.quit()
        LOGGER.info("Reminder e-mail sent.")
    else:
        LOGGER.error("No credentials found. E-mail was not sent.")


###############################################################################


def main():
    today = datetime.datetime.now().strftime("%d-%m-%Y")

    ###########################################################################

    desc = "Check and Remind if attendance is not marked (Kendra, Pingala)"

    p = argparse.ArgumentParser(description=desc)
    p.add_argument("-d", "--date", help="date dd-mm-yyyy", default=today)
    p.add_argument(
        "-f", "--force", help="force re-configure", action="store_true"
    )
    p.add_argument(
        "--unsafe", help="Store credentials in plaintext", action="store_true"
    )
    p.add_argument(
        "-v",
        "--verbose",
        help="Verbose output and logging",
        action="store_true",
    )

    args = vars(p.parse_args())

    date = args["date"]
    fresh = args["force"]
    secure = not args["unsafe"]
    verbose = args["verbose"]

    date_object = datetime.date(*map(int, reversed(date.split("-"))))
    day_of_week = date_object.strftime("%A")
    is_weekday = day_of_week not in ["Saturday", "Sunday"]

    if verbose:
        LOGGER.setLevel(logging.INFO)
        LOGGER.addHandler(logging.StreamHandler())

    ###########################################################################

    config = configure(fresh=fresh, secure=secure)

    smtp_user = config["smtp"]["username"]
    smtp_pass = config["smtp"]["password"]

    ###########################################################################

    for name in ["kendra", "pingala"]:
        title = name.title()
        details = config.get(name, {})

        if details and details.get("check"):
            username = details["username"]
            password = details["password"]
            fetch_attendance = details["function"]

            try:
                attendance_status = fetch_attendance(username, password, date)
            except Exception as e:
                LOGGER.error(e)
                attendance_status = None
                subject = f"Error in fetching attendance from {title}"
                content = traceback.print_exec()
                sendmail(smtp_user, smtp_pass, subject, content)

            # send reminder mail if applicable (not marked and not weekend)
            if attendance_status is None and is_weekday:
                attendance_status = "not marked!"
                LOGGER.info(f"Attendance not marked on {title} for {date}")

                # reminder only for today
                if date == today:
                    subject = f"Mark attendance on {title} for {today}"
                    content = ""

                    # login failed, so uncertain
                    if not CONTEXT["login"]:
                        subject = f"Login to {title} failed."
                    if CONTEXT["details"]:
                        content = CONTEXT["details"]

                    sendmail(smtp_user, smtp_pass, subject, content)

            attendance_msg = f"{title}: [{date}] {attendance_status}"

            LOGGER.info(attendance_msg)
            print(attendance_msg)

    ###########################################################################


###############################################################################

if __name__ == "__main__":
    main()

###############################################################################
