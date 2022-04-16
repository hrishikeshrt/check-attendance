# Attendance Checker and Reminder for IITK CSE

Checks both on **Kendra** and **Pingala**

## Instructions

```
usage: check_attendance.py [-h] [-d DATE] [-f] [--unsafe] [-v]

Check and Remind if attendance is not marked (Kendra, Pingala)

optional arguments:
  -h, --help            show this help message and exit
  -d DATE, --date DATE  date dd-mm-yyyy
  -f, --force           force re-configure
  --unsafe              Store credentials in plaintext
  -v, --verbose         Verbose output and logging
```

### Basic Usage

```python3 check_attendance.py```

Checks if the attendance was marked on the day the script is run, and if it
wasn't and the day isn't a weekend, a reminder is sent.

### Automated Check

The command can be added as a cron job. Run the command `crontab -e` and add
the following line at the end, for running the script at 5pm, 8pm and 11pm.

```
    0 17,20,23 * * * <path_to_python3> <path_to_the_script>
```

## Requirements:

* `requests>=2.27.1`
* `beautifulsoup4>=4.11.1`
* `python_gnupg>=0.4.7` (required for secure storage)

Install all requirements using `pip install -r requirements.txt`
