# Spam Whistle

Given a spam email in .eml format, this program:
- Finds the sending mailserver
- Does a whois lookup for said server
- Finds the registrar abuse contact
- Sends an email reporting the abuse, and attaches the eml file.

## Usage

```bash
python3 spamwhistle.py [emlfile]
```

## Notes

Dependencies (requires auth keys):
- whoisxmlapi.com
- mailgun.com

If the proper registrar abuse contact cannot be found (these are sometimes
not listed for whatever reason) the program will look for admin, tech or
general contact emails and use them instead (in that priority order). 
