# report spam emails
import sys
import env
from requests import get, post
import json


def find_email_in_blob(blob, sub):
    # find all occurrences
    occs = []
    i = 0
    while i < len(blob):
        i = blob.find(sub, i)
        if i == -1:
            break
        occs.append(i)
        i += len(sub)

    if len(occs) == 0:
        return None

    for occi in occs:

        email = sub
        j = occi - 1
        while blob[j] in ['.', '@'] or blob[j].isalnum():
            email = blob[j] + email
            j -= 1

        j = occi + len(sub)
        while blob[j] in ['.', '@'] or blob[j].isalnum():
            email += blob[j]
            j += 1

        if email.find('.') > -1 and email.find('@') > -1:
            return email
        else:
            continue  # try next occurrence

    return None


def find_abuse(whoisdata):
    """Search through whois output for abuse contact email"""
    blob = json.dumps(whoisdata)

    abuse_email = find_email_in_blob(blob, 'abuse')
    if abuse_email is None:
        abuse_email = find_email_in_blob(blob, 'complain')
        if abuse_email is None:
            if 'customField1Value' in whoisdata['WhoisRecord']:  # get from custom field
                abuse_email = whoisdata['WhoisRecord']['customField1Value']

            elif 'administrativeContact' in whoisdata['WhoisRecord']['registryData']:  # contact general admin
                abuse_email = whoisdata['WhoisRecord']['registryData']['administrativeContact']['email']

            elif 'technicalContact' in whoisdata['WhoisRecord']['registryData']:
                abuse_email = whoisdata['WhoisRecord']['registryData']['technicalContact']['email']

            elif 'contactEmail' in whoisdata['WhoisRecord']:
                abuse_email = whoisdata['WhoisRecord']['contactEmail']

            else:
                # last resort: any email
                abuse_email = find_email_in_blob(blob, '@')
                if abuse_email is None:  # absolutely nothing found
                    return None

    return abuse_email


def is_domain(text):
    """text contains dots and does not contain exclusively numbers beyond that"""
    dots = False
    nonnum = False
    for let in text:
        if let == '.':
            dots = True
        elif let.isalnum() and not let.isdigit():
            nonnum = True
        if dots and nonnum:
            return True
    return False


def clean_dom(text):
    """rid brackets and tld-dot-end"""
    dom = ''
    for let in text:
        if let == '.' or let.isalnum():
            dom += let
    if dom[-1] == '.':
        dom = dom[:-1]
    return dom


def get_sender_domain(emlarr):
    for line in emlarr:
        if line.startswith('Received: from'):
            words = line.split(' ')
            doms = [w for w in words if is_domain(w)]
            return clean_dom(doms[-1])  # last domain in the line
    return None


def email_domain_abuse(email, domain, emlfile):
    resp = post('https://api.eu.mailgun.net/v3/'+env.EMAIL_DOMAIN+'/messages', data={
        'from': 'Spam Whistle <spamwhistle@'+env.EMAIL_DOMAIN+'>',
        'to': email,
        'subject': 'Spam email report',
        'html': """
        <p>Good day</p>
        <p>This email serves as notification that a domain you are responsible for is being used to
            send bad-faith spam/scam emails. Attached is an email sent from """+domain+""" (refer to the headers).</p>
        <p>Please take the appropriate action to stop this abuse.</p>
        <p>Regards<br/>Spam Whistle</p>
        <p><br/>P.S. Even though this email was sent automatically, the mailbox of this address is monitored. 
            Feel free to reply.</p> 
        """},
        files=[("attachment", open(emlfile))],
        auth=('api', env.MAILGUN_KEY)
    )

    return resp.status_code // 100 == 2


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please specify spam eml file')
        exit(1)

    emlfile = sys.argv[1]
    emlarr = open(emlfile, 'r').readlines()

    sender = get_sender_domain(emlarr)
    print('Originating mailserver:', sender)

    whoisdata = get(
        'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=' + env.WHOIS_KEY + '&domainName=' + sender +
        '&outputFormat=JSON').json()

    abuse_email = find_abuse(whoisdata)
    if abuse_email is None:
        print('Could not find abuse email :/')
        exit()

    print('Abuse email:', abuse_email)

    esucc = email_domain_abuse(abuse_email, sender, emlfile)

    if esucc:
        print('Report email successfully sent.')
    else:
        print('Failed to send report email.')

    print('Done.')
