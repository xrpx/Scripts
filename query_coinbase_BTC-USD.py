#!/usr/bin/env python

# Author:        	xrpx
# Description:   	Simple python script to check on Bitcoin value at the moment
# Last modified: 	May 3, 2014

import urllib2
import json
import smtplib


def send_email(rcptto, subject, data):
    '''Use Gmail to send simple email alert'''

    username = 'gmailUsername'
    password = 'gmailPassword'
    mailfrom = 'gmail.account@gmail.com'
    
    # Draft the message
    headers = "\r\n".join(["from: " + username,
                           "subject: " + subject,
                           "to: " + rcptto,
                           "mime-version: 1.0",
                           "content-type: text/html"])

    content = headers + '\r\n\r\n' + data

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.login(username, password)
    server.sendmail(mailfrom, rcptto, content)
    server.quit()


response = urllib2.urlopen('https://coinbase.com/api/v1/currencies/exchange_rates')
values = response.read()
dictionary = json.loads(values)
print 'USD to BTC: ' + dictionary['usd_to_btc']
print 'BTC to USD: ' + dictionary['btc_to_usd']

data = 'Current price\nBTC to USD: ' + dictionary['btc_to_usd']
send_email('gmail.account@gmail.com', 'Bitcoin alert', data)

