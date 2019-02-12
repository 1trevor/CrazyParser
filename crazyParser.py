#!/usr/bin/python

import argparse
import os
import sys
import subprocess
import csv
import smtplib
import tempfile
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
import atexit
#import automationassets
#from automationassets import AutomationAssetNotFound

mail_recip = ["recipient1@domain.com", "recipient2@domain.com"]
#mail_creds = automationassets.get_automation_credential("Alerts")
mail_creds = {"username": "alerts@domain.com", "password": "12345"}
mail_server = 'smtp.office365.com'
mail_port = 587
dnstwistPath = '/opt/dnstwist/dnstwist.py'

# set up global defaults
tempFiles = [] # define temporary files array

def checkPerms(docRoot, resultsFile):
    # Test if we have execute permissions to docRoot
    if not os.access(docRoot, os.X_OK):
        print "Destination directory " + docRoot + " not accessible."
        print "Please check permissions.  Exiting..."
        sys.exit()
    else:
        pass

    # Test if we have write permissions to docRoot
    try:
        permtest = tempfile.TemporaryFile('w+b', bufsize=-1, dir=docRoot)
    except OSError:
        print "Unable to write to desired directory: " + docRoot + "."
        print "Please check permissions.  Exiting..."
        sys.exit()

def checkDepends(myDomains, knownDomains, docRoot, resultsFile):
    # Test if mydomains.csv exists
    if not os.access(myDomains, os.F_OK) or not os.access(knownDomains, os.F_OK):
        print "Required configuration files - mydomains.csv or knowndomains.csv - not found."
        print "Please verify configuration.  Exiting..."
        sys.exit()
    else:
        pass

    # Test if docRoot is actually a directory
    if not os.path.isdir(docRoot):
        print "Argument: -d " + docRoot + " is not a directory."
        print "Please review arguments.  Exiting..."
        sys.exit()
    else:
        pass

    # Ensure resultsFile isn't actually a directory
    if os.path.exists(resultsFile) and not os.path.isfile(resultsFile):
    #if not os.path.isfile(resultsFile):
        print "Argument: -o " + resultsFile + " should be a regular file but is something else."
        print "Please review arguments.  Exiting..."
        sys.exit()
    else:
        pass
        
    if not os.access(dnstwistPath, os.F_OK):
        print "DNStwist specified as " + dnstwistPath + "but was not found."
        print "Please check dnstwistPath in crazyParser.py.  Exiting..."
        sys.exit()
                 
def doCrazy(docRoot, resultsFile, myDomains):
    # cleanup old results file
    try:
        os.remove(resultsFile)
    except OSError:
        pass
    
    with open(myDomains, 'rbU') as domains:
        reader = csv.reader(domains)
        for domain in domains:
            domain = domain.rstrip()

            # Run dnstwist if enabled
            dtargs=[dnstwistPath, '-r', '-f', 'csv', domain]
	    dtoutfile = tempfile.NamedTemporaryFile('w', bufsize=-1, suffix='.dttmp', prefix=domain + '.', dir=docRoot, delete=False)
            try:
                with open(dtoutfile.name, 'wb') as dtout:
                    output=subprocess.check_output(dtargs, shell=False)
                    dtout.write(output)
                tempFiles.append(dtoutfile.name)
            except:
                # An error occurred running dnstwist
                print "Unexpected error running dnstwist:", sys.exc_info()[0]
                pass
    
def parseOutput(docRoot, knownDomains, resultsFile):
    # set up domains dictionary
    domains = []

    # compare known domains to discovered domains
    knowndom = []
    with open (knownDomains, 'rbU') as domfile:
        reader = csv.DictReader(domfile)
        for row in reader:
            knowndom.append(row['Domain'])

    # Parse each dnstwist temp file in tempFiles list
    for file in tempFiles:
        if file.endswith(".dttmp"):
            with open (file, 'rbU') as csvfile:
                reader = csv.reader(csvfile)
                next(reader) # Due to recent change in dnstwist, skip header line
                next(reader) # skip second line, contains original domain
                for row in reader:
                    if row[1] in knowndom:
                        pass
                    else:
                        domains.append(row)
    
    # write out results
    # this file will only contain the header if there are no new results
    with open(resultsFile, 'wb') as outfile:
        outfile.write('fuzzer,domain-name,dns-a,dns-aaaa,dns-mx,dns-ns,geoip-country,whois-created,whois-updated,ssdeep-score\n')
        for row in domains:
            outfile.write(",".join(row) + '\n')
    outfile.close()

def sendMail(resultsFile):

    def mail(to, subject, html, resultsFile, numResults):
            msg = MIMEMultipart('alternative')
            msg['From'] = mail_creds["username"]
            msg['To'] = ", ".join(to)
            msg['Subject'] = subject
            msg.attach(MIMEText(html, 'html'))
            mailServer = smtplib.SMTP(mail_server, mail_port)
            mailServer.ehlo()
            mailServer.starttls()
            mailServer.ehlo()
            mailServer.login(mail_creds["username"], mail_creds["password"])
            mailServer.sendmail(mail_creds["username"], to, msg.as_string())
            mailServer.close()
    
    # this counts the number of line in the results file
    # if it is 1, there were no results
  
    numResults = sum(1 for line in open(resultsFile))
    if numResults >= 2:
        html = """\
        <html>
        <head>
        <style>
        table, th, td {
            border: 1px solid black;
        }
        </style>
        </head>
            <body>
                The following new domains have been registered recently. Please investigate!<br><br>
                <table cellpadding="4" cellspacing="0">
                    <tr style="font-weight:bold">
                        <td>
                            Domain
                        </td>
                        <td>
                            A record
                        </td>
                        <td>
                            MX record
                        </td>
                        <td>
                            NS record
                        </td>
                    </tr>
        """
        rfile = open(resultsFile)
        lines = rfile.readlines()[1:]
        for line in lines:
            html += "<tr><td>" + line.split(',')[1] + "</td><td>" + line.split(',')[2] + "</td><td>" + line.split(',')[4] + "</td><td>" + line.split(',')[5] + "</td></tr>"
        html += """</table>
            </body>
        </html>
        """

        mail(mail_recip,
                "Alert: New suspicious domain registration", # subject line
                html, resultsFile, numResults)

def doCleanup(docRoot):
    # Delete all temporary .tmp files created by urlcrazy and dnstwist
    for f in tempFiles:
        try:
            os.remove(f)
        except OSError:
            print "Error removing temporary file: " + f
            pass

def dedup(domainslist, idfun=None):
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in domainslist:
        marker = idfun(item)
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result

def main():
    configDir = '/opt/CrazyParser/'
    docRoot = '/opt/CrazyParser/'

    # set up global files
    resultsFile = os.path.join(docRoot, 'results.csv')
    myDomains = os.path.join(configDir,'mydomains.csv')
    knownDomains = os.path.join(configDir,'knowndomains.csv')

    # Check to make sure we have the necessary permissions
    checkPerms(docRoot, resultsFile)

    # Check dependencies
    checkDepends(myDomains, knownDomains, docRoot, resultsFile)

    # Clean up output files at exit
    atexit.register(doCleanup, docRoot)
    
    # Execute discovery
    doCrazy(docRoot, resultsFile, myDomains)

    # parse output
    parseOutput(docRoot, knownDomains, resultsFile)

    # send results
    sendMail(resultsFile)

if __name__ == "__main__":
    main()

