#!/bin/env python3

import argparse
import base64
import configparser
import requests
import json
import sys


def parse_args():
    '''Parse commandline arguments and return an argparse.Namespace object'''
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--config', help="config file", required=True,
                        type=argparse.FileType('r'))
    parser.add_argument('-t', '--print_token', help='print OKAPI token and exit',
                        action='store_true')
    return parser.parse_args()


def get_configuration(file):
    pass


def get_auth_token(okapi_base_url, tenant, username, password):
    ''' Authenticate to OKAPI and return authentication token'''
    
    url = okapi_base_url+'/authn/login'
    headers = {"Content-type": "application/json", "X-Okapi-Tenant": tenant}
    payload = {"username": username, "password": password}
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    return r.headers['x-okapi-token']


def get_sp_metadata(okapi_base_url, tenant, token):
    url = okapi_base_url+'/configurations/entries/'
    headers = {"Content-type": "application/json",
               "X-Okapi-Tenant": tenant,
               "X-Okapi-Token": token}
    r = requests.get(url, headers=headers)
    return r.content


def generate_sp_metadata(okapi_base_url, tenant, token):
    url = okapi_base_url+'/saml/regenerate'
    headers = {"Content-type": "application/json",
               "X-Okapi-Tenant": tenant,
               "X-Okapi-Token": token}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    # unpack base64-encoded metadata and decode byte string into UTF-8
    sp_metadata = base64.b64decode(response.json()['fileContent']).decode('utf-8')
    return sp_metadata


def main():
    args = parse_args()

    config = configparser.ConfigParser()
    try:
        config.read_file(args.config)
    except configparser.Error as err:
        print(err)
        sys.exit(1)

    # do the work
    token = get_auth_token(config['OKAPI']['okapi_base_url'],
                           config['OKAPI']['tenant'],
                           config['OKAPI']['username'],
                           config['OKAPI']['password'])
    if args.print_token:
        print(token)
        sys.exit(0)

    # TODO: first try to pull SP metadata from configuration module
    # Note: Looks like maybe SP metdata is not stored.
        
    sp_metadata = generate_sp_metadata(config['OKAPI']['okapi_base_url'],
                                       config['OKAPI']['tenant'],
                                       token)
    sys.stdout.write(sp_metadata)
    

if __name__ == '__main__':
    main()
