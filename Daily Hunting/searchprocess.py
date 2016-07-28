#!/usr/bin/python
"""
    Author: Matthew Willig
    Elsa API query
    elsa_query.ini format:
        [MAIN]
        user = elsa
        ip =
        apikey =
"""

from __future__ import print_function
from yattag import Doc
import optparse
import time
import hashlib
from requests import Request, Session
import json
import datetime
from configparser import ConfigParser
import urllib


# Global variables


def query_elsa(user, apikey, ip, query):
    url = 'https://' + ip + '/elsa-query/API/query'
    epoch = int(time.time())
    hash_it = hashlib.sha512()
    hash_it.update(str(epoch) + apikey)
    header = {}
    header['Authorization'] = 'ApiKey ' + user + ':' + str(epoch) + ':' + hash_it.hexdigest()
    s = Session()
    payload = '{"class_id":{"0": 1},"program_id":{"0": 1},"node_id":{"0": 1},"host_id":{"0": 1}}'
    elsa_post = Request('POST',
                        url,
                        data=[('permissions', payload), ('query_string', query)],
                        headers=header)
    data = elsa_post.prepare()
    results = s.send(data, verify=False)
    return results

def start_query(user, apikey, ip):
    rdptoInet = "class=BRO_RDP -(dstip>=10.0.0.0 dstip<=10.255.255.255) -(dstip>=172.16.0.0 dstip<=172.31.255.255) -(dstip>=192.168.0.0 dstip<=192.168.255.255) groupby:srcip"
    rdptoInet_result = query_elsa(user, apikey, ip, rdptoInet)
    print rdptoInet_result
    
    malProcSea = "class='WINDOWS_PROCESS' 'new process' groupby:image limit:9500 -'Program Files' -'system32' -SysWOW64 -WinSXS -'kix32.exe' -'Microsoft.NET' -'progra~2'"
    malProcSea_result = query_elsa(user, apikey, ip, malProcSea)
    
    
    rdpFromInet = "class=BRO_RDP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) groupby:srcip"
    rdpFromInet_result = query_elsa(user, apikey, ip, rdpFromInet)
    
    
    rarExfil = "class=BRO_FTP -(command='GET' OR command='RETR') mime_type='application/x-rar' -(dstip>=10.0.0.0 AND dstip<=10.255.255.255) -(dstip>=172.16.0.0 AND dstip<=172.31.255.255) -(dstip>=192.168.0.0 AND dstip<=192.168.255.255) limit:9000"
    rarExfil_result = query_elsa(user, apikey, ip, rarExfil)
    
    
    rarExfil2 = "class=BRO_HTTP -method='GET' mime_type='application/x-rar' -(dstip>=10.0.0.0 AND dstip<=10.255.255.255) -(dstip>=172.16.0.0 AND dstip<=172.31.255.255) -(dstip>=192.168.0.0 AND dstip<=192.168.255.255) -'ESS Update' -update.eset.com limit:9000"
    rarExfil2_result = query_elsa(user, apikey, ip, rarExfil2)
    
    
    webShell = "class=BRO_HTTP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) limit:9000 BRO_HTTP.status_code=200 groupby:uri"
    webShell_result = query_elsa(user, apikey, ip, webShell)
    
    
    
    
if __name__ == "__main__":
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    yesterday = (datetime.datetime.utcnow() - datetime.timedelta(1)).strftime("%Y-%m-%d %H:%M:%S")
    parser = optparse.OptionParser(usage='''
        -a, --apikey  : Elsa API key
                        If not specified then read it from the elsa_query.ini file
                        If this option is used then specify options -i and -u or accept the their defaults.
        -i, --ip      : Elsa server IP
                        Default is '127.0.0.1'

        -p, --print   : Print search results to stdout
        -u, --user    : Elsa user
                        Default is 'elsa'
        -v, --verbose : Print verbose results
        When running this on Windows you will need to escape quotes in the Elsa search string with a quote.
            \_> For example: "127.0.0.1 BRO_HTTP.uri=""/test/testing/"""
        ''')
    parser.add_option('-a', '--apikey',
                      dest='elsa_apikey', action='store', type='string')
    parser.add_option('-i', '--ip',
                      dest='elsa_ip', action='store', type='string',
                      default='127.0.0.1')
    parser.add_option('-p', '--print',
                      dest='print_it', action='store_true')
    parser.add_option('-u', '--user',
                      dest='elsa_user', action='store', type='string',
                      default='elsa')
    parser.add_option('-v', '--verbose',
                      dest='verbose', action='store_true')
    parser.add_option('-w', '--http',
                      dest='elsa_http', action='store_true')
    (options, args) = parser.parse_args()
    if not options.elsa_apikey:
        elsa_user, elsa_apikey, elsa_ip = read_conf()
    else:
        elsa_user = options.elsa_user
        elsa_ip = options.elsa_ip
        elsa_apikey = options.elsa_apikey
    
    start_query(elsa_user, elsa_apikey, elsa_ip)