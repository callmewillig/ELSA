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
from HTML import table

# Global variables
def read_conf():
    config = ConfigParser()
    config.read('./elsa_query.ini')
    user = config.get('MAIN', 'user')
    apikey = config.get('MAIN', 'apikey')
    ip = config.get('MAIN', 'ip')
    return user, apikey, ip

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

def print_results(output):
    output = json.loads(output)
    if output.get('results'):
        if 'groupby' in output:
            col_headers = "{:^35} {:<20}".format('Group', 'Value')
            print(col_headers)
            for row in output['results'].values()[0]:
                aligned_row = "{:>35} {:<20}".format(row['_groupby'], row['_count'])
                print(aligned_row)
        else:
            for msg in output['results']:
                log = json.dumps(msg['msg'], ensure_ascii=True)
                log = log.replace("\\\\\\\\", "\\")
                print(log)
    else:
        print('\nThe search did not return any records.')

def string_results(output):
    temp_list = []
    output = json.loads(output)
    if output.get('results'):
        if 'groupby' in output:
            col_headers = "{:^35} {:<20}".format('Group', 'Value')
            temp_list.append(col_headers)
            for row in output['results'].values()[0]:
                aligned_row = "{:>35} {:<20}".format(row['_groupby'], row['_count'])
                temp_list.append(aligned_row)
        else:
            for msg in output['results']:
                log = json.dumps(msg['msg'], ensure_ascii=True)
                log = log.replace("\\\\\\\\", "\\")
                temp_list.append(log)
        return temp_list
    else:
        return('\nThe search did not return any records.')
        

        
        

def query1(user, apikey, ip):
    query = "class=BRO_RDP -(dstip>=10.0.0.0 dstip<=10.255.255.255) -(dstip>=172.16.0.0 dstip<=172.31.255.255) -(dstip>=192.168.0.0 dstip<=192.168.255.255) groupby:srcip"
    query_result = query_elsa(user, apikey, ip, query)
    return query_result

def query2(user, apikey, ip):
    rdpFromInet = "class=BRO_RDP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) groupby:srcip"
    query_result = query_elsa(user, apikey, ip, rdpFromInet)
    return query_result
    
def query3(user, apikey, ip):
    webShell = "class=BRO_HTTP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) limit:9000 BRO_HTTP.status_code=200 groupby:uri"
    query_result = query_elsa(user, apikey, ip, webShell)
    return query_result



def split_line(text):
    words = text.split(" ")
    return words
        
def listinlist(list):
    i = 0
    list2 = []
    while i < len(list):
        list2.append(list[i])
        i+=1
    i = 0
    
    new_list = []
    while i < len(list2):
        new_list.append(list2[i:i+1])
        i+=2
    return new_list   
    
    
def create_html(user, apikey, ip):
    f = open ('report.html', 'w')
    
    message = """<!DOCTYPE html>
    <html>
    <style>
    body {font-family: "Lato", sans-serif;}

    ul.tab {
        list-style-type: none;
        margin: 0;
        padding: 0;
        overflow: hidden;
        border: 1px solid #ccc;
        background-color: #f1f1f1;
    }

    /* Float the list items side by side */
    ul.tab li {float: left;}

    /* Style the links inside the list items */
    ul.tab li a {
        display: inline-block;
        color: black;
        text-align: center;
        padding: 10px 12px;
        text-decoration: none;
        transition: 0.3s;
        font-size: 12px;
    }

    /* Change background color of links on hover */
    ul.tab li a:hover {
        background-color: #ddd;
    }

    /* Create an active/current tablink class */
    ul.tab li a:focus, .active {
        background-color: #ccc;
    }

    /* Style the tab content */
    .tabcontent {
        display: none;
        padding: 2px 4px;
        border: 1px solid #ccc;
        border-top: none;
        font-size: 12px;
    }
    </style>
    <body>
    <ul class="tab">
      <li><a href="#" class="tablinks" onclick="openQuery(event, 'RDP to Internet')">RDP to Internet</a></li>
      <li><a href="#" class="tablinks" onclick="openQuery(event, 'RDP from Internet')">RDP from Internet</a></li>
      <!--<li><a href="#" class="tablinks" onclick="openQuery(event, 'Malicious process search')">Malicious process search</a></li>
      <li><a href="#" class="tablinks" onclick="openQuery(event, 'RAR Exfil')">RAR Exfil</a></li>
      <li><a href="#" class="tablinks" onclick="openQuery(event, 'RAR Exfil 2')">RAR Exfil 2</a></li>-->
      <li><a href="#" class="tablinks" onclick="openQuery(event, 'WebShell URI Search')">WebShell URI Search</a></li>
    </ul>

    <div id="RDP to Internet" class="tabcontent">
      <h3>Find suspicious RDP outgoing to the Internet</h3>
      <p>1. Investigate destination IPs on Internet. </p>
      <p>2. Look for any other suspicious traffic to/from internal IP.</p>
      <p>(xxx.xxx.xxx. groupby:class)</p>"""
    f.write(message)
    data = query1(user, apikey, ip)
    list = string_results(data.text)
    table_data = listinlist(list)
    htmlcode = table(table_data)
    f.write(htmlcode)

    message = """
    </div>

    <div id="RDP from Internet" class="tabcontent">
      <h3>Find all successful INET incoming RDP connections</h3>
      <p>Research source and destination IPs to help determine context.</p>
      <p>What is the length and time frame of the connection?</p>
      <p>Was the logon successful? If so, what was the username?</p>
      <p>What processes were initiated by the user?</p>
      <p>Did the user move to another account or another device?</p>"""
    f.write(message)
    data = query2(user, apikey, ip)
    list = string_results(data.text)
    table_data = listinlist(list)
    htmlcode = table(table_data)
    f.write(htmlcode)
    
    message = """
    </div>

    <!--<div id="Malicious process search" class="tabcontent">
      <h3>Find suspicious process executing on server to investigate further to see if they are malicious</h3>
      <p>1. Investigate search results.</p>
      <p>2. Pull suspicious process and analyze them. (static and dynamic analysis)</p>
      <p>  - apps.fireeye.com/intel/analysis</p>
      <p>  - malwr.com</p>
      <p>  - strings command</p>
      <p>  - virustotal.com</p>
    </div>

    <div id="RAR Exfil" class="tabcontent">
      <h3>Investigate Bro logs for outgoing RAR files</h3>
      <p>Attribute source and destination IPs as much as is possible to help form the context of the transmission.</p>
      <p>Time frame of the RAR upload? After hours?</p>
      <p>If the transmission seems suspect then extract the RAR file from any recoverable pcap and determine if it is password protected.</p>
      <p>If the file is not password protected examine its contents.</p>
      <p>If it is password protected then try to crack it.</p>
    </div>

    <div id="RAR Exfil 2" class="tabcontent">
      <h3>Investigate Bro logs for outgoing RAR files</h3>
      <p>Attribute source and destination IPs as much as is possible to help form the context of the transmission.</p>
      <p>Time frame of the RAR upload? After hours?</p>
      <p>If the transmission seems suspect then extract the RAR file from any recoverable pcap and determine if it is password protected.</p>
      <p>If the file is not password protected examine its contents.</p>
      <p>If it is password protected then try to crack it.</p>
    </div>-->

    <div id="WebShell URI Search" class="tabcontent">
      <h3>List URI's rarely accessed in order to key in on possible web shells</h3>
      <p>View ELSA results from least hits to most.</p>
      <p>Look at the referrer field as WebShell CNC communications often do not include a referrer.</p>
      <p>If any URI is suspicious then pull a copy of that file with HX from Windows servers.</p>
      <p>Or, ask a *NIX admin to pull a copy from any *NIX server where the URI is pointing to.</p>
      <p>Examine the file to determine if it is a WebShell.</p>"""
    f.write(message)
    data = query3(user, apikey, ip)
    list = string_results(data.text)
    table_data = listinlist(list)
    htmlcode = table(table_data)
    f.write(htmlcode)
    
    message = """
    </div>

    <script>
    function openQuery(evt, queryName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(queryName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    </script>
         
    </body>
    </html>"""
    f.write(message)
    f.close()
    


    
'''  
def start_query(user, apikey, ip):
    query = "class=BRO_RDP -(dstip>=10.0.0.0 dstip<=10.255.255.255) -(dstip>=172.16.0.0 dstip<=172.31.255.255) -(dstip>=192.168.0.0 dstip<=192.168.255.255) groupby:srcip"
    query_result = query_elsa(user, apikey, ip, query)
    print_results(query_result.text)
    
    print(" ############################################################################################################################################### ")
	
    webShell = "class=BRO_HTTP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) limit:9000 BRO_HTTP.status_code=200 groupby:uri"
    query_result = query_elsa(user, apikey, ip, webShell)
    print_results(query_result.text)
    print(" ############################################################################################################################################### ")
    
    rdpFromInet = "class=BRO_RDP -(srcip>=10.0.0.0 srcip<=10.255.255.255) -(srcip>=172.16.0.0 srcip<=172.31.255.255) -(srcip>=192.168.0.0 srcip<=192.168.255.255) groupby:srcip"
    query_result = query_elsa(user, apikey, ip, rdpFromInet)
    print_results(query_result.text)
    print(" ############################################################################################################################################### ")
    
    rarExfil = "class=BRO_FTP -(command='GET' OR command='RETR') mime_type='application/x-rar' -(dstip>=10.0.0.0 AND dstip<=10.255.255.255) -(dstip>=172.16.0.0 AND dstip<=172.31.255.255) -(dstip>=192.168.0.0 AND dstip<=192.168.255.255) limit:9000"
    query_result = query_elsa(user, apikey, ip, rarExfil)
    print_results(query_result.text)
    print(" ############################################################################################################################################### ")
    
    rarExfil2 = "class=BRO_HTTP -method='GET' mime_type='application/x-rar' -(dstip>=10.0.0.0 AND dstip<=10.255.255.255) -(dstip>=172.16.0.0 AND dstip<=172.31.255.255) -(dstip>=192.168.0.0 AND dstip<=192.168.255.255) -'ESS Update' -update.eset.com limit:9000"
    query_result = query_elsa(user, apikey, ip, rarExfil2)
    print_results(query_result.text)
    print(" ############################################################################################################################################### ")
	
    malProcSea = "class='WINDOWS_PROCESS' 'new process' groupby:image limit:9500 -'Program Files' -'system32' -SysWOW64 -WinSXS -'kix32.exe' -'Microsoft.NET' -'progra~2'"
    query_result = query_elsa(user, apikey, ip, malProcSea)
    print_results(query_result.text)'''
    
    
    
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
    (options, args) = parser.parse_args()
    if not options.elsa_apikey:
        elsa_user, elsa_apikey, elsa_ip = read_conf()
    else:
        elsa_user = options.elsa_user
        elsa_ip = options.elsa_ip
        elsa_apikey = options.elsa_apikey
    
    '''start_query(elsa_user, elsa_apikey, elsa_ip)'''
    create_html(elsa_user, elsa_apikey, elsa_ip)
    
    
    
    
    