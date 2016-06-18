#!/usr/bin/env python3

import csv
import nmap
from yattag import Doc
from yattag import indent
from time import sleep

csv_file = 'hosts.csv'
subnet = ['192.168.1.0/24']
timeout = 60


def get_hostlist(file):
    hosts = dict()
    with open(file, 'rt') as f:
        for row in csv.reader(f, delimiter=','):
            name = row[0]
            ip = row[1]
            hosts.update({ip:name})
    return hosts


def get_online_ips(hosts):
    nm = nmap.PortScanner()
    for subnet in hosts:
        nm.scan(hosts=subnet, arguments='-n -sP -PE -PA21,23,80,3389')
    return nm.all_hosts()


def create_report(online_hosts, offline_hosts):
    doc, tag, text = Doc().tagtext()
    doc.asis('<!DOCTYPE html>')
    with tag('html'):
        with tag('head'):
            with tag('meta', ('http-equiv','Content-Type'), ('content','text/html; charset=utf-8')):
                with tag('meta', ('http-equiv', "Refresh"), ('content', timeout)):
                    with tag('body'):
                        with tag('p', style='font-weight:bold'): text('Online:')
                        for ip in list(online_hosts.keys()):
                            text('%s [%s]' % (ip, online_hosts[ip]))
                            doc.stag('br')
                        with tag('p', style='font-weight:bold'):text('Offline:')
                        for ip in list(offline_hosts.keys()):
                            text('%s [%s]' % (ip, offline_hosts[ip]))
                            doc.stag('br')
    with open('index.html', 'w') as html:
        html.write(indent(doc.getvalue()))


def main():
    while True:
        hostlist = get_hostlist(csv_file)
        hostlist_ips = hostlist.keys()

        online_ips = get_online_ips(subnet)

        online_hosts, offline_hosts = dict(), dict()
        for ip in list(hostlist_ips):
            name = hostlist[ip]
            if ip not in online_ips:
                offline_hosts.update({(name, ip)})
            else:
                online_hosts.update({(name, ip)})

        create_report(online_hosts,offline_hosts)
        sleep(timeout)

if __name__ == '__main__':
    main()
