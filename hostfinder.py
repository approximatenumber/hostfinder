#!/usr/bin/env python3

import csv
import nmap
from time import sleep
from jinja2 import Environment, FileSystemLoader
import sys

csv_file = 'true_hosts.csv'
subnets = sys.argv[1].split(',')
timeout = 60


def get_hostlist(file):
    hosts = dict()
    with open(file, 'rt') as f:
        for row in csv.reader(f, delimiter=','):
            name = row[1]
            ip = row[6]
            hosts.update({ip: name})
    return hosts


def get_online_ips(subnet):
    nm = nmap.PortScanner()
    # nm.scan(hosts=subnet, arguments='-n -sP -PE -PA21,23,80,3389')
    nm.scan(hosts=subnet, arguments='-sn')
    return nm.all_hosts()


def create_report(online_hosts, offline_hosts, unknown_hosts):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('template.html')
    parsed_report = template.render(online_hosts=online_hosts,
                                      offline_hosts=offline_hosts,
                                      unknown_hosts=unknown_hosts)
    with open('index.html', 'wt') as html:
        html.write(parsed_report)


def main():

    while True:
        hostlist = get_hostlist(csv_file)
        hostlist_ips = hostlist.keys()

        nonflattened_online_ips = []
        for subnet in subnets:
            nonflattened_online_ips.append(get_online_ips(subnet))
        online_ips = [val for sublist in nonflattened_online_ips for val in sublist]
        
        online_hosts, offline_hosts, unknown_hosts = dict(), dict(), dict()
        for ip in list(hostlist_ips):
            name = hostlist[ip]
            if ip in online_ips:
                online_hosts.update({(name, ip)})
            elif ip not in online_ips:
                offline_hosts.update({(name, ip)})
        num = 0
        for online_ip in online_ips:
            if online_ip not in list(hostlist_ips):
                num += 1
                name = ('Неизвестный хост №%.2d' % num)
                unknown_hosts.update({(name, online_ip)})

        create_report(online_hosts, offline_hosts, unknown_hosts)
        sleep(timeout)

if __name__ == '__main__':
    main()
