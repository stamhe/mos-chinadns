import netaddr
import requests
import logging
import math

logger = logging.getLogger(__name__)


def update_ip():
    url = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    timeout = 30
    save_to_file = './chn.list'

    logger.info(f'connecting to {url}')

    ipNetwork_list = []

    with requests.get(url, timeout=timeout) as res:
        if res.status_code != 200:
            raise Exception(f'status code :{res.status_code}')

        logger.info(f'parsing...')

        lines = res.text.splitlines()
        for line in lines:
            try:
                if line.find('|CN|ipv4|') != -1:
                    elems = line.split('|')
                    ip_start = elems[3]
                    count = int(elems[4])
                    cidr_prefix_length = int(32 - math.log(count, 2))
                    ipNetwork_list.append(netaddr.IPNetwork(f'{ip_start}/{cidr_prefix_length}\n'))

                if line.find('|CN|ipv6|') != -1:
                    elems = line.split('|')
                    ip_start = elems[3]
                    cidr_prefix_length = elems[4]
                    ipNetwork_list.append(netaddr.IPNetwork(f'{ip_start}/{cidr_prefix_length}\n'))
            except IndexError:
                logging.warning(f'unexpected format: {line}')

    logger.info('merging')
    ipNetwork_list = netaddr.cidr_merge(ipNetwork_list)
    logger.info('writing to file')

    with open(save_to_file, 'wt') as f:
        f.writelines([f'{x}\n' for x in ipNetwork_list])

    logger.info('all done')


def update_domain():
    url = 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf'
    timeout = 30
    save_to_file = './chn_domain.list'
    logger.info(f'connecting to {url}')

    with requests.get(url, timeout=timeout) as res:
        if res.status_code != 200:
            res.close()
            raise Exception(f'status code :{res.status_code}')

        logger.info(f'parsing...')

        domains = []

        lines = res.text.splitlines()
        for line in lines:
            try:
                if line.find('server=/') != -1:
                    elems = line.split('/')
                    domain = elems[1]
                    domains.append(domain)
            except IndexError:
                logger.warning(f'unexpected format: {line}')

    with open(save_to_file, 'wt') as f:
        f.writelines([f'{x}\n' for x in domains])

    logger.info('all done')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    update_domain()
    update_ip()
