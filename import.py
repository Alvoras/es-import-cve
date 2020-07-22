#!/usr/bin/env python3

import json
import argparse

import elasticsearch
import elasticsearch.helpers
from elasticsearch import RequestsHttpConnection, Elasticsearch


class ProxyConnection(RequestsHttpConnection):
    def __init__(self, *args, **kwargs):
        proxies = kwargs.pop('proxies', {})
        super(ProxyConnection, self).__init__(*args, **kwargs)
        self.session.proxies = proxies


class CVEBundle:
    def __init__(self):
        self.ids = []
        self.current = -1

    def add(self, cve_bundle):
        cve_id = cve_bundle["cve"]['CVE_data_meta']['ID']
        cve_bundle["cve"].update(cve_bundle['impact'])
        cve_bundle["cve"]['year'] = cve_id.split('-')[1]
        cve_bundle["cve"]['just_id'] = cve_id.split('-')[2]

        cve_bulk = {
                    "_op_type": "update",
                    "_index":   "cve-index",
                    "_id":      cve_id,
                    "doc_as_upsert": True,
                    "doc":  cve_bundle
                   }

        self.ids.append(cve_bulk)

    def __next__(self):
        "Handle a call to next()"

        self.current = self.current + 1
        if self.current >= len(self.ids):
            raise StopIteration

        return self.ids[self.current]

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.ids)


def main():
    parser = argparse.ArgumentParser(description="Import an CVE data file from NVD to an elasticsearch instance")
    parser.add_argument("-s", "--socks5", dest="socks5", help="SOCKS5 proxy in the <host>:<port> format (example : localhost:1234)")
    parser.add_argument("-u", "--username", dest="username", help="Username of the Kibana user to log in with")
    parser.add_argument("-p", "--password", dest="password", help="Password of the Kibana user to log in with")
    parser.add_argument("-U", "--url", dest="url", default="http://localhost:9200", help="Kibana URL. Default : http://localhost:9200")
    parser.add_argument("-f", "--file", dest="file", required=True, help="NVD CVE JSON file")
    args = parser.parse_args()

    params = {
        "connection_class": ProxyConnection,
        "auth": (),
        "hosts": [args.url],
    }

    if args.username and args.password:
        params["auth"] = (args.username, args.password)

    if args.socks5:
        params["proxies"] = {'http': f"socks5://{args.socks5}"}

    es = Elasticsearch(**params)

    # First let's see if the index exists
    if es.indices.exists('cve-index') is False:
        es.indices.create('cve-index')

    f = open(args.file)
    json_data = json.load(f)

    cves = CVEBundle()
    for cve in json_data['CVE_Items']:
        # ['CVE_Items'][0]['cve']['CVE_data_meta']['ID']
        cves.add(cve)

    for ok, item in elasticsearch.helpers.streaming_bulk(es, cves, max_retries=2):
        if not ok:
            print("Failed to import", item)


if __name__ == "__main__":
    main()

