### c99 subdomain finder API

import requests
import json
import re
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class subdomainFinder:
    def __init__(self, retries=10, timeout=15):
        self.timeout = (timeout, timeout)

        session = requests.Session()
        session.headers.update({"User-Agent": "SubFinder/Tasty1.0"})
        session.mount("http://", HTTPAdapter(max_retries=Retry(total=retries, backoff_factor=1.2, status_forcelist=(429,500,502,503,504), allowed_methods={"GET"})))
        session.mount("https://", HTTPAdapter(max_retries=Retry(total=retries, backoff_factor=1.2, status_forcelist=(429,500,502,503,504), allowed_methods={"GET"})))

        self.session = session

    def _get(self, url):
        r = self.session.get(url, timeout=self.timeout); r.raise_for_status()
        try: return r.json()
        except: return [json.loads(x) for x in r.text.splitlines() if x.strip().startswith("{")]




    def crtsh_subdomains(self, domain: str):

        data = self._get(url=f"https://crt.sh/?q=%.{domain}&output=json")

        if not isinstance(data, list):
            return []

        subs = []
        for row in data:
            for n in row.get("name_value", "").splitlines():
                n = n.strip().lower()
                if n.endswith(domain):
                    subs.append(n.lstrip("*."))
        return sorted(set(subs))
    


    def circl_subdomains(self, domain: str):
        x = 0

        url = f"https://www.circl.lu/pdns/query/{domain}"


        pass



    def get_subdomains(self, domain: str):
        subdomains = []
        crtsh_subs = self.crtsh_subdomains(domain=domain)

        subdomains.extend(crtsh_subs)


        return subdomains


subdomain_finder = subdomainFinder()


if __name__=="__main__":
    domain = "bananagun.io"


    all_subs = subdomain_finder.get_subdomains(domain=domain)

    print(all_subs)