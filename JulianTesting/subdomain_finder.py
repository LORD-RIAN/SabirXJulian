### c99 subdomain finder API

import requests
import json
import re
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class subdomainFinder:
    def __init__(self):
        pass


    def crtsh_subdomains(self, domain: str, max_retries: int=10):

        session = requests.Session()

        retries = Retry(
            total = max_retries,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        resp = session.get(url, params=params, timeout=15)
        resp.raise_for_status() 
    
        data = resp.json()
        

        subs = set(re.sub(r'^\*\.', '', n.strip().lower())
                for d in data for n in d.get('name_value', '').split('\n')
                if n.endswith(domain))
        return sorted(subs)
    
    def circl_subdomains(self, domain: str):
        x = 0

        pass



    def get_subdomains(self, domain: str):
        subdomains = []
        crtsh_subs = self.crtsh_subdomains(domain=domain)

        subdomains.extend(crtsh_subs)


        return subdomains


subdomain_finder = subdomainFinder()


if __name__=="__main__":
    domain = "bananagun.io"

    crtsh_subdomains = subdomain_finder.crtsh_subdomains(domain=domain)

    print(crtsh_subdomains)
    print(len(crtsh_subdomains))

    all_subs = subdomain_finder.get_subdomains(domain=domain)

    print(all_subs)