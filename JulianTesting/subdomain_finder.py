### c99 subdomain finder API

import requests
import json
import re
import time

class subdomainFinder:
    def __init__(self):
        pass


    def crtsh_subdomains(self, domain: str):
        x = 0
        while True:
            x += 1
            try:
                r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
                print(r.status_code)
                if r.status_code == 200:
                    break

            except Exception as e:
                print("Shit failed! CRTSH\n", e)
            
            time.sleep(2)

            if x > 15:
                print("QUITTING CUZZA CRTSH!!")
                quit()

        

        data = r.json() if r.text.strip().startswith('[') else [json.loads(x) for x in r.text.splitlines()]
        subs = set(re.sub(r'^\*\.', '', n.strip().lower())
                for d in data for n in d.get('name_value', '').split('\n')
                if n.endswith(domain))
        return sorted(subs)



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