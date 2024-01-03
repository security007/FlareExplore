from censys.search import CensysHosts
from difflib import SequenceMatcher
from bs4 import BeautifulSoup as bs
from colorama import Fore,init
import argparse
import socket
import whois
import requests
import sys
import json
import censys
init()

# disable insecure warning requests verify=False
requests.packages.urllib3.disable_warnings() 

class Flare:
    def __init__(self,api,secret,domain):
        self.domain = domain

        # handle exception if api not set
        try:
            self.censysApi = CensysHosts(api_id=api,api_secret=secret)
        except censys.common.exceptions.CensysException as e:
            print(f"❌ {Fore.RED}{e}{Fore.RESET}")
            sys.exit()

    def similarity(self,text=list()):
        try:
            # Calculate the similarity ratio using SequenceMatcher
            similarity_ratio = SequenceMatcher(None, text[0], text[1]).ratio()
            
            # Convert the ratio to percentage
            similarity_percentage = similarity_ratio * 100
        except KeyboardInterrupt:
            sys.exit()
        
        return f"{similarity_percentage:.2f}"
    
    def check_dns(self,domain):
        try:
            answers = whois.whois(domain)
            answer = answers['name_servers']
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            answer = "None"
        return answer
    
    def bsoup(self,content):
        soup = bs(content,'html.parser')
        try:
            title = soup.find('title').text.strip()
        except AttributeError:
            title = ""
        return title
    
    def requester(self,domain,pass_=False):
        try:
            req = requests.get(domain,headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'},verify=False,timeout=5)
            return req
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            print(f"❌ {Fore.RED}{e}{Fore.RESET}")
            if pass_:
                pass
            else:
                sys.exit()

    def scan(self):
        query = self.censysApi.search(self.domain, pages=-1)
        return query()
    
    def ipaddr(self):
        return socket.gethostbyname(self.domain)
    
    def main(self):
        print(f"🔎 {Fore.BLUE}Scanning {self.domain} {Fore.RESET}")

        ###################### check domain NS
        ns = self.check_dns(self.domain)
        if "cloudflare" in ns[0].lower():
            print(f"⚠️ {self.domain} ({self.ipaddr()}) {Fore.YELLOW}IS BEHIND CLOUDFLARE{Fore.RESET} {ns}")
        else:
            print(f"✔️ {self.domain} ({self.ipaddr()}) {Fore.GREEN}IS NOT BEHIND CLOUDFLARE{Fore.RESET} {ns}")
            sys.exit()

        ####################### main target info
        main_target_content = self.requester("https://"+self.domain).content
        main_target_content_length = len(main_target_content) / 1024
        main_target_title = self.bsoup(main_target_content)

        print(f"🌐 {self.domain} | size: {main_target_content_length:.2f} kb | title: {main_target_title}")

        ######################## scan domain
        print(f"🔎 {Fore.BLUE}Finding possible Ip{Fore.RESET}")
        scanner = self.scan()
        list_ip = list()
        total_results = len(scanner)

        if total_results == 0:
            sys.exit()

        for ip in scanner:
            try:
                if "." in ip['ip']:
                    list_ip.append(ip['ip'])
            except TypeError:
                pass
        print(f"🔎 {len(list_ip)} Ip associated with {self.domain} ")
        

        ########################## check similarity
        print(f"🔎 {Fore.BLUE}Checking candidates ip{Fore.RESET}")

        # get candidate content and title for checking similarity
        for test_ip in list_ip:
            try:
                candidate_content = self.requester("http://"+test_ip,True).content
            except AttributeError:
                candidate_content = ""
            candidate_content_length = len(candidate_content) / 1024
            candidate_title = self.bsoup(candidate_content)

        
            similar_content = float(self.similarity([main_target_content,candidate_content]))
            similar_title = float(self.similarity([main_target_title,candidate_title]))
            if similar_content > 60.0 and similar_title > 70.0:
                print(f"🌐 {test_ip} size: {candidate_content_length:.2f} kb | content similarity: {similar_content}% | title similarity: {similar_title}% ({Fore.GREEN}POSSIBLE REAL IP{Fore.RESET})")
            else:
                print(f"🌐 {test_ip} size: {candidate_content_length:.2f} kb | content similarity: {similar_content}% | title similarity: {similar_title}% ")

if __name__ == "__main__":
    banner = f"""
 {Fore.BLUE}_______  __                       _______                __                    
|    ___||  |.---.-..----..-----. |    ___|.--.--..-----.|  |.-----..----..-----.
|    ___||  ||  _  ||   _||  -__| |    ___||_   _||  _  ||  ||  _  ||   _||  -__|
|___|    |__||___._||__|  |_____| |_______||__.__||   __||__||_____||__|  |_____| 
                                                  |__|  {Fore.RESET}
    v 1.0 
    Find Real IP Behind CloudFlare
    Dont forget to set censys api_id and api_secret in config.json                    
"""
    print(banner)
    parser = argparse.ArgumentParser()
    required = parser.add_argument_group('required arguments')
    required.add_argument('-d', '--domain', help="Domain to check , example.com, without http(s)://",required=True) 
    args = parser.parse_args()
    with open("config.json","r") as config:
        read_config = json.load(config)
    app = Flare(read_config['api_id'],read_config['api_secret'],args.domain)
    app.main()
    