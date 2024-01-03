from mod import explore
from colorama import Fore,init
import json
import argparse
init()

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
app = explore.Flare(read_config['api_id'],read_config['api_secret'],args.domain)
app.main()