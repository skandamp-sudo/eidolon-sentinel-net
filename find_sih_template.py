import urllib.request
import re
from bs4 import BeautifulSoup
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    req = urllib.request.Request('https://www.sih.gov.in', headers={'User-Agent': 'Mozilla/5.0'})
    html = urllib.request.urlopen(req, context=ctx).read().decode('utf-8')
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a', href=True)
    pptx_links = [l['href'] for l in links if '.ppt' in l['href'].lower()]
    print("Found PPTX links:", pptx_links)
except Exception as e:
    print("Error:", e)
