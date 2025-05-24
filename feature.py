import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(r"(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|bitly\.com|is\.gd)", self.url)
        return -1 if match else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        try:
            return -1 if '-' in self.domain else 1
        except:
            return -1

    def SubDomains(self):
        count = self.url.count('.')
        return 1 if count == 1 else 0 if count == 2 else -1

    def Hppts(self):
        try:
            return 1 if 'https' in self.urlparse.scheme else -1
        except:
            return 1

    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            crt = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(crt, list): crt = crt[0]
            if exp is None or crt is None: return -1
            age = (exp.year - crt.year) * 12 + (exp.month - crt.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href'] or self.url in link['href']:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        try:
            return -1 if ':' in self.domain else 1
        except:
            return -1

    def HTTPSDomainURL(self):
        try:
            return -1 if 'https' in self.domain else 1
        except:
            return -1

    def RequestURL(self):
        try:
            i, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    i += 1
                    if self.domain in element['src'] or self.url in element['src']:
                        success += 1
            percentage = success / i * 100 if i != 0 else 0
            return 1 if percentage < 22 else 0 if percentage < 61 else -1
        except:
            return -1

    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if any(keyword in a['href'].lower() for keyword in ['#', 'javascript', 'mailto']) or not self.domain in a['href']:
                    unsafe += 1
                i += 1
            percentage = unsafe / i * 100 if i != 0 else 0
            return 1 if percentage < 31 else 0 if percentage < 67 else -1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, href=True) if tag == 'link' else self.soup.find_all(tag, src=True):
                    href = element.get('href') if tag == 'link' else element.get('src')
                    if self.domain in href or self.url in href:
                        success += 1
                    i += 1
            percentage = success / i * 100 if i != 0 else 0
            return 1 if percentage < 17 else 0 if percentage < 81 else -1
        except:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms: return 1
            for form in forms:
                action = form['action']
                if action == "" or action == "about:blank": return -1
                if self.domain not in action: return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        try:
            if re.search(r"[mail\(\)|mailto:?]", self.response.text):
                return -1
            return 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            return 1 if self.response.text == self.whois_response else -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            count = len(self.response.history)
            return 1 if count <= 1 else 0 if count <= 4 else -1
        except:
            return -1

    def StatusBarCust(self):
        try:
            return 1 if re.search(r"<script>.+onmouseover.+</script>", self.response.text) else -1
        except:
            return -1

    def DisableRightClick(self):
        try:
            return 1 if "event.button==2" in self.response.text else -1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            return 1 if "alert(" in self.response.text else -1
        except:
            return -1

    def IframeRedirection(self):
        try:
            return 1 if "<iframe>" in self.response.text or "<frameBorder>" in self.response.text else -1
        except:
            return -1

    def AgeofDomain(self):
        try:
            crt = self.whois_response.creation_date
            if isinstance(crt, list): crt = crt[0]
            today = date.today()
            age = (today.year - crt.year) * 12 + (today.month - crt.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    def DNSRecording(self):
        try:
            crt = self.whois_response.creation_date
            if isinstance(crt, list): crt = crt[0]
            today = date.today()
            age = (today.year - crt.year) * 12 + (today.month - crt.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    def WebsiteTraffic(self):
        try:
            alexa = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml")
            rank = alexa.find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    def PageRank(self):
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            rank = int(re.findall(r"Global Rank: ([0-9]+)", response.text)[0])
            return 1 if rank < 100000 else -1
        except:
            return -1

    def GoogleIndex(self):
        try:
            results = list(search(self.url, num_results=5))
            return 1 if results else -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            links = len(re.findall(r"<a href=", self.response.text))
            return 1 if links == 0 else 0 if links <= 2 else -1
        except:
            return -1

    def StatsReport(self):
        try:
            match = re.search(r'(at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es)', self.url)
            ip = socket.gethostbyname(self.domain)
            bad_ips = ['146.112.61.108', '213.174.157.151', '121.50.168.88', '192.185.217.116']
            return -1 if match or ip in bad_ips else 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features

# ✅ This is the callable function to use in app.py
def featureExtraction(url):
    return FeatureExtraction(url).getFeaturesList()
