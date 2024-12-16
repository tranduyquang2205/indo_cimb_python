
import hashlib
import requests
import json
import base64
import random
import string
import json
import os
import hashlib
import time
import uuid
from datetime import datetime
from datetime import datetime
from urllib.parse import unquote

class CIMB:
    def __init__(self, username, password, account_number,proxy_list=None):
                # Public key in PEM format
        # Load the public key
        self.public_key = ""
        self.user_id = ""
        self.authToken = ""
        self.clientIp = ""
        self.session = requests.Session()
        self.guid = ""
        self.uuid = ""
        self.signNo = ""
        self.is_login = False
        self.time_login = time.time()
        self.proxy_list = proxy_list
        self.file = f"data/{username}.txt"
        self.access_token = None
        self.cifNo = ""
        self.account_list = {}
        self.browser_id = self.generate_numeric_format()
        self.url = {
            'login':'https://www.octoclicks.co.id/api/v1/login',
            'account_list': 'https://www.octoclicks.co.id/api/myaccount/v1/getAccountListCASA',
            'get_transactions_by_month': 'https://www.octoclicks.co.id/api/myaccount/v1/getMonthlyTransactionHistory',
            'last_10_rows': 'https://www.octoclicks.co.id/api/myaccount/v1/getTransactionHistory',
            'refresh_access_token':'https://www.octoclicks.co.id/api/myaccount/v1/getMonthlyTransactionHistory'
            
            
            

}


        if not os.path.exists(self.file) or os.path.getsize(self.file) == 0:
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            if self.proxy_list:
                try:
                    self.proxy_info = self.proxy_list.pop(0)
                    proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
                    self.proxies = {
                        'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
                        'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
                    }
                    
                except ValueError:
                    self.proxies = None 
                except Exception as e:
                    self.proxies = None
            else:
                self.proxies = None
            self.save_data()
            
        else:
            self.parse_data()
            if not self.proxies:
                if self.proxy_list:
                    try:
                        self.proxy_info = self.proxy_list.pop(0)
                        proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
                        self.proxies = {
                            'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
                            'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
                        }
                        
                    except ValueError:
                        self.proxies = None 
                    except Exception as e:
                        self.proxies = None
                else:
                    self.proxies = None
            self.username = username
            self.password = password
            self.account_number = account_number
            self.save_data()
            
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'browser_id': self.browser_id,
            'cifNo': self.cifNo,
            'is_login': self.is_login,
            'time_login': self.time_login,
            'access_token': self.access_token,
            'account_list': self.account_list,
            'proxies':self.proxies
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)

    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.browser_id = data.get('browser_id', '')
        self.cifNo = data.get('cifNo', '')
        self.is_login = data.get('is_login', '')
        self.time_login = data.get('time_login', '')
        self.access_token = data.get('access_token', '')
        self.account_list = data.get('account_list', '')
        self.proxies = data['proxies']
        
    def Pt(self,cookie_name):
        cookie_string = "; ".join([f"{cookie.name}={cookie.value}" for cookie in self.session.cookies])
        """
        Retrieve the value of a specific cookie from a cookie string.

        Args:
            cookie_string (str): The full cookie string (e.g., "key1=value1; key2=value2").
            cookie_name (str): The name of the cookie to retrieve.

        Returns:
            str: The value of the specified cookie, or an empty string if not found.
        """
        # Prepare the target cookie name pattern
        target = cookie_name + "="
        # Split the cookie string into individual cookies
        cookies = unquote(cookie_string).split(";")
        
        # Loop through each cookie
        for cookie in cookies:
            # Strip leading spaces from the cookie
            while cookie.startswith(" "):
                cookie = cookie[1:]
            # Check if the cookie starts with the target pattern
            if cookie.startswith(target):
                # Return the cookie's value (everything after `target`)
                return cookie[len(target):]
        
        # Return empty string if no matching cookie is found
        return ""
    def encrypt_password(self,e, t, a):
        """
        Encrypt a password using MD5 and SHA256 algorithms.

        Args:
            e (str): The first input string (to be converted to uppercase).
            t (str): The second input string.
            a (str): The third input string.

        Returns:
            str: The encrypted password as a string.
        """
        # Step 1: MD5 hash of `t`, convert to uppercase
        n = hashlib.md5(t.encode()).hexdigest().upper()

        # Step 2: Convert `e` to uppercase
        r = e.upper()

        # Step 3: Calculate SHA256(n + a)
        sha256_1 = hashlib.sha256((n + a).encode()).hexdigest()

        # Step 4: Calculate SHA256(SHA256(n + r) + a)
        sha256_2 = hashlib.sha256(hashlib.sha256((n + r).encode()).hexdigest().encode() + a.encode()).hexdigest()

        # Step 5: Concatenate and return
        return sha256_1 + sha256_2

    def Ht(self,data):
        # Load the RSA key from the key string (in PEM format)
        key = f"-----BEGIN PUBLIC KEY-----\n{self.public_key}\n-----END PUBLIC KEY-----"
        rsa_key = RSA.import_key(key)

        # Encrypt the message using PKCS1 padding
        cipher = PKCS1_v1_5.new(rsa_key)

        ciphertext = cipher.encrypt(data.encode('utf-8'))

        # Encode the ciphertext as base64
        return base64.b64encode(ciphertext).decode('utf-8')
    def Kt(self):
        def replace_char(e):
            t = int(16 * random.random())
            if e == 'x':
                return hex(t)[2:]
            elif e == 'y':
                return hex((t & 0x3) | 0x8)[2:]

        uuid = ''.join(replace_char(e) if e in 'xy' else e for e in "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx")
        return uuid
    def pad(self,data):
        block_size = AES.block_size
        padding = block_size - len(data) % block_size
        return data + bytes([padding] * padding)
    def Ut(self,password, plaintext):
    # Generate random IV and salt
        iv = get_random_bytes(16)
        salt = get_random_bytes(16)

        # Derive key using PBKDF2
        key = PBKDF2(password.encode(), salt, dkLen=32, count=2000)

        # Pad the plaintext
        padded_plaintext = self.pad(plaintext.encode())

        # Encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Return the result
        return {
            'iv': iv.hex(),
            'salt': salt.hex(),
            'data': base64.b64encode(ciphertext).decode('utf-8')
        }
    def get_key_site(self):
        url = "https://onlinebanking.eximbank.com.vn/api/IB/KHDN/security/getPermission"

        payload = json.dumps({})
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://onlinebanking.eximbank.com.vn',
        'Referer': 'https://onlinebanking.eximbank.com.vn/KHDN/account/login-corp?returnUrl=%2Fhome',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'X-Token': '',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        response = self.session.request("POST", url, headers=headers, data=payload,proxies=self.proxies)
        res = response.json()
        if 'ID' in res:
            self.public_key = res['ID']
        return res
    def generate_numeric_format(self,length=9):
        """
        Generate a random numeric string of the specified length.

        Args:
            length (int): The length of the numeric string to generate.

        Returns:
            str: A random numeric string of the specified length.
        """
        # Ensure the first digit is non-zero by using randint
        first_digit = random.randint(1, 9)
        # Generate the remaining digits
        other_digits = ''.join(str(random.randint(0, 9)) for _ in range(length - 1))
        # Combine and return the result
        return str(first_digit) + other_digits
    def curl_post(self, url, data,refresh_access_token = False):

        headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'browser-id': self.browser_id,
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://www.octoclicks.co.id',
        'priority': 'u=1, i',
        'referer': 'https://www.octoclicks.co.id/login/',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'x-forwarded-for': ''
        }
        if self.access_token:
            headers['authorization'] = 'Bearer ' +self.access_token
        response = self.session.post(url, headers=headers, data=json.dumps(data),proxies=self.proxies)
        access_token = response.headers.get('access_token')
        try:
            result = response.json()
        except Exception as e:
            result = response.text
        refreshed = False
        if access_token and access_token != self.access_token:
            print('new_access_token')
            self.access_token = access_token
            self.time_login = time.time()
            self.is_login = True
            self.save_data()
            if refresh_access_token and result and 'myaccountresponse' in result and 'status' in result['myaccountresponse'] and result['myaccountresponse']['status'] == "00":
                refreshed = True
        if refresh_access_token:
            return result,refreshed
        return result

    def curl_get(self, url):

        headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'browser-id': self.browser_id,
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://www.octoclicks.co.id',
        'priority': 'u=1, i',
        'referer': 'https://www.octoclicks.co.id/login/',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'x-forwarded-for': ''
        }
        if self.access_token:
            headers['authorization'] = 'Bearer ' +self.access_token
        response = self.session.get(url, headers=headers,proxies=self.proxies)
        print(response)
        try:
            result = response.json()
        except Exception as e:
            result = response.text
        return result

    def generate_request_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)) + '|' + str(int(datetime.now().timestamp()))
    
    def do_login(self):
        print('login')
        data = {
            "username": self.username,
            "password": self.encrypt_password(self.username,self.password,"CxuzTeZb8wRWyN4x"),
            "c": self.Pt("clientId"),
        }
        result = self.curl_post(self.url['login'], data)
        if 'loginresponse' in result and 'status' in result['loginresponse'] and result['loginresponse']['status'] == 1:
            print('login success')
            self.cifNo = result['loginresponse']['cif']
            self.is_login = True
            self.time_login = time.time()
            self.save_data()
            
            return {
                'code': 200,
                'success': True,
                'message': "success",
                'access_token': self.access_token,
                'cifNo': self.cifNo,
                'data': result if result else ""
            }
        elif 'apierror' in result and 'message' in result['apierror'] and result['apierror']['message'] == "User Already Login":
            return {
                'code': 200,
                'success': True,
                'message': "success",
                'access_token': self.access_token,
                'cifNo': self.cifNo,
                'data': result if result else ""
            }
        elif 'apierror' in result and 'message' in result['apierror'] and result['apierror']['message'] == "Username or Password Invalid":
            return {
                'code': 444,
                'success': False,
                'message': result['loginresponse']['message'] if 'loginresponse' in result and 'message' in result['loginresponse'] else result,
                "param": data,
                'data': result if result else ""
            }
        else:
            return {
                'code': 500,
                'success': False,
                'message': result['loginresponse']['message'] if 'loginresponse' in result and 'message' in result['loginresponse'] else result,
                "param": data,
                'data': result if result else ""
            }

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result
    def getPermissions(self):
        data = {
            "routerLink": "/home",
            "userId": self.user_id,
            "certId": self.user_id
        }
        e = json.dumps(data)
        r = self.Kt()
        i = self.Ut(r,e)
        s = f"{i['salt']}::{i['iv']}::{r}"
        param = {
                    'meta': self.Ht(s),
                    'data': i['data'],
                    'verified': True
                }
        result = self.curl_post(self.url['getPermissions'], param)
        return (result)
    def getNoteByMenuId(self):
        data = {
            "reqId": "100",
            "certId": self.user_id
        }
        e = json.dumps(data)
        r = self.Kt()
        i = self.Ut(r,e)
        s = f"{i['salt']}::{i['iv']}::{r}"
        param = {
                    'meta': self.Ht(s),
                    'data': i['data'],
                    'verified': True
                }
        result = self.curl_post(self.url['getNoteByMenuId'], param)
        return (result)
    def refresh_access_token(self,):
        result,refreshed = self.curl_post(self.url['account_list'],{},refresh_access_token=True)
        print('refresh_access_token',result,refreshed)
        if not refreshed:
            login = self.do_login()
            if not login['success']:
                return login
        print('refresh_access_token',result,refreshed)
        return result
        
        
        
    def get_balance(self,account_number=None,retry=False):
        if not account_number:
            account_number = self.account_number
        if not self.is_login or time.time()- self.time_login > 24*3600:
            login = self.do_login()
            if not login['success']:
                return login
        elif self.is_login and time.time()- self.time_login > 595:
            self.refresh_access_token()

        result = self.curl_post(self.url['account_list'],{})
        if result and 'myaccountresponse' in result and 'status' in result['myaccountresponse'] and result['myaccountresponse']['status'] == "00" and 'sofShariah' in result['myaccountresponse'] and 'saaccountList' in result['myaccountresponse']['sofShariah']:
            account_list = result['myaccountresponse']['sofShariah']['saaccountList']
            self.account_list = account_list
            self.save_data()
            for account_index, account_data in account_list.items():
                res_account_number = account_data.get("accountNumber", self.account_number)
                account_balance = account_data.get("accountBalance", 0)
                
                if account_number == res_account_number:
                    if float(account_balance) < 0 :
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':float(account_balance)
                                }
                                }
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':account_number,
                                    'balance':float(account_balance)
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else: 
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_balance(account_number,retry=True)
            return {'code':520 ,'success': False, 'message': 'Unknown Error!','data':result} 

    def months_ago(self,month_year):
        """
        Calculate how many months ago a given month/year is relative to the current month/year.

        Args:
            month_year (str): The input month/year in "MM/YYYY" format.

        Returns:
            int: The number of months ago.
        """
        # Parse the input month/year
        input_month, input_year = map(int, month_year.split('/'))
        
        # Get the current month and year
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        
        # Calculate the total months difference
        months_difference = (current_year - input_year) * 12 + (current_month - input_month)
        return str(months_difference)

    def get_transactions(self, month="12/2024", account_number='',retry=False):
        print(account_number,self.account_list)
        account_index = None
        if not self.is_login or time.time()- self.time_login > 24*3600:
                login = self.do_login()
                if not login['success']:
                    return login
        if not self.account_list:
            self.get_balance(account_number)
        for res_account_index, account_data in self.account_list.items():
            res_account_number = account_data.get("accountNumber", self.account_number)                
            if account_number == res_account_number:
                account_index = str(res_account_index)
        if not account_index:
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        data = {
            "accountIndex": account_index,
            "isSharia": True,
            "month": self.months_ago(month)
        }

        result = self.curl_post(self.url['get_transactions_by_month'], data)
        if result and 'myaccounttransactionresponse' in result and 'myAccountTransactions' in result['myaccounttransactionresponse']:
            transactions = result['myaccounttransactionresponse']['myAccountTransactions']
            return {'code':200,'success': True, 'message': 'Thành công',
                            'data':{
                                'transactions':transactions,
                    }}
        else:
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_transactions(month, account_number,retry=True)
            return  {
                    "success": False,
                    "code": 503,
                    "message": "Service Unavailable!",
                    "data": result
                }

