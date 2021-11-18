import requests
import yaml
import inspect
from base64 import b64encode
from urllib.parse import urljoin, quote
import re

class XForce:
    def __init__(self, item, item_id):
        self.item = item
        self.item_id = item_id
        self.api_data = self.read_api_info()
        self.xf_details = self.get_details()
        self.xf_whois = self.get_whois()

    def get_xf_url(self):
        """XFのurlを取得"""
        if self.item_id == 'url':
            hp_addr = self.item
            url = self.api_data['XForce']['URLSCAN']['HOST'] + hp_addr.replace('/', '~2F')
            return url

        elif self.item_id == 'ip_addr_global':
            ip_addr = self.item
            url = self.api_data['XForce']['IPSCAN']['HOST'] + ip_addr
            return url

        elif self.item_id == 'file_hash':
            file_hash = self.item
            url = self.api_data['XForce']['FILESCAN']['HOST'] + file_hash
            return url

    def get_details(self):
        """評価を取得"""
        url, headers = self.set_params()
        return requests.get(url, headers=headers)

    def get_whois(self):
        """whois情報の取得"""
        url, headers = self.set_params()
        return requests.get(url, headers=headers)

    def set_params(self):
        """urlパラメーターの作成"""
        apikey = self.api_data['XForce']['API']['APIKEY']
        apipass = self.api_data['XForce']['API']['APIPASS']
        auth_string = f'{apikey}:{apipass}'
        auth_base64 = b64encode(auth_string.encode()).decode()

        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {auth_base64}',
            }
        # 呼び出し元関数がget_detailsの時の処理
        if inspect.stack()[1].function == 'get_details':
            if self.item_id == 'url':
                hp_addr = self.create_url(self.item)
                url = self.api_data['XForce']['API']['URLSCAN']['HOST'] + quote(hp_addr)
                return url, headers

            elif self.item_id == 'ip_addr_global':
                ip_addr = self.item
                url = urljoin(self.api_data['XForce']['API']['IPSCAN']['HOST'], ip_addr)
                return url, headers

            elif self.item_id == 'file_hash':
                file_hash = self.item
                url = urljoin(self.api_data['XForce']['API']['FILESCAN']['HOST'], file_hash)
                return url, headers

        # 呼び出し元関数がget_whoisの時の処理
        elif inspect.stack()[1].function == 'get_whois':
            if self.item_id == 'url':
                pattern = r'(:\d+)'
                item = re.sub(pattern, '', self.item)
                url = urljoin(self.api_data['XForce']['API']['WHOIS']['HOST'], self.create_url(item))
            else:
                url = urljoin(self.api_data['XForce']['API']['WHOIS']['HOST'], self.item)
            return url, headers

    def create_url(self, hp_addr):
        """urlを調査する際のurlの作成"""
        if 'https' in self.item:
            hp_addr = hp_addr.replace('https://', '')
        elif 'http' in self.item:
            hp_addr = hp_addr.replace('http://', '')
        return hp_addr

    def get_reputation(self):
        """評価を取得"""
        details_result = self.xf_details.json()
        if self.item_id != 'file_hash':
            whois_result = self.xf_whois.json()
            return self.create_template(details_result, whois_result)
        else:
            return self.create_template(details_result)

    def create_template(self, details_result, *whois_result):
        """テンプレートの作成"""
        if self.item_id == 'url':
            # 見つからないときはNone属性が返る
            whois_info = {
                'country': self.get_contact_value(whois_result, 'country'),
                'organization': self.get_contact_value(whois_result, 'organization'),
                'createdDate': whois_result[0].get('createdDate'),
                'updatedDate': whois_result[0].get('updatedDate')
            }
            if 'error' in details_result:
                xf_data = self.get_template_whois(self.item_id).format(whois_info)
                return details_result['error'], xf_data
            else:
                reputation = {
                    'Score': details_result['result']['score'],
                    'Category(%)': details_result.get('result', {}).get('cats'),
                    'categoryDescriptions': [val for val in details_result.get('result', {}).get('categoryDescriptions').values()],
                    'Action': details_result.get('result', {}).get('application', {}).get('actions')
                }

                xf_data = self.get_template_details(self.item_id).format(reputation) + '\n' + self.get_template_whois(self.item_id).format(whois_info)
                return reputation['Score'], xf_data

        elif self.item_id == 'ip_addr_global':
            whois_info = {
                'country': whois_result[0].get('contact', {}).get(0, {}).get('country'),
                'organization': whois_result[0].get('contact', {}).get(0, {}).get('organization'),
                'updatedDate': whois_result[0].get('updatedDate')
            }
            if 'error' in details_result:
                xf_data = self.get_template_whois(self.item_id).format(whois_info)
                return details_result['error'], xf_data
            else:
                reputation = {
                    'Score': details_result.get('score'),
                    'Category(%)': details_result.get('cats'),
                    'categoryDescriptions': [val for val in details_result.get('history', {}).get(0, {}).get('categoryDescriptions').values()],
                    'Country': details_result.get('geo', {}).get('country'),
                    'Company(ASN)': details_result('history').get(3, {}).get('asns')
                }
                xf_data = self.get_template_details(self.item_id).format(reputation) + '\n' + self.get_template_whois(self.item_id).format(whois_info)
                return reputation['Score'], xf_data

        elif self.item_id == 'file_hash':
            if 'error' in details_result:
                return details_result['error'], details_result['error']
            else:
                reputation = {
                    'Risk': details_result.get('malware', {}).get('risk'),
                    'Type': details_result.get('malware', {}).get('type'),
                    'FirstSeen': details_result.get('malware', {}).get('origins', {}).get('external', {}).get('firstSeen'),
                    'LastSeen': details_result.get('malware', {}).get('origins', {}).get('external', {}).get('lastSeen'),
                    'Family': details_result.get('malware', {}).get('origins', {}).get('external', {}).get('family'),
                    'MalwareType': details_result.get('malware', {}).get('origins', {}).get('external', {}).get('malwareType'),
                    'Platform': details_result.get('malware', {}).get('origins', {}).get('external', {}).get('platform')
                }

                xf_data = self.get_template_details(self.item_id).format(reputation)
                return reputation['Risk'], xf_data
    
    def get_contact_value(self, whois_result, key):
        """
        dictの中でlistがネストされているときにgetでkeyがあるか確認できない
        listがネストされているもののみこの関数を使用
        """
        contact = whois_result[0].get('contact', {})
        if contact:
            value = contact[0].get(key, {})
            return value
        return None

    def get_template_whois(self, item_id):
        """whoisのテンプレートの取得"""
        template_list = {
            'url': 'XF_Template_whois_URL.txt',
            'ip_addr': 'XF_Template_whois_IP.txt',
        }
        with open('templates/' + template_list[self.item_id], 'r', encoding='utf-8') as f:
            template = f.read()
        return template
    
    def get_template_details(self, item_id):
        """detailsのテンプレートの取得"""
        template_list = {
            'url': 'XF_Template_details_URL.txt',
            'ip_addr': 'XF_Template_details_IP.txt',
            'file_hash': 'XF_Template_details_HASH.txt'
        }
        with open('templates/' + template_list[self.item_id], 'r', encoding='utf-8') as f:
            template = f.read()
        return template

    def read_api_info(self):
        """アカウント情報取得"""
        with open('conf/Settings.yaml', 'r') as f:
            api_data = yaml.load(f, Loader=yaml.SafeLoader)
        return api_data
