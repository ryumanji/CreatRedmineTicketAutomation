import requests
import yaml
import re

class VirusTotal:
    def __init__(self, item, item_id):
        self.item = item
        self.item_id = item_id
        self.api_data = self.read_api_info()

    def get_vt_url(self):
        """VTのurlを取得"""
        if self.item_id == 'url':
            url = self.api_data['VirusTotal']['URLSCAN']['HOST'] + self.item.replace('/', '~2F')
            return url

        elif self.item_id == 'file_hash':
            url = self.api_data['VirusTotal']['FILESCAN']['HOST'] + self.item
            return url
        
        elif self.item_id == 'ip_addr':
            url = self.api_data['VirusTotal']['IPSCAN']['HOST'] + self.item
            return url

    def set_params(self, item):
        """urlパラメーターの作成"""
        params = {
            'apikey': self.api_data['VirusTotal']['API']['KEY'],
            'resource': item
            }
        if self.item_id == 'url':
            url = self.api_data['VirusTotal']['API']['URLSCAN']['HOST']
            return url, params

        elif self.item_id == 'file_hash':
            url = self.api_data['VirusTotal']['API']['FILESCAN']['HOST']
            return url, params

    def get_reputation(self):
        """スコアの取得"""
        url, params = self.set_params(self.item)
        vt = requests.get(url, params)
        result = vt.json()
        if result['response_code'] == 0:
            return 'no matches faund.'

        elif result['response_code'] == 1:
            reputation = {
                'positives': result['positives'],
                'total': result['total']
            }
            vtscore = self.calc_vtscore(reputation['positives'], reputation['total'])
            return vtscore

    def calc_vtscore(self, positives_num, total_num):
        """VTのスコアを計算"""
        vtscore = str(positives_num) + "/" + str(total_num)
        return vtscore

    def read_api_info(self):
        """アカウント情報取得"""
        with open('conf/Settings.yaml', 'r') as f:
            api_data = yaml.load(f, Loader=yaml.SafeLoader)
        return api_data