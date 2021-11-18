import requests
import yaml
import inspect
from base64 import b64encode
from urllib.parse import urljoin

class CiscoAMP:
    def __init__(self):
        self.api_data = self.read_api_info()
    
    def set_params(self, item):
        """urlパラメーターの作成"""
        apiid = self.api_data['CiscoAMP']['APIID']
        apikey = self.api_data['CiscoAMP']['APIKEY']
        auth_string = f'{apiid}:{apikey}'
        auth_base64 = b64encode(auth_string.encode()).decode()

        headers = {
            'Accept': 'application/json',
            'content-type': 'application/json',
            'Authorization': f'Basic {auth_base64}',
            }
        if inspect.stack()[1].function == 'get_computer_info':
            jkkj = item
            url = urljoin(self.api_data['CiscoAMP']['COMPUTER']['HOST'], f'?hostname[]={jkkj}')
            return url, headers
        elif inspect.stack()[1].function == 'get_event':
            connector_guid = item
            url = urljoin(self.api_data['CiscoAMP']['EVENT']['HOST'], f'?connector_guid[]={connector_guid}')
            return url, headers

    def get_computer_info(self, jkkj):
        """端末情報の取得"""
        url, headers = self.set_params(jkkj)
        get_computer_info = requests.get(url, headers=headers)
        computer = get_computer_info.json()
        computer_info = {
            'connector_guid': computer['data'][0]['connector_guid'],
            'connector_version': computer['data'][0]['connector_version'],
            'internal_ips': computer['data'][0]['internal_ips'],
            'isolation': computer['data'][0]['isolation'],
            'operating_system': computer['data'][0]['operating_system']
        }
        return computer_info

    def get_event(self, connector_guid):
        """
        端末のイベントを取得
        CloudIOCのようなイベントは通信先のURLやIPを検知していることがあるので、
        'file'という文字列があるかどうかでevent_infoを変更
        """
        url, headers = self.set_params(connector_guid)
        get_event = requests.get(url, headers=headers)
        event = get_event.json()
        if 'file' in event['data'][0]:
            event_type = 'file'
            event_info = {
                'event_id': event['data'][0].get('id'),
                'event_type': event['data'][0].get('event_type', {}),
                'disposition': event['data'][0].get('file', {}).get('disposition'),
                'sha256': event['data'][0].get('file', {}).get('identity', {}).get('sha256')
            }
            event_info['file_name'] = self.get_filename(event, event_info['sha256'])
            event_info['file_path'] = self.get_filepath(event, event_info['sha256'])
        elif 'file' not in event['data'][0]:
            event_type = 'url'
            event_info = {
                'event_id': event['data'][0].get('id'),
                'event_type': event['data'][0].get('event_type'),
                'dirty_url': event['data'][0].get('network_info', {}).get('dirty_url')
            }
        return event_info, event_type

    def get_filename(self, event, sha256):
        """端末のイベント内直近３つ以内でsha256からファイル名を特定"""
        file_name = '取得できませんでした。'
        for i in range(3):
            if 'file_name' in event['data'][i]['file'].keys():
                if sha256 == event['data'][i]['file']['identity']['sha256']:
                    file_name = event['data'][i]['file']['file_name']
                    return file_name
        return file_name

    def get_filepath(self, event, sha256):
        """端末のイベント内直近３つ以内でsha256からファイルパスを特定"""
        file_path = '取得できませんでした。'
        for i in range(3):
            if 'file_path' in event['data'][i]['file'].keys():
                if sha256 == event['data'][i]['file']['identity']['sha256']:
                    file_path = event['data'][i]['file']['file_path']
                    return file_path
        return file_path

    def read_api_info(self):
        """アカウントの取得"""
        with open('conf/Settings.yaml', 'r') as f:
            api_data = yaml.load(f, Loader=yaml.SafeLoader)
        return api_data