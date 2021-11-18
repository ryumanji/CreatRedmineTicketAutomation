import requests
import yaml

class QRadar:
    def __init__(self):
        self.api_data = self.read_api_info()

    def get_offenses(self):
        pass

    def get_logs(self):
        pass

    def screen_shot(self):
        pass

    def get_pdf(self):
        pass

    def read_api_info(self):
        with open('Settings.yaml', 'r') as f:
            api_data = yaml.load(f, Loader=yaml.SafeLoader)
        return api_data