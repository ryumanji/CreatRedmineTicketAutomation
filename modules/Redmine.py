from redminelib import Redmine
from datetime import datetime
import yaml, urllib3, codecs

class Issue:
    def __init__(self):
        self.api_data = self.read_api_info()
        self.input_value = self.read_settings_values()
        urllib3.disable_warnings()
        self.redmine = Redmine(self.api_data['Redmine']['HOST'], key=self.api_data['Redmine']['KEY'], requests={'verify': False})
        self.today = self.get_date_today()
        self.now = self.get_time_now()

    def set_params(self, subject, description):
        """チケット作成に必要なパラメータの付与"""
        self.new_issue = self.redmine.issue.new()
        self.new_issue.project_id = 'redmine-test'
        self.new_issue.subject = subject
        self.new_issue.tracker_id = self.input_value['Events']['redmine-test']['トラッカー']['SecurityOperation']   # トラッカー
        self.new_issue.status_id = self.input_value['Events']['redmine-test']['ステータス']['初動'] # ステータス
        self.new_issue.priority_id = self.input_value['Events']['redmine-test']['優先度']['F/P']   # 優先度
        self.new_issue.assigned_to_id = self.input_value['Events']['redmine-test']['担当者']['自分']    # 担当者
        self.new_issue.custom_fields = [
                    {'id': self.input_value['Events']['redmine-test']['発生日']['id'], 'value': self.today, 'name': self.input_value['Events']['redmine-test']['発生日']},    # 発生日
                    {'id': self.input_value['Events']['redmine-test']['発生時刻']['id'], 'value': self.now, 'name': self.input_value['Events']['redmine-test']['発生時刻']['name']},    # 発生時刻
        self.new_issue.description = description

    def get_date_today(self):
        now = datetime.now()
        return now.strftime('%Y-%m-%d')

    def get_time_now(self):
        now = datetime.now()
        return now.strftime('%H:%M')

    def create_issues(self, subject, description):
        """チケットの作成"""
        self.set_params(subject, description)
        self.new_issue.save()

    def update_issues(self, notes):
        """
        チケットの更新
        web上での「編集」と同じ
        """
        self.redmine.issue.update(
        self.new_issue.id,
        notes = notes
        # uploads=[
        #     {'path': './data/evidence/amp.png'},
        #     {'path': './data/evidence/vt.png'},
        #     {'path': './data/evidence/xf.png'},
        #     {'path': './data/evidence/QRadar.png'}]
        )

    def read_api_info(self):
        """アカウント情報取得"""
        with open('conf/Settings.yaml', 'r') as f:
            api_data = yaml.load(f, Loader=yaml.SafeLoader)
        return api_data

    def read_settings_values(self):
        """チケット作成に必要なパラメータ情報の取得"""
        with codecs.open('conf/Values.yaml', 'r', 'utf-8') as f:
            input_value = yaml.load(f, Loader=yaml.SafeLoader)
        return input_value
