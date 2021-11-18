import os
from logging import getLogger, StreamHandler, DEBUG, Formatter
from modules import Redmine
from modules import VirusTotal
from modules import XForce
from modules import CiscoAMP
from Mail import Mail
import re
from templates import *
from time import sleep
import csv
import ipaddress

def mail_check():
    """新規メールの受信確認"""
    if mailer.detect_newmail() == 1:
        mail_list = [num for num in mailer.data_in_box]
        return mail_list

def get_info_from_mail(mail_text):
    """メールの内容を取得"""
    strings_key_list = ['Event Type', 'Computer', 'Hostname', 'Timestamp']
    strings_value_list = []
    for i in range(len(strings_key_list)):
        pattern = strings_key_list[i] + r': (.*?)\r*\n'
        result = re.findall(pattern, mail_text)
        strings_value_list.append(result)
    strings_dict = dict(zip(strings_key_list, strings_value_list))
    return strings_dict

def judge_action_eventtypes(strings_dict):
    """eventtypes_not_create_new_ticketリストにて、メールを受信しても新しくチケットを立てないEvent Typeを指定"""
    eventtypes_not_create_new_ticket = ['Endpoint Isolation Start Success', 'Endpoint Isolation Stop Success', 'Endpoint Isolation Stop Failure']
    if (strings_dict['Event Type'][0] in eventtypes_not_create_new_ticket):
        return
    else:
        return True

# def judge_action_duplicate(strings_dict, ):
#     """異なるイベントタイプで同じファイルハッシュやIP, URLを検知した場合は新しくチケットを立てない"""

def judge_action_id(jkkj, event_info):
    """ids(text)に記載されているイベントのIDを確認し、重複している場合は新しくチケットを立てない"""
    id = str(event_info['event_id'])
    ids = read_ids()
    if (id in ids):
        return
    else:
        add_ids(jkkj, id)
        return True

def add_ids(jkkj, id):
    """CiscoAMPのイベントIDをcsvで管理し、重複チェックを行う"""
    with open('data/ids.csv', 'a') as f:
        writer = csv.writer(f)
        writer.writerow([jkkj, id])

def read_ids():
    """ids.csvを読み込んで返す"""
    with open('data/ids.csv', 'r') as f:
        return f.read()

def clear_ids():
    """ids.csvのファイルサイズを0にする"""
    with open('data/ids.csv', mode="r+") as f:
        print(f.read())
        f.truncate(0)

def html2text(mail_text):
    """メールをHTML形式からテキストに変換（タグを消すだけ）"""
    mail_text = mail_text.replace('<li>', '\n')
    tags = re.findall(r'(<.*?>)', mail_text)
    for tag in tags:
        mail_text = mail_text.replace(tag, '')
    return mail_text

def create_ticket_description(mail_text):
    """Redmineチケットの「説明」を作成"""
    description = get_ticket_description_template().format(mail_text)
    return description

def create_ticket_subject(event_type, jkkj):
    """Redmineチケットの「題名」を作成"""
    subject = f"CiscoAMPで{event_type}を検知({jkkj})"
    return subject

def create_ticket_template(item_id, *args):
    """チケットの「編集」を作成"""
    if item_id != 'ip_addr_private':
        computer_info, event_info, vtscore, vt_url, xfscore, xf_url, xf_data = args[0], args[1], args[2], args[3], args[4], args[5], args[6]
        notes = get_ticket_notes_template(item_id).format(computer_info, event_info, vtscore, vt_url, xfscore, xf_url, xf_data)
    elif item_id == 'ip_addr_private':
        notes = get_ticket_notes_template(item_id)
    return notes

def get_ticket_description_template():
    """チケットの説明内容をテンプレートで管理"""
    with open('templates/Redmine_Template_DESCRIPTION.txt', 'r', encoding='utf-8') as f:
        template = f.read()
    return template

def get_ticket_notes_template(item_id):
    """チケットの編集内容をテンプレートで管理"""
    if item_id == 'file_hash':
        with open('templates/Redmine_Template_NOTE_SuspiciousFile.txt', 'r', encoding='utf-8') as f:
            template = f.read()
    elif item_id == 'url' or item_id == 'ip_addr_global':
        with open('templates/Redmine_Template_NOTE_SuspiciousUrl.txt', 'r', encoding='utf-8') as f:
            template = f.read()
    elif item_id == 'ip_addr_private':
        with open('templates/Redmine_Template_NOTE_PrivateIP.txt', 'r', encoding='utf-8') as f:
            template = f.read()
    return template

def set_id(suspicious_item):
    """item のカテゴリを分類"""
    if "http" in suspicious_item:
        item_id = 'url'
    elif '.' in suspicious_item:
        ip = ipaddress.ip_address(suspicious_item)
        if ip.is_private():
            item_id = 'ip_addr_private'
        else:
            item_id = 'ip_addr_global'
    else:
        item_id = 'file_hash'
    return item_id

def main():
    # メール関連処理
    mail_text = html2text(mailer.fetch_mail_text(num))
    strings_dict = get_info_from_mail(mail_text)
    if judge_action_eventtypes(strings_dict):
        # CiscoAMP関連処理
        jkkj = strings_dict['Hostname'][0]
        computer_info = cisco_amp.get_computer_info(jkkj)
        event_info, event_type = cisco_amp.get_event(computer_info['connector_guid'])
        if judge_action_id(jkkj, event_info):
            if event_type == 'file':
                # レピュテーションサイト関連処理
                suspicious_item = event_info['sha256']
                item_id = set_id(suspicious_item)
                xf, vt = XForce.XForce(suspicious_item, item_id), VirusTotal.VirusTotal(suspicious_item, item_id)
                xf_url, vt_url = xf.get_xf_url(), vt.get_vt_url()
                xfscore, xf_data = xf.get_reputation()
                vtscore = vt.get_reputation()

            elif event_type == 'url':
                suspicious_item = event_info['dirty_url']
                item_id = set_id(suspicious_item)
                # レピュテーションサイト関連処理
                if item_id != 'ip_addr_private':
                    xf, vt = XForce.XForce(suspicious_item, item_id), VirusTotal.VirusTotal(suspicious_item, item_id)
                    xf_url, vt_url = xf.get_xf_url(), vt.get_vt_url()
                    xfscore, xf_data = xf.get_reputation()
                    vtscore = vt.get_reputation()

            # Redmine関連処理
            description = create_ticket_description(mail_text)
            subject = create_ticket_subject(event_info['event_type'], jkkj)
            notes = create_ticket_template(item_id, computer_info, event_info, vtscore, vt_url, xfscore, xf_url, xf_data)
            issue.create_issues(subject, description)
            logger.info(subject + 'を起票しました。')
            issue.update_issues(notes)
            logger.info(subject + 'を編集しました。')
            mailer.set_seen_flag(num)
        else:
            logger.info('起票しないイベント')
    else:
        logger.info('起票しないイベント')

if __name__ == '__main__':
    try:
        script_dir = os.path.dirname(__file__)
        script_root = os.path.abspath(script_dir)
        os.chdir(script_root)

        logger = getLogger(__name__)
        handler = StreamHandler()
        handler.setLevel(DEBUG)
        logger.setLevel(DEBUG)
        logger.addHandler(handler)
        formatter = Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False

        logger.info('StartScript')

        mailer = Mail()
        mailer.connect()
        mail_list = mail_check()

        if mail_list != None:
            issue = Redmine.Issue()
            cisco_amp = CiscoAMP.CiscoAMP()

            logger.info(f'メールを{len(mail_list)}件受信しました。')
            i = 1
            for num in mail_list:
                logger.info(f'{i}件目')
                i+=1
                main()
        else:
            logger.info('新規メールはありません。')
        logger.info('EndScript')
    except Exception as e:
        logger.error(str(e))
    finally:
        mailer.imap_obj.logout()