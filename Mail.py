import yaml
import imapclient, ssl
import email
import smtplib

class Mail:
    def __init__(self):
        self.account = self.get_account()
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.imap_obj = imapclient.IMAPClient(self.account['Mail']['IMAP']['SERVER'], ssl=True, ssl_context=context)

    def connect(self):
        """imapへのログイン"""
        self.imap_obj.login(self.account['Mail']['IMAP']['ACCOUNT'], self.account['Mail']['IMAP']['PASSWORD'])
        self.imap_obj.select_folder('INBOX/NSOC_Automation')

    def detect_newmail(self):
        """
        未読メールを新規と判断
        未読メールがある場合は1を返す
        """
        self.data_in_box = self.imap_obj.search(['UNSEEN'])
        if len(self.data_in_box) == 0:
            return 0
        elif len(self.data_in_box) >= 1:
            return 1

    def fetch_mail_text(self, num):
        """メールの本文を取得"""
        msg_data = self.imap_obj.fetch(num, 'RFC822')
        msg = email.message_from_bytes(msg_data[num][b'RFC822'])

        if msg.is_multipart() is True:
            for part in msg.walk():
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset()
                if charset is not None:
                    payload = payload.decode(charset, "ignore")
                return payload

        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset()
            if charset is not None:
                payload = payload.decode(charset, "ignore")
                return payload

    def set_seen_flag(self, num):
        """既読フラグをつける"""
        self.imap_obj.remove_flags(num, 'UNSEEN', silent=False)

    def get_account(self):
        """アカウント情報取得"""
        with open('conf/Settings.yaml', 'r') as f:
            account = yaml.load(f, Loader=yaml.SafeLoader)
        return account