import logging
import requests
import urllib3
from requests_toolbelt.multipart.encoder import MultipartEncoder


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# THIS IS STILL A WIP
class FireWebCall:
    def __init__(self,hostname: str,username: str,password: str,verify_cert=False):

        if not verify_cert:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0'
        }
        self.hostname = hostname
        self.session = requests.Session()
        self.verify_cert = verify_cert
        self.username = username
        self.password = password

    def handle_auth(self):
        auth_type = 'login'
        logger.info(f'Attempting {auth_type.upper()} with Firepower Management Center {self.hostname}')

        url = f'https://{self.hostname}/auth/{auth_type}'

        multipart_data = MultipartEncoder(
            fields={
                'username':self.username,
                'password':self.password,
                'endSession': '1'
            }
        )

        self.headers['Content-Type'] = multipart_data.content_type
        session = self.session.post(
            url=url,
            headers=self.headers,
            verify=self.verify_cert,
            data=multipart_data,
        )
        return

