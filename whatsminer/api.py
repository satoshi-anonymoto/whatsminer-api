"""
Heavily assisted by and modified from code found from an unknown source on Telegram
with the following credit:
 * @Author: passby
 * @Date: 2020-07-23 00:16:29 
"""
import base64
import binascii
import datetime
import hashlib
import json
import logging
import os
import re
import select
import socket

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from passlib.hash import md5_crypt

logger = logging.getLogger(__name__)



"""
    Create a WhatsminerAccessToken for each ASIC you want to control and then pass the
    token to the WhatsminerAPI classmethods.

    Basic flow:

    token1 = WhatsminerAccessToken(ip_address="1.2.3.4", admin_password="xxxx")
    token2 = WhatsminerAccessToken(ip_address="1.2.3.5", admin_password="xxxx")

    # Read-only checks
    WhatsminerAPI.get_read_only_info(token1, "status")
    WhatsminerAPI.get_read_only_info(token2, "status")

    # Writeable API
    WhatsminerAPI.exec_command(token1, "power_off", additional_params={"respbefore": "true"})
"""


class WhatsminerAccessToken:
    """ Reusable token to access and/or control a single Whatsminer ASIC.
        Token will renew itself as needed if it expires.
    """
    def __init__(self, ip_address: str, port: int = 4028, admin_password: str = None):
        # Create a read-only access token with just ip_address.
        # Create a read and write access token with ip_address and admin_password
        self.created = datetime.datetime.now()
        self.ip_address = ip_address
        self.port = port
        self._admin_password = admin_password

        if self._admin_password:
            self._initialize_write_access()


    def _initialize_write_access(self):
        """
        Encryption algorithm:
        Ciphertext = aes256(plaintext)，ECB mode
        Encode text = base64(ciphertext)

        (1)api_cmd = token,$sign|api_str    # api_str is API command plaintext
        (2)enc_str = aes256(api_cmd, $key)  # ECB mode
        (3)tran_str = base64(enc_str)

        Final assembly: enc|base64(aes256("token,sign|set_led|auto", $aeskey))
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.ip_address, self.port))
            s.sendall('{"cmd": "get_token"}'.encode('utf-8'))
            data = recv_all(s, 4000)

        token_info = json.loads(data)["Msg"]
        if token_info == "over max connect":
            raise Exception(data)

        # Make the encrypted key from the admin password and the salt
        pwd = crypt(self._admin_password, "$1$" + token_info["salt"] + '$')
        pwd = pwd.split('$')
        key = pwd[3]

        # Make the aeskey from the key computed above and prep the AES cipher
        aeskey = hashlib.sha256(key.encode()).hexdigest()
        aeskey = binascii.unhexlify(aeskey.encode())
        self.cipher = AES.new(aeskey, AES.MODE_ECB)

        # Make the 'sign' that is passed in as 'token'
        tmp = crypt(pwd[3] + token_info["time"], "$1$" + token_info["newsalt"] + '$')
        tmp = tmp.split('$')
        self.sign = tmp[3]

        self.created = datetime.datetime.now()


    def enable_write_access(self, admin_password: str):
        self._admin_password = admin_password
        self._initialize_write_access()


    def has_write_access(self):
        """ Checks write access and refreshes token, if necessary. """
        if not self._admin_password:
            return False

        if (datetime.datetime.now() - self.created).total_seconds() > 30 * 60:
            # writeable token has expired; reinitialize
            self._initialize_write_access(self._admin_password)

        return True



class WhatsminerAPI:
    """ Stateless classmethod-only read/write API calls. Use a WhatsminerAccessToken
        instance for each ASIC you want to access.
    """

    @classmethod
    def get_read_only_info(self, access_token: WhatsminerAccessToken, cmd: str, additional_params: dict = None):
        """ Send READ-ONLY API command.

            e.g. WhatsminerAPI.get_read_only_info(access_token, cmd="summary")

            Returns: json response
        """
        json_cmd = {"cmd": cmd}
        if additional_params:
            json_cmd.update(additional_params)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((access_token.ip_address, access_token.port))
            s.send(json.dumps(json_cmd).encode('utf-8'))
            data = recv_all(s, 4000)

        try:
            return json.loads(data.decode())
        except Exception as e:
            logging.exception("Error calling read-only endpoint")
            try:
                logging.error(data.decode())
            except:
                pass

            raise e


    @classmethod
    def exec_command(self, access_token: WhatsminerAccessToken, cmd: str, additional_params: dict = None):
        """ Send WRITEABLE API command.

            e.g. WhatsminerAPI.exec_command(access_token, cmd="power_off", additional_params={"respbefore": "true"})

            Returns: json response
        """
        if not access_token.has_write_access():
            raise Exception("access_token must have write access")

        # Assemble the plaintext json
        json_cmd = {"cmd": cmd, "token": access_token.sign}
        if additional_params:
            json_cmd.update(additional_params)
        api_cmd = json.dumps(json_cmd)

        # Encrypt it and assemble the transport json
        enc_str = str(
            base64.encodebytes(
                access_token.cipher.encrypt(add_to_16(api_cmd))),
                encoding='utf8'
            ).replace('\n', '')
        data_enc = {'enc': 1}    # transmit w/ "enc" to signal that it's encrypted
        data_enc['data'] = enc_str
        api_packet_str = json.dumps(data_enc)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((access_token.ip_address, access_token.port))
            s.send(api_packet_str.encode())
            data = recv_all(s, 4000)

        try:
            json_response = json.loads(data.decode())
            if "STATUS" in json_response and json_response["STATUS"] == "E":
                logger.error(json_response["Msg"])
                raise Exception(api_cmd + "\n" + json_response["Msg"])

            resp_ciphertext = b64decode(json.loads(data.decode())["enc"])
            resp_plaintext = access_token.cipher.decrypt(resp_ciphertext).decode().split("\x00")[0]
            resp = json.loads(resp_plaintext)
        except Exception as e:
            logger.exception("Error decoding encrypted response")
            try:
                logger.error(data.decode())
            except:
                pass
            raise e

        return resp



# ================================ misc helpers ================================
def crypt(word, salt):
    standard_salt = re.compile('\s*\$(\d+)\$([\w\./]*)\$')
    match = standard_salt.match(salt)
    if not match:
        raise ValueError("salt format is not correct")
    extra_str = match.group(2)
    result = md5_crypt.hash(word, salt=extra_str)
    return result


# Adapted from: https://stackoverflow.com/a/17668009
def recv_all(sock, n):
    # Helper function to recv n bytes
    sock.setblocking(True)
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            if data:
                return data
            return None
        data.extend(packet)
    return data


def add_to_16(s):
    while len(s) % 16 != 0:
        s += '\0'
    return str.encode(s)  # return bytes

