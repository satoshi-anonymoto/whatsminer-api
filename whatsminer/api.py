"""
Heavily assisted by and modified from code found from an unknown source on Telegram
with the following credit:
 * @Author: passby
 * @Date: 2020-07-23 00:16:29 
"""
import base64
import hashlib
import json
import os
import re
import select
import socket

from base64 import b64encode, b64decode
from Crypto.Cipher import AES



class WhatsminerAPI:
    def __init__(self, ip_address, admin_password):
        self.host = ip_address
        self.admin_password = admin_password
        self.port = 4028


    def get_read_only(self, cmd: str, additional_params: dict = None):
        """ Send READ-ONLY API command.

            Returns: json response
        """
        json_cmd = {"cmd": cmd}
        if additional_params:
            json_cmd.update(additional_params)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.send(json.dumps(json_cmd).encode('utf-8'))
            data = recv_all(s, 4000)

        try:
            return json.loads(data.decode())
        except Exception as e:
            print(repr(e))
            print(data.decode())
            raise e



    def exec_command(self, cmd: str, additional_params: dict = None):
        # -------------- Send WRITEABLE API command --------------
        """
        Encryption algorithm:
        Ciphertext = aes256(plaintext)，ECB mode
        Encode text = base64(ciphertext)

        (1)api_cmd = token,$sign|api_str    # api_str is API command plaintext
        (2)enc_str = aes256(api_cmd, $key)  # ECB mode
        (3)tran_str = base64(enc_str)

        Final assembly: enc|base64(aes256("token,sign|set_led|auto", $aeskey))
        """
        def add_to_16(s):
            while len(s) % 16 != 0:
                s += '\0'
            return str.encode(s)  # return bytes

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall('{"cmd": "get_token"}'.encode('utf-8'))
            data = recv_all(s, 4000)

        token_info = json.loads(data)["Msg"]
        if token_info == "over max connect":
            raise Exception(data)

        # key = openssl passwd -1 -salt $salt "$(admin_passwd)" | cut -f 4 -d '$'
        key = os.popen(f"""openssl passwd -1 -salt {token_info["salt"]} "{self.admin_password}" | cut -f 4 -d '$'""").read().strip()
        aeskey = hashlib.sha256(key.encode('utf-8'))
        cipher = AES.new(aeskey.digest(), AES.MODE_ECB)

        token = f"""{token_info["time"]} {token_info["salt"]} {token_info["newsalt"]}"""

        # sign = openssl passwd -1 -salt $newsalt "${key}${time:0-4}" | cut -f 4 -d '$'
        sign = os.popen(f"""openssl passwd -1 -salt {token_info["newsalt"]} "{key}{token_info["time"]}" | cut -f 4 -d '$'""").read().strip()

        json_cmd = {"cmd": cmd, "token": sign}
        if additional_params:
            json_cmd.update(additional_params)

        api_cmd = json.dumps(json_cmd)

        # api_cmd = json.dumps({"cmd": "summary", "token": sign})
        enc_str = str(base64.encodebytes(cipher.encrypt(add_to_16(api_cmd))), encoding='utf8').replace('\n', '')
        data_enc = {'enc': 1}
        data_enc['data'] = enc_str
        api_packet_str = json.dumps(data_enc)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.send(api_packet_str.encode())    # transmit w/ "enc" to signal that it's encrypted
            data = recv_all(s, 4000)

        resp_ciphertext = b64decode(json.loads(data.decode())["enc"])
        resp_plaintext = cipher.decrypt(resp_ciphertext).decode().split("\x00")[0]
        resp = json.loads(resp_plaintext)

        return resp


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

