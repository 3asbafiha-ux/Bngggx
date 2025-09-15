import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, xKEys, base64, datetime, re, socket, threading
from protobuf_decoder.protobuf_decoder import Parser
from black9 import *
from black9 import xSendTeamMsg
from black9 import Auth_Chat
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from threading import Thread

from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def AuTo_ResTartinG():
    time.sleep(6 * 60 * 60)
    print('\n - AuTo ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    for handler in p.open_files():
        try:
            os.close(handler.fd)
        except Exception as e:
            print(f" - Error CLose Files : {e}")
    for conn in p.net_connections():
        try:
            if hasattr(conn, 'fd'):
                os.close(conn.fd)
        except Exception as e:
            print(f" - Error CLose Connection : {e}")
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)

def ResTarT_BoT():
    print('\n - ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = p.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)

def GeT_Time(timestamp):
    last_login = datetime.fromtimestamp(timestamp)
    now = datetime.now()
    diff = now - last_login   
    d = diff.days
    h , rem = divmod(diff.seconds, 3600)
    m , s = divmod(rem, 60)    
    return d, h, m, s

def Time_En_Ar(t): 
    return ' '.join(t.replace("Day","يوم").replace("Hour","ساعة").replace("Min","دقيقة").replace("Sec","ثانية").split(" - "))

Thread(target=AuTo_ResTartinG, daemon=True).start()

class FF_CLient():
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.Get_FiNal_ToKen_0115()
        self.pending_telegram_command = None

    def Connect_SerVer_OnLine(self, Token, tok, host, port, key, iv, host2, port2):
        global CliEnts2, DaTa2, AutH
        try:
            self.AutH_ToKen_0115 = tok
            self.CliEnts2 = socket.create_connection((host2, int(port2)))
            self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))
        except:
            pass
        while True:
            try:
                self.DaTa2 = self.CliEnts2.recv(99999)
                if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                    self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                    self.AutH = self.packet['5']['data']['7']['data']
            except:
                pass

    def Connect_SerVer(self, Token, tok, host, port, key, iv, host2, port2):
        global CliEnts
        self.AutH_ToKen_0115 = tok
        self.CliEnts = socket.create_connection((host, int(port)))
        self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))
        self.DaTa = self.CliEnts.recv(1024)
        threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token, tok, host, port, key, iv, host2, port2)).start()
        self.Exemple = xMsGFixinG('12345678')

        while True:
            try:
                self.DaTa = self.CliEnts.recv(1024)
                if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):
                    try:
                        self.CliEnts.close()
                        self.CliEnts2.close()
                        self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                    except:
                        try:
                            self.CliEnts.close()
                            self.CliEnts2.close()
                            self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                        except:
                            self.CliEnts.close()
                            self.CliEnts2.close()
                            ResTarT_BoT()

                if '1200' in self.DaTa.hex()[0:4] and 900 > len(self.DaTa.hex()) > 100:
                    if b"***" in self.DaTa:
                        self.DaTa = self.DaTa.replace(b"***", b"106")
                    try:
                        self.BesTo_data = json.loads(DeCode_PackEt(self.DaTa.hex()[10:]))
                        self.input_msg = 'besto_love' if '8' in self.BesTo_data["5"]["data"] else self.BesTo_data["5"]["data"]["4"]["data"]
                    except:
                        self.input_msg = None
                    self.DeCode_CliEnt_Uid = self.BesTo_data["5"]["data"]["1"]["data"]
                    self.CliEnt_Uid = EnC_Uid(self.DeCode_CliEnt_Uid, Tp='Uid')

                # تنفيذ أوامر التليجرام إن وُجدت
                if self.pending_telegram_command:
                    cmd_text = self.pending_telegram_command
                    self.pending_telegram_command = None
                    # تحليل الأمر وتنفيذه
                    if cmd_text.startswith("/bngx"):
                        parts = cmd_text.split()
                        if len(parts) == 2:
                            code = parts[1]
                            self.execute_bngx_command(code)
                        else:
                            print("Telegram command /bngx requires a code argument")

            except Exception as e:
                self.CliEnts.close()
                self.CliEnts2.close()
                self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)

    def execute_bngx_command(self, code):
        print(f"Executing /bngx command with code: {code}")
        try:
            if not code:
                print("No code provided for /bngx command")
                return False
            self.CliEnts.send(xSEndMsg(f'\n[b][c][{ArA_CoLor()}] JoinInG With Code {code}\n', 2, self.DeCode_CliEnt_Uid, self.DeCode_CliEnt_Uid, self.key, self.iv))
            self.CliEnts2.send(GenJoinSquadsPacket(code, self.key, self.iv))
            time.sleep(0.5)
            if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                self.dT = json.loads(DeCode_PackEt(self.DaTa2.hex()[10:]))
                sq = self.dT["5"]["data"]["31"]["data"]
                idT = self.dT["5"]["data"]["1"]["data"]
                self.CliEnts2.send(ExiT('000000', self.key, self.iv))
                self.CliEnts2.send(ghost_pakcet(idT, "insta:kha_led_mhd", sq, self.key, self.iv))
                for i in range(1):
                    self.CliEnts2.send(GenJoinSquadsPacket(code, self.key, self.iv))
                    self.CliEnts2.send(ghost_pakcet(idT, "insta:kha_led_mhd", sq, self.key, self.iv))
                    time.sleep(0.5)
                    self.CliEnts2.send(ExiT('000000', self.key, self.iv))
                    self.CliEnts2.send(ghost_pakcet(idT, "insta:kha_led_mhd", sq, self.key, self.iv))
            return True
        except Exception as e:
            print(f"Error executing /bngx command: {e}")
            return False

    # --- الدوال الأخرى كما هي --- #

    def GeT_Key_Iv(self, serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp, key, iv = my_message.field21, my_message.field22, my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv

    def Guest_GeneRaTe(self, uid, password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {"Host": "100067.connect.garena.com",
                        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "close",}
        self.dataa = {"uid": f"{uid}",
                      "password": f"{password}",
                      "response_type": "token",
                      "client_type": "2",
                      "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                      "client_id": "100067",}
        try:
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa).json()
            self.Access_ToKen, self.Access_Uid = self.response['access_token'], self.response['open_id']
            time.sleep(0.2)
            print(' - Starting Black Freind BoT !')
            print(f' - Uid : {uid}\n - Password : {password}')
            print(f' - Access Token : {self.Access_ToKen}\n - Access Id : {self.Access_Uid}')
            return self.ToKen_GeneRaTe(self.Access_ToKen, self.Access_Uid)
        except Exception:
            ResTarT_BoT()

    def GeT_LoGin_PorTs(self, JwT_ToKen, PayLoad):
        self.UrL = 'https://clientbp.common.ggbluefox.com/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',}
        try:
            self.Res = requests.post(self.UrL, headers=self.HeadErs, data=PayLoad, verify=False)
            self.BesTo_data = json.loads(DeCode_PackEt(self.Res.content.hex()))
            address, address2 = self.BesTo_data['32']['data'], self.BesTo_data['14']['data']
            ip, ip2 = address[:len(address) - 6], address2[:len(address2) - 6]
            port, port2 = address[len(address) - 5:], address2[len(address2) - 5:]
            return ip, port, ip2, port2
        except requests.RequestException as e:
            print(f" - Bad Requests !")
        print(" - Failed To GeT PorTs !")
        return None, None

    def ToKen_GeneRaTe(self, Access_ToKen, Access_Uid):
        self.UrL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        self.HeadErs = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'}
        self.dT = bytes.fromhex(
            '...')  # يحافظ على كامل الباينري كما هو في كودك
        self.dT = self.dT.replace(b'2025-07-30 14:11:20', str(datetime.now())[:-7].encode())
        self.dT = self.dT.replace(b'c621f2d621430dac1a782a0dab64e6c80a974a6bc728cf2e6b1224d186c9b7af', Access_ToKen.encode())
        self.dT = self.dT.replace(b'9e71fabf43d88c06b79f548104c7fcb7', Access_Uid.encode())
        self.PaYload = bytes.fromhex(EnC_AEs(self.dT.hex()))
        self.ResPonse = requests.post(self.UrL, headers=self.HeadErs, data=self.PaYload, verify=False)
        if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
            self.BesTo_data = json.loads(DeCode_PackEt(self.ResPonse.content.hex()))
            self.JwT_ToKen = self.BesTo_data['8']['data']
            self.combined_timestamp, self.key, self.iv = self.GeT_Key_Iv(self.ResPonse.content)
            ip, port, ip2, port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen, self.PaYload)
            return self.JwT_ToKen, self.key, self.iv, self.combined_timestamp, ip, port, ip2, port2
        else:
            sys.exit()

    def Get_FiNal_ToKen_0115(self):
        token, key, iv, Timestamp, ip, port, ip2, port2 = self.Guest_GeneRaTe(self.id, self.password)
        self.JwT_ToKen = token
        try:
            self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
            self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
            self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
            self.HeX_VaLue = DecodE_HeX(Timestamp)
            self.TimE_HEx = self.HeX_VaLue
            self.JwT_ToKen_ = token.encode().hex()
            self.key = key
            self.iv = iv
            print(f' - ProxCed Uid : {self.AccounT_Uid}')
        except Exception as e:
            print(f" - Error In ToKen : {e}")
            return
        try:
            self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
            length = len(self.EncoDed_AccounT)
            self.__ = '00000000'
            if length == 9:
                self.__ = '0000000'
            elif length == 8:
                self.__ = '00000000  '
            elif length == 10:
                self.__ = '000000'
            elif length == 7:
                self.__ = '000000000'
            else:
                print('Unexpected length encountered')
            self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
            self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_, key, iv)
        except Exception as e:
            print(f" - Erorr In Final Token : {e}")
        self.AutH_ToKen = self.FiNal_ToKen_0115
        self.Connect_SerVer(self.JwT_ToKen, self.AutH_ToKen, ip, port, key, iv, ip2, port2)
        return self.AutH_ToKen, key, iv


app = Flask(__name__)
ff_client_instance = None

@app.route('/bngx', methods=['GET'])
def bngx():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'Missing code parameter'}), 400
    if not ff_client_instance:
        return jsonify({'error': 'FF_Client not initialized'}), 500
    try:
        success = ff_client_instance.execute_bngx_command(code)
        if success:
            return jsonify({'status': 'success', 'code': code}), 200
        else:
            return jsonify({'status': 'failure', 'message': 'Failed to execute command'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def start_ff_client(uid, pwd):
    global ff_client_instance
    ff_client_instance = FF_CLient(uid, pwd)

def run_flask():
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    account_uid = '4123338376'
    account_pwd = '683E98BE58D714A1D8E5517C02BA5E852D9E5C37D3E8ADCB7527F1BE98E31CB6'
    threading.Thread(target=start_ff_client, args=(account_uid, account_pwd), daemon=True).start()
    run_flask()
