import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp , asyncio , random
from flask import Flask, request, jsonify
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Server configurations with guest accounts
SERVER_CONFIGS = {
    "ind": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "India",
        "retry_count": 0,
        "max_retries": 3
    },
    "bd": {
        "uid": "4522603395",  # Using same for testing - replace with actual BD credentials
        "password": "LEGEND-Y1EPQHEK8-ARMY",
        "name": "Bangladesh",
        "retry_count": 0,
        "max_retries": 3
    },
    "na": {
        "uid": "4493875511",  # Replace with NA credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "North America",
        "retry_count": 0,
        "max_retries": 3
    },
    "br": {
        "uid": "4493875511",  # Replace with BR credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Brazil",
        "retry_count": 0,
        "max_retries": 3
    },
    "pk": {
        "uid": "4493875511",  # Replace with PK credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Pakistan",
        "retry_count": 0,
        "max_retries": 3
    },
    "sg": {
        "uid": "4493875511",  # Replace with SG credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Singapore",
        "retry_count": 0,
        "max_retries": 3
    },
    "id": {
        "uid": "4493875511",  # Replace with ID credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Indonesia",
        "retry_count": 0,
        "max_retries": 3
    },
    "me": {
        "uid": "4493875511",  # Replace with ME credentials
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Middle East",
        "retry_count": 0,
        "max_retries": 3
    }
}

# Active bot instances per server
active_bots = {}
bot_locks = {}
bot_start_status = {}  # Track initialization status

#EMOTES BY YASH X CODEX
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
BOT_UID = None
key = None
iv = None
region = None
#------------------------------------------#

app = Flask(__name__)

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: 
                print(f"Failed to get access token for UID {uid}: {response.status}")
                return None, None
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.120.2"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=payload, headers=Hr, ssl=ssl_context, timeout=30) as response:
                if response.status == 200: 
                    return await response.read()
                print(f"MajorLogin failed with status: {response.status}")
                return None
        except Exception as e:
            print(f"MajorLogin exception: {e}")
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr_copy = Hr.copy()
    Hr_copy['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=payload, headers=Hr_copy, ssl=ssl_context, timeout=30) as response:
                if response.status == 200: 
                    return await response.read()
                print(f"GetLoginData failed with status: {response.status}")
                return None
        except Exception as e:
            print(f"GetLoginData exception: {e}")
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: 
        try:
            ChaT.write(PacKeT)
            await ChaT.drain()
        except:
            pass
    elif TypE == 'OnLine' and OnLinE:
        try:
            OnLinE.write(PacKeT)
            await OnLinE.drain()
        except:
            pass
    else: 
        return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, bot_name="Unknown", reconnect_delay=0.5):
    global online_writer
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            print(f"[{bot_name}] Online connection established")
            
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key, iv)
                        # We need whisper_writer reference - will be handled in main loop
                        
                    except Exception as e:
                        print(f"[{bot_name}] Error processing online packet: {e}")

        except Exception as e: 
            print(f"[{bot_name}] Online connection error: {e}")
            online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region, bot_name="Unknown", reconnect_delay=0.5):
    print(f"[{bot_name}] Starting TCP Chat...")

    global whisper_writer, online_writer
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            print(f"[{bot_name}] Chat connection established")
            
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print(f'[{bot_name}] Bot in Clan: {clan_id}')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: 
                    whisper_writer.write(pK) 
                    await whisper_writer.drain()
            
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        # Handle chat messages - simplified for now
                        pass
                    except:
                        pass
                            
        except Exception as e: 
            print(f"[{bot_name}] Chat connection error: {e}")
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)

# ---------------------- BOT INSTANCE CLASS ----------------------

class BotInstance:
    def __init__(self, server_name):
        self.server_name = server_name
        self.config = SERVER_CONFIGS.get(server_name)
        self.loop = None
        self.key = None
        self.iv = None
        self.region = None
        self.BOT_UID = None
        self.online_writer = None
        self.whisper_writer = None
        self.ready = False
        self.ready_event = asyncio.Event()
        self.task1 = None
        self.task2 = None
        self.name = self.config["name"] if self.config else server_name.upper()
        self.start_time = None
        self.error_count = 0

    async def start(self):
        if not self.config:
            print(f"Invalid server: {self.server_name}")
            bot_start_status[self.server_name] = "failed"
            return False

        print(f"\n{'='*50}")
        print(f"Starting bot for {self.name} server...")
        print(f"{'='*50}")
        
        try:
            # Login process with retry
            max_login_retries = 3
            for attempt in range(max_login_retries):
                print(f"[{self.name}] Login attempt {attempt + 1}/{max_login_retries}")
                
                open_id, access_token = await GeNeRaTeAccEss(self.config['uid'], self.config['password'])
                if not open_id or not access_token:
                    print(f"[{self.name}] Login failed, retrying in 2s...")
                    await asyncio.sleep(2)
                    continue
                
                print(f"[{self.name}] Got access token, proceeding...")
                
                PyL = await EncRypTMajoRLoGin(open_id, access_token)
                MajoRLoGinResPonsE = await MajorLogin(PyL)
                
                if not MajoRLoGinResPonsE:
                    print(f"[{self.name}] MajorLogin failed, retrying...")
                    await asyncio.sleep(2)
                    continue
                
                # Success - break retry loop
                break
            else:
                # All retries failed
                print(f"[{self.name}] All login attempts failed!")
                bot_start_status[self.server_name] = "failed"
                return False

            MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
            UrL = MajoRLoGinauTh.url
            self.region = MajoRLoGinauTh.region
            ToKen = MajoRLoGinauTh.token
            TarGeT = MajoRLoGinauTh.account_uid
            self.key = MajoRLoGinauTh.key
            self.iv = MajoRLoGinauTh.iv
            timestamp = MajoRLoGinauTh.timestamp
            self.BOT_UID = int(TarGeT)

            print(f"[{self.name}] Got login data, getting ports...")

            LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
            if not LoGinDaTa:
                print(f"[{self.name}] Failed to get login data!")
                bot_start_status[self.server_name] = "failed"
                return False

            LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
            OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
            ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port

            OnLineiP, OnLineporT = OnLinePorTs.split(":")
            ChaTiP, ChaTporT = ChaTPorTs.split(":")

            acc_name = LoGinDaTaUncRypTinG.AccountName

            equie_emote(ToKen, UrL)

            AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), self.key, self.iv)
            
            self.start_time = datetime.now()
            
            # Create tasks
            self.task1 = asyncio.create_task(
                self._run_chat(ChaTiP, ChaTporT, AutHToKen, self.key, self.iv,
                              LoGinDaTaUncRypTinG, self.region)
            )

            # Wait for chat to be ready
            await asyncio.sleep(2)

            self.task2 = asyncio.create_task(
                self._run_online(OnLineiP, OnLineporT, self.key, self.iv, AutHToKen)
            )

            self.ready = True
            bot_start_status[self.server_name] = "online"
            print(f"\n✅ [{self.name}] Bot started successfully!")
            print(f"   Bot UID: {self.BOT_UID}")
            print(f"   Account: {acc_name}")
            print(f"   Region: {self.region}\n")
            
            return True

        except Exception as e:
            print(f"[{self.name}] Failed to start: {e}")
            import traceback
            traceback.print_exc()
            bot_start_status[self.server_name] = "failed"
            return False

    async def _run_chat(self, ip, port, auth_token, key, iv, login_data, region):
        global whisper_writer
        while True:
            try:
                reader, writer = await asyncio.open_connection(ip, int(port))
                self.whisper_writer = writer
                whisper_writer = writer
                bytes_payload = bytes.fromhex(auth_token)
                self.whisper_writer.write(bytes_payload)
                await self.whisper_writer.drain()
                print(f"[{self.name}] Chat connected")
                
                if login_data.Clan_ID:
                    clan_id = login_data.Clan_ID
                    clan_compiled_data = login_data.Clan_Compiled_Data
                    pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                    if self.whisper_writer:
                        self.whisper_writer.write(pK)
                        await self.whisper_writer.drain()
                
                while True:
                    data = await reader.read(9999)
                    if not data:
                        break
                    
            except Exception as e:
                print(f"[{self.name}] Chat error: {e}")
                self.whisper_writer = None
                whisper_writer = None
            await asyncio.sleep(1)

    async def _run_online(self, ip, port, key, iv, auth_token):
        global online_writer
        while True:
            try:
                reader, writer = await asyncio.open_connection(ip, int(port))
                self.online_writer = writer
                online_writer = writer
                bytes_payload = bytes.fromhex(auth_token)
                self.online_writer.write(bytes_payload)
                await self.online_writer.drain()
                print(f"[{self.name}] Online connected")
                
                while True:
                    data = await reader.read(9999)
                    if not data:
                        break
                    
            except Exception as e:
                print(f"[{self.name}] Online error: {e}")
                self.online_writer = None
                online_writer = None
            await asyncio.sleep(1)

    async def perform_emote(self, team_code: str, uids: list, emote_id: int):
        if not self.ready or not self.online_writer:
            raise Exception(f"Bot for {self.name} not connected")

        try:
            # Set global variables for compatibility
            global online_writer, key, iv, region, BOT_UID
            online_writer = self.online_writer
            key = self.key
            iv = self.iv
            region = self.region
            BOT_UID = self.BOT_UID

            print(f"[{self.name}] Performing emote: {emote_id} for UIDs: {uids}")

            # 1. JOIN SQUAD
            EM = await GenJoinSquadsPacket(team_code, self.key, self.iv)
            await SEndPacKeT(self.online_writer, None, 'OnLine', EM)
            await asyncio.sleep(0.15)

            # 2. PERFORM EMOTE
            for uid_str in uids:
                uid = int(uid_str)
                H = await Emote_k(uid, emote_id, self.key, self.iv, self.region)
                await SEndPacKeT(self.online_writer, None, 'OnLine', H)
                await asyncio.sleep(0.05)

            # 3. LEAVE SQUAD
            LV = await ExiT(self.BOT_UID, self.key, self.iv)
            await SEndPacKeT(self.online_writer, None, 'OnLine', LV)
            await asyncio.sleep(0.05)

            print(f"[{self.name}] Emote completed successfully")
            return {"status": "success", "message": f"Emote done on {self.name}"}

        except Exception as e:
            print(f"[{self.name}] Emote error: {e}")
            raise Exception(f"Failed to perform emote on {self.name}: {str(e)}")

# ---------------------- FLASK ROUTES ----------------------

@app.route('/join')
def join_team():
    team_code = request.args.get('tc')
    uid1 = request.args.get('uid1')
    uid2 = request.args.get('uid2')
    uid3 = request.args.get('uid3')
    uid4 = request.args.get('uid4')
    uid5 = request.args.get('uid5')
    uid6 = request.args.get('uid6')
    emote_id_str = request.args.get('emote_id')
    server_name = request.args.get('server_name', 'ind').lower()

    if not team_code or not emote_id_str:
        return jsonify({
            "status": "error", 
            "message": "Missing tc or emote_id",
            "usage": "/join?tc=CODE&uid1=UID&emote_id=ID&server_name=ind"
        })

    if server_name not in SERVER_CONFIGS:
        return jsonify({
            "status": "error", 
            "message": f"Invalid server. Choose from: {', '.join(SERVER_CONFIGS.keys())}"
        })

    try:
        emote_id = int(emote_id_str)
    except:
        return jsonify({"status": "error", "message": "emote_id must be integer"})

    uids = [uid for uid in [uid1, uid2, uid3, uid4, uid5, uid6] if uid]

    if not uids:
        return jsonify({"status": "error", "message": "Provide at least one UID"})

    # Check bot status
    if server_name not in active_bots:
        status = bot_start_status.get(server_name, "not_started")
        return jsonify({
            "status": "error",
            "message": f"Bot for {server_name} server is {status}. Please wait for initialization.",
            "server_status": bot_start_status
        })

    bot_instance = active_bots.get(server_name)
    
    # Wait for bot to be ready (with timeout)
    max_wait = 30  # seconds
    start_wait = time.time()
    while not bot_instance.ready and time.time() - start_wait < max_wait:
        time.sleep(1)
    
    if not bot_instance.ready:
        return jsonify({
            "status": "error",
            "message": f"Bot for {server_name} server is not ready after {max_wait}s. Please try again.",
            "server_status": bot_start_status
        })

    # Perform emote
    try:
        # Create task and wait for result
        future = asyncio.run_coroutine_threadsafe(
            bot_instance.perform_emote(team_code, uids, emote_id),
            bot_instance.loop
        )
        result = future.result(timeout=15)
        
        response = OrderedDict([
            ("status", "success"),
            ("server", server_name),
            ("server_name", SERVER_CONFIGS[server_name]["name"]),
            ("team_code", team_code),
            ("uids", uids),
            ("emote_id", emote_id_str),
            ("message", "Emote triggered successfully"),
            ("channel", "@legendapis"),
            ("owner", "@Legend_official0"),
            ("credit", "API by @Legend_official0"),
        ])
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e),
            "server": server_name
        })

@app.route('/servers')
def list_servers():
    """Endpoint to list all available servers and their status"""
    server_status = {}
    for server, config in SERVER_CONFIGS.items():
        bot = active_bots.get(server)
        server_status[server] = {
            "name": config["name"],
            "status": bot_start_status.get(server, "offline"),
            "bot_uid": str(bot.BOT_UID) if bot and bot.ready else None,
            "uptime": str(datetime.now() - bot.start_time) if bot and bot.start_time else None
        }
    
    response = OrderedDict([
        ("status", "success"),
        ("total_servers", len(SERVER_CONFIGS)),
        ("online_servers", sum(1 for s in server_status.values() if s["status"] == "online")),
        ("servers", server_status),
        ("channel", "@legendapis"),
        ("owner", "@Legend_official0"),
        ("credit", "API by @Legend_official0"),
    ])
    
    return jsonify(response)

@app.route('/')
def home():
    response = OrderedDict([
        ("status", "online"),
        ("message", "Multi-Server Emote Bot API"),
        ("endpoints", {
            "/join": "Join squad and perform emote (params: tc, uid1-6, emote_id, server_name)",
            "/servers": "List all available servers and their status"
        }),
        ("available_servers", list(SERVER_CONFIGS.keys())),
        ("server_status", bot_start_status),
        ("example", "/join?tc=CODE&uid1=123456&emote_id=5&server_name=ind"),
        ("channel", "@legendapis"),
        ("owner", "@Legend_official0"),
        ("credit", "API by @Legend_official0"),
    ])
    return jsonify(response)

def run_flask():
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# ---------------------- MAIN BOT SYSTEM ----------------------

async def start_bot_for_server(server_name):
    """Start a bot instance for a specific server"""
    bot = BotInstance(server_name)
    bot.loop = asyncio.get_running_loop()
    success = await bot.start()
    if success:
        active_bots[server_name] = bot
        return True
    return False

async def start_all_bots():
    """Start bots for all configured servers"""
    print("\n" + "="*60)
    print("STARTING MULTI-SERVER EMOTE BOT SYSTEM")
    print("="*60 + "\n")
    
    tasks = []
    for server_name in SERVER_CONFIGS.keys():
        tasks.append(start_bot_for_server(server_name))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    successful = 0
    for server, result in zip(SERVER_CONFIGS.keys(), results):
        if result is True:
            successful += 1
        elif isinstance(result, Exception):
            print(f"❌ Failed to start bot for {server}: {result}")
            bot_start_status[server] = "failed"
    
    print("\n" + "="*60)
    print(f"✅ Started {successful}/{len(SERVER_CONFIGS)} bots")
    print("="*60 + "\n")
    
    return successful

async def monitor_bots():
    """Monitor bot health and restart if needed"""
    while True:
        await asyncio.sleep(30)  # Check every 30 seconds
        
        for server_name, bot in list(active_bots.items()):
            if not bot.ready:
                print(f"⚠️ Bot for {server_name} is not ready, attempting restart...")
                await start_bot_for_server(server_name)

async def MaiiiinE():
    # This is the main function that will be called
    global loop
    
    loop = asyncio.get_running_loop()
    
    # Clear screen and show banner
    os.system('clear' if os.name == 'posix' else 'cls')
    try:
        print(render('MULTI SERVER', colors=['white', 'green'], align='center'))
    except:
        print("="*60)
        print("          MULTI-SERVER EMOTE BOT SYSTEM")
        print("="*60)
    
    # Start all bots
    await start_all_bots()
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    print("🌐 Flask API server started on port " + os.environ.get("PORT", "10000"))
    
    # Start monitor
    asyncio.create_task(monitor_bots())
    
    # Keep the main task running
    while True:
        await asyncio.sleep(60)

async def StarTinG():
    while True:
        try:
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("⏰ Session expired, restarting all bots...")
        except Exception as e:
            print(f"❌ Error in main loop: {e}, restarting...")
            import traceback
            traceback.print_exc()
            await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(StarTinG())