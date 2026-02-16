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
        "name": "India"
    },
    "bd": {
        "uid": "4522644287",
        "password": "LEGEND-OTVQVWGW8-ARMY",
        "name": "Bangladesh"
    },
    "na": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "North America"
    },
    "br": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Brazil"
    },
    "pk": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Pakistan"
    },
    "sg": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Singapore"
    },
    "id": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Indonesia"
    },
    "me": {
        "uid": "4493875511",
        "password": "3EBF336B61F1E417B0B777BFF74F4E705E961F8760BE3C3E96A7E975FB9025BE",
        "name": "Middle East"
    }
}

# Active bot instances per server
active_bots = {}
bot_start_status = {}

#EMOTES BY YASH X CODEX
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
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
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]"
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
                return None
        except:
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
                return None
        except:
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
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
    else: headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

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
        self.name = self.config["name"] if self.config else server_name.upper()
        self.online_reader = None
        self.chat_reader = None

    async def start(self):
        if not self.config:
            print(f"Invalid server: {self.server_name}")
            return False

        print(f"\nStarting bot for {self.name} server...")
        
        try:
            # Login process
            open_id, access_token = await GeNeRaTeAccEss(self.config['uid'], self.config['password'])
            if not open_id or not access_token:
                print(f"[{self.name}] Login failed")
                return False

            PyL = await EncRypTMajoRLoGin(open_id, access_token)
            MajoRLoGinResPonsE = await MajorLogin(PyL)
            
            if not MajoRLoGinResPonsE:
                print(f"[{self.name}] MajorLogin failed")
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

            LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
            if not LoGinDaTa:
                print(f"[{self.name}] Failed to get login data")
                return False

            LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
            OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
            ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port

            OnLineiP, OnLineporT = OnLinePorTs.split(":")
            ChaTiP, ChaTporT = ChaTPorTs.split(":")

            acc_name = LoGinDaTaUncRypTinG.AccountName

            equie_emote(ToKen, UrL)

            AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), self.key, self.iv)
            
            # Connect to both services
            await self.connect_chat(ChaTiP, ChaTporT, AutHToKen, self.key, self.iv, LoGinDaTaUncRypTinG)
            await self.connect_online(OnLineiP, OnLineporT, self.key, self.iv, AutHToKen)

            self.ready = True
            bot_start_status[self.server_name] = "online"
            print(f"\n✅ [{self.name}] Bot started successfully!")
            print(f"   Bot UID: {self.BOT_UID}")
            print(f"   Account: {acc_name}")
            
            return True

        except Exception as e:
            print(f"[{self.name}] Failed to start: {e}")
            bot_start_status[self.server_name] = "failed"
            return False

    async def connect_chat(self, ip, port, auth_token, key, iv, login_data):
        try:
            self.chat_reader, self.whisper_writer = await asyncio.open_connection(ip, int(port))
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
                    
        except Exception as e:
            print(f"[{self.name}] Chat connection error: {e}")

    async def connect_online(self, ip, port, key, iv, auth_token):
        try:
            self.online_reader, self.online_writer = await asyncio.open_connection(ip, int(port))
            bytes_payload = bytes.fromhex(auth_token)
            self.online_writer.write(bytes_payload)
            await self.online_writer.drain()
            print(f"[{self.name}] Online connected")
        except Exception as e:
            print(f"[{self.name}] Online connection error: {e}")

    async def perform_emote(self, team_code: str, uids: list, emote_id: int):
        if not self.ready or not self.online_writer:
            raise Exception(f"Bot for {self.name} not connected")

        try:
            print(f"[{self.name}] Performing emote: {emote_id} for UIDs: {uids}")
            print(f"[{self.name}] Team code: {team_code}")

            # 1. JOIN SQUAD
            print(f"[{self.name}] Joining squad...")
            EM = await GenJoinSquadsPacket(team_code, self.key, self.iv)
            self.online_writer.write(EM)
            await self.online_writer.drain()
            await asyncio.sleep(1)  # Wait for join to process

            # 2. PERFORM EMOTE for each UID
            for uid_str in uids:
                uid = int(uid_str)
                print(f"[{self.name}] Sending emote to UID: {uid}")
                H = await Emote_k(uid, emote_id, self.key, self.iv, self.region)
                self.online_writer.write(H)
                await self.online_writer.drain()
                await asyncio.sleep(0.2)  # Small delay between emotes

            # 3. LEAVE SQUAD
            print(f"[{self.name}] Leaving squad...")
            LV = await ExiT(self.BOT_UID, self.key, self.iv)
            self.online_writer.write(LV)
            await self.online_writer.drain()
            await asyncio.sleep(0.5)

            print(f"[{self.name}] Emote completed successfully")
            return True

        except Exception as e:
            print(f"[{self.name}] Emote error: {e}")
            raise Exception(f"Failed to perform emote: {str(e)}")

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
        return jsonify({
            "status": "error",
            "message": f"Bot for {server_name} server is not initialized. Please wait.",
            "server_status": bot_start_status
        })

    bot_instance = active_bots.get(server_name)
    
    if not bot_instance.ready:
        return jsonify({
            "status": "error",
            "message": f"Bot for {server_name} server is not ready. Please try again.",
            "server_status": bot_start_status
        })

    # Perform emote
    try:
        # Create task and wait for result
        future = asyncio.run_coroutine_threadsafe(
            bot_instance.perform_emote(team_code, uids, emote_id),
            bot_instance.loop
        )
        result = future.result(timeout=30)
        
        if result:
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
        else:
            response = OrderedDict([
                ("status", "error"),
                ("message", "Emote failed to execute"),
                ("server", server_name)
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
    server_status = {}
    for server, config in SERVER_CONFIGS.items():
        bot = active_bots.get(server)
        server_status[server] = {
            "name": config["name"],
            "status": bot_start_status.get(server, "offline"),
            "bot_uid": str(bot.BOT_UID) if bot and bot.ready else None
        }
    
    response = OrderedDict([
        ("status", "success"),
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
            "/join": "Join squad and perform emote",
            "/servers": "List all available servers"
        }),
        ("available_servers", list(SERVER_CONFIGS.keys())),
        ("example", "/join?tc=3703642&uid1=1103196242&emote_id=909000085&server_name=ind"),
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
    
    # Start only IND server first for testing
    await start_bot_for_server("ind")
    
    print("\n" + "="*60)
    print("✅ IND server bot started")
    print("="*60 + "\n")
    
    return 1

async def MaiiiinE():
    global loop
    
    loop = asyncio.get_running_loop()
    
    # Clear screen and show banner
    os.system('clear' if os.name == 'posix' else 'cls')
    try:
        print(render('EMOTE BOT', colors=['white', 'green'], align='center'))
    except:
        print("="*60)
        print("          EMOTE BOT SYSTEM")
        print("="*60)
    
    # Start IND bot
    await start_all_bots()
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    print("🌐 Flask API server started on port " + os.environ.get("PORT", "10000"))
    
    # Keep the main task running
    while True:
        await asyncio.sleep(60)

async def StarTinG():
    while True:
        try:
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("⏰ Session expired, restarting...")
        except Exception as e:
            print(f"❌ Error: {e}")
            await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(StarTinG())