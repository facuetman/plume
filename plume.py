import datetime
import json
import os
import random
import re
import sys
import time
from typing import List

import eth_account.messages
import ua_generator
from curl_cffi import requests
from dotenv import load_dotenv
from loguru import logger
from peewee import Model, FloatField, CharField, IntegerField, SqliteDatabase, DateTimeField
from playhouse.sqlite_ext import JSONField
from tenacity import retry, stop_after_attempt, wait_random
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractLogicError
from web3.types import TxReceipt, BlockData, HexBytes, TxParams, ChecksumAddress

import wallet_util
from yes_captcha import YesCaptcha

load_dotenv()
db = SqliteDatabase(os.path.dirname(__file__) + '/plume_testnet.db')

logger.remove(0)
logger.add(sys.stdout, level="INFO")
logger.add("logs/plume_tx_{time:YYYY-MM-DD-HH-mm-ss-SSS}.log", level="INFO", rotation="100 MB")


class PlumeAccount(Model):
    wallet_address = CharField()
    private_key = CharField(null=True)
    version = IntegerField(null=True)
    invite_code = CharField(null=True)
    perchy_safe_mint_time = DateTimeField(null=True)
    next_perchy_safe_mint_time = DateTimeField(null=True)
    next_invite_time = DateTimeField(null=True)
    vote_time = DateTimeField(null=True)
    next_vote_time = DateTimeField(null=True)
    invite_count = IntegerField(null=True)
    total_points = IntegerField(null=True)
    eth_faucet_time = DateTimeField(null=True)
    next_eth_faucet_time = DateTimeField(null=True)
    goon_faucet_time = DateTimeField(null=True)
    next_goon_faucet_time = DateTimeField(null=True)
    game_time = DateTimeField(null=True)
    next_game_time = DateTimeField(null=True)
    create_token_time = DateTimeField(null=True)
    next_create_token_time = DateTimeField(null=True)
    swap_time = DateTimeField(null=True)
    next_swap_time = DateTimeField(null=True)
    stake_time = DateTimeField(null=True)
    next_stake_time = DateTimeField(null=True)
    kuma_nft_time = DateTimeField(null=True)
    eth_balance = FloatField(null=True)
    auth_token = CharField(null=True)
    olympics_time = DateTimeField(null=True)
    next_olympics_time = DateTimeField(null=True)
    swap_usd_plus_time = DateTimeField(null=True)
    next_swap_usd_plus_time = DateTimeField(null=True)
    mint_aick_time = DateTimeField(null=True)
    next_mint_aick_time = DateTimeField(null=True)
    landshare_time = DateTimeField(null=True)
    next_landshare_time = DateTimeField(null=True)
    ua_info = JSONField(null=True)

    class Meta:
        database = db
        table_name = 'plume_account'


class PlumePetOlympic(Model):
    wallet_address = CharField()
    event_name = CharField()
    pet_time = DateTimeField()

    class Meta:
        database = db
        table_name = 'plume_pet_olympic'


class QgProxy:

    def __init__(self, auth_key, password):
        self.auth_key = auth_key
        self.password = password
        # 代理ip服务器
        self.proxy_addr = None
        self.proxy_ip = None
        self.deadline = None

    def get_proxies(self) -> dict:
        # return {}
        self._get_proxy_ip()
        proxy_url = "http://%(user)s:%(password)s@%(server)s" % {
            "user": self.auth_key,
            "password": self.password,
            "server": self.proxy_addr,
        }
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        return proxies

    def _get_proxy_ip(self):
        if self.proxy_addr is not None:
            if self.deadline >= datetime.datetime.now() - datetime.timedelta(seconds=10):
                return self.proxy_addr
        proxy_ip_res = requests.get(f"{os.getenv('qg_url')}?key={self.auth_key}&distinct=true")
        self.proxy_addr = proxy_ip_res.json()['data'][0]['server']
        self.proxy_ip = proxy_ip_res.json()['data'][0]['proxy_ip']
        dead_time = proxy_ip_res.json()['data'][0]['deadline']
        self.deadline = datetime.datetime.strptime(dead_time, '%Y-%m-%d %H:%M:%S')
        logger.info(
            f"Get New Proxy IP address 💻 : {self.proxy_ip} , Proxy Addr: {self.proxy_addr} , Dead Line: {self.deadline}")
        time.sleep(1)


class FuncCallData:
    address: ChecksumAddress
    data: bytes
    value: int


class Plume:

    def __init__(self,
                 wallet_address: str,
                 private_key: str,
                 qg_proxy: QgProxy,
                 version: int = None,
                 ref_invite_code: str = None
                 ):
        db.create_tables([PlumePetOlympic, PlumeAccount])
        self.version = version
        self.ref_invite_code = ref_invite_code
        self.wallet_address = wallet_address
        self.private_key = private_key
        self.qg_proxy = qg_proxy
        self.ua_info = ua_generator.generate(device='desktop', browser=('chrome', 'edge')).headers.get()
        self.__init_db_data()
        self.solidviolet_token = None
        self.w3 = Web3(Web3.HTTPProvider("https://testnet-rpc.plumenetwork.xyz/http"
                                         , request_kwargs={
                # "proxies": {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
            }
                                         ))
        if not self.w3.is_connected():
            raise Exception("Web3 not connected")
        f = open(os.path.dirname(__file__) + '/contract_abi.json', 'r', encoding='utf-8')
        full_abl_json = json.load(f)
        self.goon_contract = self.w3.eth.contract(abi=full_abl_json['goon']['abi'],
                                                  address=Web3.to_checksum_address(
                                                      full_abl_json['goon']['contractAddress']))
        self.croc_impact_contract = self.w3.eth.contract(abi=full_abl_json['crocImpact']['abi'],
                                                         address=Web3.to_checksum_address(
                                                             full_abl_json['crocImpact']['contractAddress']))
        self.croc_swap_dex_contract = self.w3.eth.contract(abi=full_abl_json['crocSwapDex']['abi'],
                                                           address=Web3.to_checksum_address(
                                                               full_abl_json['crocSwapDex']['contractAddress']))
        self.gn_usd_contract = self.w3.eth.contract(abi=full_abl_json['gnUsd']['abi'],
                                                    address=Web3.to_checksum_address(
                                                        full_abl_json['gnUsd']['contractAddress']))
        self.nest_staking_contract = self.w3.eth.contract(abi=full_abl_json['nestStaking']['abi'],
                                                          address=Web3.to_checksum_address(
                                                              full_abl_json['nestStaking']['contractAddress']))

        self.check_in_contract = self.w3.eth.contract(abi=full_abl_json['checkIn']['abi'],
                                                      address=Web3.to_checksum_address(
                                                          full_abl_json['checkIn']['contractAddress']))

        self.game_contract = self.w3.eth.contract(abi=full_abl_json['oracleGame']['abi'],
                                                  address=Web3.to_checksum_address(
                                                      full_abl_json['oracleGame']['contractAddress']))
        self.faucet_contract = self.w3.eth.contract(abi=full_abl_json['faucet']['abi'],
                                                    address=Web3.to_checksum_address(
                                                        full_abl_json['faucet']['contractAddress']))
        self.rwa_factory_contract = self.w3.eth.contract(abi=full_abl_json['rwaFactory']['abi'],
                                                         address=Web3.to_checksum_address(
                                                             full_abl_json['rwaFactory']['contractAddress']))
        # 奥运会竞猜
        self.cultured_contract = self.w3.eth.contract(abi=full_abl_json['cultured']['abi'],
                                                      address=Web3.to_checksum_address(
                                                          full_abl_json['cultured']['contractAddress']))

        self.kuma_mint_contract = self.w3.eth.contract(abi=full_abl_json['KUMAMint']['abi'],
                                                       address=Web3.to_checksum_address(
                                                           full_abl_json['KUMAMint']['contractAddress']))
        self.kuma_swap_contract = self.w3.eth.contract(abi=full_abl_json['kumaSwap']['abi'],
                                                       address=Web3.to_checksum_address(
                                                           full_abl_json['kumaSwap']['contractAddress']))

        self.kuma_bonds_contract = self.w3.eth.contract(abi=full_abl_json['kumaBonds']['abi'],
                                                        address=Web3.to_checksum_address(
                                                            full_abl_json['kumaBonds']['contractAddress']))

        self.usd_plus_contract = self.w3.eth.contract(abi=full_abl_json['usdPlus']['abi'],
                                                      address=Web3.to_checksum_address(
                                                          full_abl_json['usdPlus']['contractAddress']))

        self.plume_test_router_contract = self.w3.eth.contract(abi=full_abl_json['plumeTestRouter']['abi'],
                                                               address=Web3.to_checksum_address(
                                                                   full_abl_json['plumeTestRouter']['contractAddress']))

        self.landshare_swap_contract = self.w3.eth.contract(abi=full_abl_json['landshareSwap']['abi'],
                                                            address=Web3.to_checksum_address(
                                                                full_abl_json['landshareSwap']['contractAddress']))
        self.land_contract = self.w3.eth.contract(abi=full_abl_json['land']['abi'],
                                                  address=Web3.to_checksum_address(
                                                      full_abl_json['land']['contractAddress']))
        self.master_chef_contract = self.w3.eth.contract(abi=full_abl_json['masterChef']['abi'],
                                                         address=Web3.to_checksum_address(
                                                             full_abl_json['masterChef']['contractAddress']))
        self.perchy_contract = self.w3.eth.contract(abi=full_abl_json['perchy']['abi'],
                                                    address=Web3.to_checksum_address(
                                                        full_abl_json['perchy']['contractAddress']))
        self.governance_contract = self.w3.eth.contract(abi=full_abl_json['governance']['abi'],
                                                        address=Web3.to_checksum_address(
                                                            full_abl_json['governance']['contractAddress']))

    @staticmethod
    def tx_record(func):
        def log_func_done(plume_instance):
            logger.info(f"{plume_instance.wallet_address} {func.__name__} 已经处理")

        def wrapper(*args, **kwargs):
            plume_instance: Plume = args[0]
            plume_account = plume_instance.plume_account

            if func.__name__ == "invite_wallet":
                if (plume_account.next_invite_time is not None
                        and plume_account.next_invite_time > datetime.datetime.now()):
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "vote":
                if (plume_account.next_vote_time is not None
                        and plume_account.next_vote_time > datetime.datetime.now()):
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "perchy_safe_mint":
                if (plume_account.next_perchy_safe_mint_time is not None
                        and plume_account.next_perchy_safe_mint_time > datetime.datetime.now()):
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "goon_faucet":
                if plume_account.next_goon_faucet_time is not None and plume_account.next_goon_faucet_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "eth_faucet":
                if plume_account.next_eth_faucet_time is not None and plume_account.next_eth_faucet_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "swap_goon_to_gn_usd":
                if plume_account.next_swap_time is not None and plume_account.next_swap_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "predict_oracle":
                if plume_account.next_olympics_time is not None and plume_account.next_olympics_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "create_token":
                if plume_account.next_create_token_time is not None and plume_account.next_create_token_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "game":
                if plume_account.next_game_time is not None and plume_account.next_game_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "swap_usd_plus":
                if plume_account.next_swap_usd_plus_time is not None and plume_account.next_swap_usd_plus_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "mint_aick":
                if plume_account.next_mint_aick_time is not None and plume_account.next_mint_aick_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            if func.__name__ == "landshare":
                if plume_account.next_landshare_time is not None and plume_account.next_landshare_time > datetime.datetime.now():
                    log_func_done(plume_instance)
                    return
            res = None
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                if str(e).__contains__("Daily stake limit reached") or str(e).__contains__("nonce too low"):
                    logger.debug(f"{plume_instance.wallet_address} 执行常规错误 {func.__name__} 出错 {e}")
                else:
                    logger.error(f"{plume_instance.wallet_address} 执行 {func.__name__} 出错 {e}")
                    raise e
            if func.__name__ == "invite_wallet":
                plume_account.next_invite_time = datetime.datetime.now() + datetime.timedelta(
                    minutes=random.randint(60, 180))
                plume_account.save()
            if func.__name__ == "perchy_safe_mint":
                plume_account.perchy_safe_mint_time = datetime.datetime.now()
                plume_account.next_perchy_safe_mint_time = plume_account.perchy_safe_mint_time + datetime.timedelta(
                    days=1,
                    minutes=random.randint(20, 80)
                )
                plume_account.save()
            if func.__name__ == "goon_faucet":
                plume_account.goon_faucet_time = datetime.datetime.now()
                plume_account.next_goon_faucet_time = plume_account.goon_faucet_time + datetime.timedelta(
                    hours=int(os.getenv("goon_facuet_hours")), minutes=random.randint(1, 10))
                plume_account.save()
            if func.__name__ == "eth_faucet":
                plume_account.eth_faucet_time = datetime.datetime.now()
                plume_account.next_eth_faucet_time = plume_account.eth_faucet_time + datetime.timedelta(
                    hours=int(os.getenv("eth_facuet_hours")), minutes=random.randint(1, 10))
                plume_account.save()
            if func.__name__ == "swap_goon_to_gn_usd":
                plume_account.swap_time = datetime.datetime.now()
                plume_account.next_swap_time = plume_account.swap_time + datetime.timedelta(days=1,
                                                                                            minutes=random.randint(60,
                                                                                                                   180))
                plume_account.save()
            if func.__name__ == "vote":
                plume_account.vote_time = datetime.datetime.now()
                next_day = plume_account.vote_time + datetime.timedelta(days=1)
                plume_account.next_vote_time = datetime.datetime(year=next_day.year, month=next_day.month,
                                                                 day=next_day.day, hour=random.randint(8, 23),
                                                                 minute=random.randint(0, 59))
                plume_account.save()
            if func.__name__ == "swap_usd_plus":
                plume_account.swap_usd_plus_time = datetime.datetime.now()
                plume_account.next_swap_usd_plus_time = plume_account.swap_usd_plus_time + datetime.timedelta(days=1,
                                                                                                              minutes=random.randint(
                                                                                                                  60,
                                                                                                                  180))
                plume_account.save()

            if func.__name__ == "mint_aick":
                plume_account.mint_aick_time = datetime.datetime.now()
                plume_account.next_mint_aick_time = plume_account.mint_aick_time + datetime.timedelta(days=1,
                                                                                                      minutes=random.randint(
                                                                                                          60,
                                                                                                          180))
                plume_account.save()
            if func.__name__ == "predict_oracle":
                plume_account.olympics_time = datetime.datetime.now()
                plume_account.next_olympics_time = plume_account.olympics_time + datetime.timedelta(
                    minutes=random.randint(240, 300))
                plume_account.save()
            if func.__name__ == "create_token":
                plume_account.create_token_time = datetime.datetime.now()
                plume_account.next_create_token_time = (plume_account.create_token_time
                                                        + datetime.timedelta(days=1,
                                                                             minutes=random.randint(
                                                                                 60,
                                                                                 180)))
                plume_account.save()
            if func.__name__ == "landshare":
                plume_account.landshare_time = datetime.datetime.now()
                plume_account.next_landshare_time = (plume_account.landshare_time
                                                     + datetime.timedelta(days=1,
                                                                          minutes=random.randint(
                                                                              60,
                                                                              180)))
                plume_account.save()
            if func.__name__ == "game":
                plume_account.game_time = datetime.datetime.now()
                plume_account.next_game_time = plume_account.game_time + datetime.timedelta(
                    minutes=random.randint(240, 300))
                plume_account.save()
            if func.__name__ == "stake_gn_usd":
                plume_account.stake_time = datetime.datetime.now()
                plume_account.save()
            return res

        return wrapper

    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def login_solidviolet(self):
        nonce = self.__get_login_solidviolet_nonce()
        sign_text = f'''By signing this message, you accept the SolidViolet's Terms and Conditions (https://www.solidviolet.com/terms) and Privacy Policy (https://www.solidviolet.com/privacy).

This will not trigger a blockchain transaction.

Wallet address:
{self.wallet_address}

Nonce:
{nonce}
'''
        sign_text_decode = eth_account.messages.encode_defunct(
            text=sign_text
        )
        sign_msg = self.w3.eth.account.sign_message(sign_text_decode, private_key=self.private_key).signature.hex()

        login_res = requests.post("https://api.app.solidviolet.com/api/v1/auth/login", headers={
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "priority": "u=1, i",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "mode": "cors",
            "origin": "https://app.solidviolet.com",
            "referrer": "https://app.solidviolet.com/",
            "referrerPolicy": "strict-origin-when-cross-origin",
            ":authority:": "api.app.solidviolet.com",
            **self.ua_info,
            "X-Solidviolet-Wallet-Address": f"{self.wallet_address}"
        },
                                  json={"address": self.wallet_address,
                                        "nonce": nonce,
                                        "signature": sign_msg})
        login_json = login_res.json()
        self.solidviolet_token = login_json['token']

    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def __get_login_solidviolet_nonce(self) -> str:
        nonce_res = requests.post("https://app.solidviolet.com/tokens/1", headers={
            "accept": "text/x-component",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "content-type": "text/plain;charset=UTF-8",
            "next-action": "7c1249eab789ac7d5b1c3f321f3dd7e0c7fd3ee4",
            "next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22consumer%22%2C%7B%22children%22%3A%5B%22tokens%22%2C%7B%22children%22%3A%5B%5B%22tokenId%22%2C%221%22%2C%22d%22%5D%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Ftokens%2F1%22%2C%22refresh%22%5D%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D%7D%5D",
            "priority": "u=1, i",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "mode": "cors",
            "origin": "https://app.solidviolet.com",
            "referrer": "https://app.solidviolet.com/tokens/1",
            "referrerPolicy": "strict-origin-when-cross-origin",
            ":authority:": "app.solidviolet.com",
            **self.ua_info,
        },
                                  data="[]")
        result = re.search(r'1:"(.*?)"', nonce_res.content.decode('utf-8'))
        if result:
            return result.group(1)
        else:
            raise Exception(f"{self.wallet_address} login_solidviolet 获取nonce失败 {nonce_res.content}")

    @tx_record
    @retry(stop=stop_after_attempt(5), wait=wait_random(min=1, max=3))
    def landshare(self):
        self.__do_approve_gn_usd(0.1, "0xd2aade12760d5e176f93c8f1c6ae10667c8fca8b")
        time.sleep(random.randint(5, 10))
        self.__contract_call(self.landshare_swap_contract.functions.swap())
        time.sleep(random.randint(5, 10))
        self.__do_approve_land(0.1, "0x5374cf69c5610950526c668a7b540df6686531b4")
        time.sleep(random.randint(5, 10))
        tx_hash = self.__contract_call(self.master_chef_contract.functions.deposit(0, Web3.to_wei(0.1, 'ether')))
        logger.info(
            f"🎉 {self.wallet_address} landshare success 🔗 : {tx_hash.hex()}")

    @tx_record
    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def swap_usd_plus(self):
        self.login_solidviolet()
        time.sleep(5)
        if self.solidviolet_token is None:
            logger.warning(f"{self.wallet_address} has no solidviolet token")
            return
        gn_usd_eth_balance = round(
            Web3.from_wei(self.gn_usd_contract.functions.balanceOf(self.wallet_address).call(), 'ether'), 3)
        if gn_usd_eth_balance <= 20:
            logger.warning(f"{self.wallet_address} gnUsd too low")
            return

        swap_usd_plus_amount = random.randint(1, 20)
        self.__do_approve_gn_usd(swap_usd_plus_amount, "0x06107c39d3fd57a059bc4abae09f3b2b3d75d64e")
        time.sleep(random.randint(5, 10))
        swap_usd_plus_amount_wei = Web3.to_wei(swap_usd_plus_amount, 'ether')

        transfer_hex_data = self.gn_usd_contract.encode_abi(
            fn_name="transfer",
            args=[
                Web3.to_checksum_address(
                    "0x4181803232280371E02a875F51515BE57B215231"),
                swap_usd_plus_amount_wei])

        mint_hex_data = self.usd_plus_contract.encode_abi(
            fn_name="mint",
            args=[
                Web3.to_checksum_address(
                    "0x06107C39D3Fd57a059Bc4Abae09f3b2b3d75D64E"),
                int(Web3.from_wei(
                    swap_usd_plus_amount_wei,
                    'szabo'))])

        func_call_datas = [[
            Web3.to_checksum_address(
                "0x5c1409a46cd113b3a667db6df0a8d7be37ed3bb3"),
            transfer_hex_data
            ,
            0
        ],
            [
                Web3.to_checksum_address(
                    "0x4194dddfb5938293621e78dd72e9bb22e59515d0"),
                mint_hex_data,
                0
            ]]

        execute_swap_data = {"parameters": {
            "swapper": Web3.to_checksum_address(self.wallet_address),
            "settler": Web3.to_checksum_address(
                "0x06107c39d3fd57a059bc4abae09f3b2b3d75d64e"),
            "tokenIn": Web3.to_checksum_address(
                "0x5c1409a46cd113b3a667db6df0a8d7be37ed3bb3")
            ,
            "amountIn": swap_usd_plus_amount_wei,
            "tokenOut": Web3.to_checksum_address(
                "0x4194dddfb5938293621e78dd72e9bb22e59515d0"),
            "minAmountOut": int(Web3.from_wei(
                swap_usd_plus_amount_wei, 'szabo')),
            "expiry": 0,
            "salt": 0
        },
            "calls": func_call_datas}

        exec_func = self.plume_test_router_contract.functions.executeSwap(
            execute_swap_data
        )
        tx_hash = self.__contract_call(exec_func)
        logger.info(f"🎉 {self.wallet_address} buy usd+  🔗 : {tx_hash.hex()}")

    def __init_db_data(self):
        is_exist_account = PlumeAccount.select().where(
            PlumeAccount.wallet_address == self.wallet_address).count() > 0
        if is_exist_account:
            self.plume_account: PlumeAccount = PlumeAccount.select().where(
                PlumeAccount.wallet_address == self.wallet_address).get()
            if self.plume_account.ua_info is None:
                self.plume_account.ua_info = self.ua_info
                self.plume_account.save()
            else:
                self.ua_info = self.plume_account.ua_info

            if self.plume_account.version is None:
                self.plume_account.version = self.version
                self.plume_account.save()
            if self.plume_account.private_key is None:
                self.plume_account.private_key = self.private_key
                self.plume_account.save()
        else:
            self.plume_account: PlumeAccount = PlumeAccount.create(wallet_address=self.wallet_address,
                                                                   private_key=self.private_key,
                                                                   version=self.version,
                                                                   ua_info=self.ua_info)

    @tx_record
    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def vote(self):
        end_date = datetime.datetime(year=2024, month=8, day=29, hour=0, minute=0, second=0)
        if datetime.datetime.utcnow() >= end_date:
            return
        remaining_votes = self.governance_contract.functions.getUserRemainingVotes(
            Web3.to_checksum_address(self.wallet_address)).call()
        if remaining_votes > 0:
            for i in range(remaining_votes):
                tx_hash = self.__contract_call(self.governance_contract.functions.vote(random.randint(1, 17)))
                logger.info(f"🎉 {self.wallet_address} vote 第{i}次 🔗 : {tx_hash.hex()}")

    @tx_record
    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def perchy_safe_mint(self):
        try:
            tx_hash = self.__contract_call(self.perchy_contract.functions.safeMint(), wait_tx=True)
            logger.info(f"🎉 {self.wallet_address} perchy mint 🔗 : {tx_hash.hex()}")
        except Exception as e:
            if str(e).__contains__("Can only mint once per interval"):
                logger.info(f"🎉 {self.wallet_address} 24小时mint重复")
            else:
                raise e

    @tx_record
    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def mint_aick(self):
        tx_hash = self.__contract_call(self.kuma_mint_contract.functions.mintAICK(), wait_tx=True)
        logger.info(f"🎉 {self.wallet_address} mint aick  🔗 : {tx_hash.hex()}")
        token_id = None
        while True:
            nft_tokens_res = requests.post(
                "https://api.goldsky.com/api/public/project_clyh18uad08wu01uah2zi4h1k/subgraphs/kuma-plume-testnet/0.1.0/gn",
                headers={
                    "accept": "*/*",
                    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "content-type": "application/json",
                    "priority": "u=1, i",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                    "mode": "cors",
                    "Referer": "https://plume.kuma.bond/",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    ":authority": "api.goldsky.com",
                    **self.ua_info,
                },
                json={
                    "query": "query allUserKumaBondTokens($owner: Bytes!) {\n  kumabondTokens(where: {owner: $owner}) {\n    ...KUMA_BOND_TOKEN_FRAGMENT\n  }\n}\n\nfragment RISK_CATEGORY_FRAGMENT on RiskCategory {\n  issuer\n  currency\n  id\n  term\n}\n\nfragment MINIMAL_KIBT_FRAGMENT on KIBToken {\n  name\n  symbol\n  id\n  address\n  epochLength\n  decimals\n}\n\nfragment KUMA_BOND_TOKEN_FRAGMENT on KUMABondToken {\n  tokenId: id\n  ownerAddress: owner\n  expired\n  redeemed\n  cusip\n  isin\n  issuance\n  maturity\n  coupon\n  principal\n  riskCategory {\n    ...RISK_CATEGORY_FRAGMENT\n    kibToken: KIBToken {\n      ...MINIMAL_KIBT_FRAGMENT\n    }\n  }\n}",
                    "variables": {"owner": f"{self.wallet_address}"},
                    "operationName": "allUserKumaBondTokens"
                }).json()
            nft_tokens = nft_tokens_res["data"]["kumabondTokens"]
            if len(nft_tokens) == 0:
                logger.info(f"{self.wallet_address} 未找到nft token Id 等待10s")
                time.sleep(10)
                continue
            nft_info = random.choice(nft_tokens)
            token_id = int(nft_info["tokenId"])
            break
        address: str = self.kuma_bonds_contract.functions.getApproved(token_id).call()
        if not address.lower().__contains__('0xa4e9ddad862a1b8b5f8e3d75a3aad4c158e0faab'.lower()):
            self.__contract_call(self.kuma_bonds_contract.functions.approve(
                Web3.to_checksum_address("0xa4e9ddad862a1b8b5f8e3d75a3aad4c158e0faab"), token_id))
        tx_hash = self.__contract_call(self.kuma_swap_contract.functions.sellBond(tokenId=token_id), wait_tx=True)
        logger.info(f"🎉 {self.wallet_address} mint and sell bonds 🔗 : {tx_hash.hex()}")

    def is_olympics_event_predict(self, event_name: str) -> bool:
        return PlumePetOlympic.select().where(
            (PlumePetOlympic.event_name == event_name)
            & (PlumePetOlympic.wallet_address == self.wallet_address)).count() > 0

    @tx_record
    def predict_oracle(self):
        '''
        预测 奥运会
        Returns:

        '''

        # print(Web3.solidity_keccak(['bytes'], ['0x' + eth_abi.encode(['string[]'],
        #                                                              [["OlympicsSummer2024", "MedalCount-MostGoldMedal",
        #                                                                "team-nation", "Albania"]]).hex()]).hex())

        pet_data_res = requests.get("https://points-api.plumenetwork.xyz/olympics",
                                    headers={
                                        "accept": "*/*",
                                        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                                        "content-type": "application/json",
                                        "priority": "u=1, i",
                                        "sec-fetch-dest": "empty",
                                        "sec-fetch-mode": "cors",
                                        "sec-fetch-site": "same-origin",
                                        "mode": "cors",
                                        "Referer": "https://miles.plumenetwork.xyz/",
                                        "Referrer-Policy": "strict-origin-when-cross-origin",
                                        ":authority": "points-api.plumenetwork.xyz",
                                        **self.ua_info,
                                    },
                                    # proxies=self.qg_proxy.get_proxies()
                                    )
        pet_data = pet_data_res.json()
        now = int(datetime.datetime.now().timestamp())
        can_pet_event = [e for e in pet_data['events'] if
                         e['bet_start'] <= now and e['bet_end'] >= now and not self.is_olympics_event_predict(
                             e['name'])]
        if len(can_pet_event) == 0:
            return
        random.shuffle(can_pet_event)
        for event in can_pet_event:
            competitor: str = random.choice(event['competitors'])
            competitor_arr = competitor.split(":")
            logger.debug(f"{self.wallet_address} start predict oracle ${event['name']}")
            tx_hash = self.__contract_call(self.cultured_contract.functions.predictOracle(
                [pet_data['oracleKeyPrefix'], event['name'], competitor_arr[0], competitor_arr[1]], 1), wait_tx=True)
            logger.info(f"🎉 {self.wallet_address} predict oracle ${event['name']}  🔗 : {tx_hash.hex()}")
            PlumePetOlympic.insert({
                PlumePetOlympic.wallet_address: self.wallet_address,
                PlumePetOlympic.event_name: event['name'],
                PlumePetOlympic.pet_time: datetime.datetime.now()
            }).execute()
            time.sleep(random.randint(10, 15))

    @tx_record
    def create_token(self):
        image_url = [
            {
                'rawType': 0,
                'image': "https://miles.plumenetwork.xyz/images/arc/art.webp"
            },
            {
                'rawType': 1,
                'image': "https://miles.plumenetwork.xyz/images/arc/collectible-cards.webp",
            },
            {
                'rawType': 2,
                'image': "https://miles.plumenetwork.xyz/images/arc/farming.webp"
            },
            {
                'rawType': 3,
                'image': "https://miles.plumenetwork.xyz/images/arc/investment-alcohol.webp"
            },
            {
                'rawType': 4,
                'image': "https://miles.plumenetwork.xyz/images/arc/investment-cigars.webp",
            },
            {
                'rawType': 5,
                'image': "https://miles.plumenetwork.xyz/images/arc/investment-watch.webp"
            },
            {
                'rawType': 6,
                'image': "https://miles.plumenetwork.xyz/images/arc/rare-sneakers.webp",
            },
            {
                'rawType': 7,
                'image': "https://miles.plumenetwork.xyz/images/arc/real-estate.webp"
            },
            {
                'rawType': 8,
                'image': "https://miles.plumenetwork.xyz/images/arc/solar-energy.webp"
            },
            {
                'rawType': 9,
                'image': "https://miles.plumenetwork.xyz/images/arc/tokenized-gpus.webp"
            }
        ]
        random_image = random.choice(image_url)
        # 获取name
        random_name = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz', random.randint(5, 10)))
        random_desc = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz', random.randint(5, 10)))
        # Get and determine gas parameters
        latest_block: BlockData = self.w3.eth.get_block("latest")
        base_fee_per_gas = latest_block['baseFeePerGas']  # Base fee in the latest block (in wei)
        max_priority_fee_per_gas = int(base_fee_per_gas * 1.02)  # Priority fee to include the transaction in the block
        max_fee_per_gas = int(max_priority_fee_per_gas)  # Maximum amount you’re willing to pay

        tx_hash = self.__contract_call(
            self.rwa_factory_contract.functions.createToken(random_name, 'ITEM', random_desc, random_image['rawType'],
                                                            random_image['image']),
            custom_fee={"maxFeePerGas": max_fee_per_gas, "maxPriorityFeePerGas": max_priority_fee_per_gas})
        logger.info(
            f"🎉 {self.wallet_address} create token ${random_name}  🔗 : {tx_hash.hex()}")

    def low_eth_balance(self) -> bool:
        gas_eth_balance = self.get_eth_gas_balance()
        if gas_eth_balance < 0.003:
            logger.info(f"{self.wallet_address} 当前gas过低，跳过执行 余额: {gas_eth_balance:.7f} $eth")
            return True
        return False

    def get_eth_gas_balance(self):
        eth_gas_balance = float(round(
            Web3.from_wei(self.w3.eth.get_balance(Web3.to_checksum_address(self.wallet_address)), 'ether'), 8))
        return eth_gas_balance

    @tx_record
    def eth_faucet(self):
        try:
            try_sign(self)
            self.__do_faucet('ETH')
        except ContractLogicError as e:
            if e.message.__contains__('Signature is already used'):
                logger.warning(f"{self.wallet_address} $ETH faucet already used")
            else:
                raise e

    @tx_record
    def goon_faucet(self):
        try:
            self.__do_faucet('GOON')
        except ContractLogicError as e:
            if e.message.__contains__('Signature is already used'):
                logger.warning(f"{self.wallet_address} $GOON faucet already used")
            else:
                raise e

    @tx_record
    def stake_gn_usd(self):
        gn_usd_eth_balance = round(
            Web3.from_wei(self.gn_usd_contract.functions.balanceOf(self.wallet_address).call(), 'ether'), 3)
        if gn_usd_eth_balance <= 4:
            logger.warning(f"{self.wallet_address} stake $gnUsd amount too low {gn_usd_eth_balance}")
            return
        stake_gn_usd_eth_amount = random.randint(1, int(gn_usd_eth_balance / 2))
        self.__do_approve_gn_usd(stake_gn_usd_eth_amount, "0xa34420e04de6b34f8680ee87740b379103dc69f6")
        self.__do_stake_gn_usd(stake_gn_usd_eth_amount)

    def __do_stake_gn_usd(self, stake_gn_usd_eth_amount):
        tx_hash = self.__contract_call(
            self.nest_staking_contract.functions.stake(Web3.to_wei(stake_gn_usd_eth_amount, 'ether')))
        logger.info(
            f"🎉 {self.wallet_address} stake {stake_gn_usd_eth_amount} $gnUsd 🔗 : {tx_hash.hex()}")

    def __do_approve_gn_usd(self, stake_gn_usd_eth_amount, address: str):
        tx_hash = self.__contract_call(
            self.gn_usd_contract.functions.approve(
                Web3.to_checksum_address(address),
                Web3.to_wei(stake_gn_usd_eth_amount, 'ether')), wait_tx=True)
        logger.info(
            f"🎉 {self.wallet_address} approve {stake_gn_usd_eth_amount} $gnUsd 🔗 : {tx_hash.hex()}")

    def __do_approve_land(self, land_eth_amount, address: str):
        tx_hash = self.__contract_call(
            self.land_contract.functions.approve(
                Web3.to_checksum_address(address),
                Web3.to_wei(land_eth_amount, 'ether')), wait_tx=True)
        logger.info(
            f"🎉 {self.wallet_address} approve {land_eth_amount} $land 🔗 : {tx_hash.hex()}")

    @tx_record
    def swap_goon_to_gn_usd(self):
        '''
        每日 swap goon
        :return:
        '''
        self.__goon_swap_approve()
        self.__do_swap_goon()
        time.sleep(random.randint(10, 15))
        self.stake_gn_usd()

    def __do_swap_goon(self):
        goon_balance = self.goon_contract.functions.balanceOf(Web3.to_checksum_address(self.wallet_address)).call()
        goon_eth_balance = float(round(Web3.from_wei(goon_balance, 'ether'), 3))
        if goon_eth_balance < 0.003:
            logger.warning(f"{self.wallet_address} swap amount too low {goon_eth_balance}")
            return
        swap_amount = int(Web3.to_wei(round(random.uniform(0.001, goon_eth_balance / 2), 3), 'ether'))
        base_flow = abs(self.croc_impact_contract.functions.calcImpact(
            Web3.to_checksum_address("0x5c1409a46cd113b3a667db6df0a8d7be37ed3bb3"),
            Web3.to_checksum_address("0xba22114ec75f0d55c34a5e5a3cf384484ad9e733"),
            36000,
            False,
            False, swap_amount,
            0, 65537).call()[0])
        min_out = int(base_flow * 0.99)

        tx_hash = self.__contract_call_legend(
            self.croc_swap_dex_contract.functions.swap(
                Web3.to_checksum_address("0x5c1409a46cd113b3a667db6df0a8d7be37ed3bb3"),
                Web3.to_checksum_address("0xba22114ec75f0d55c34a5e5a3cf384484ad9e733"),
                36000, False, False, swap_amount,
                0, 65537, min_out, 0), wait_tx=True)
        logger.info(f"🎉 {self.wallet_address} swap {Web3.from_wei(swap_amount, 'ether')} $goon 🔗 : {tx_hash.hex()}")

    def __goon_swap_approve(self):
        # 检查是否授权
        approved_value = self.goon_contract.functions.allowance(Web3.to_checksum_address(self.wallet_address),
                                                                Web3.to_checksum_address(
                                                                    "0x4c722a53cf9eb5373c655e1dd2da95acc10152d1")).call()
        if (approved_value == 0):
            tx_hash = self.__contract_call_legend(
                self.goon_contract.functions.approve(
                    Web3.to_checksum_address("0x4c722a53cf9eb5373c655e1dd2da95acc10152d1"), ((2 ** 256) - 1)),
                wait_tx=True)
            logger.info(f"🎉 {self.wallet_address} swap $goon 合约授权 🔗 : {tx_hash.hex()}")

    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def sign(self):
        nonce_info_result = self.__get_login_nonce()
        fmt_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        sign_text = f"miles.plumenetwork.xyz wants you to sign in with your Ethereum account:\n{self.wallet_address}\n\nPlease sign with your account\n\nURI: https://miles.plumenetwork.xyz\nVersion: 1\nChain ID: 161221135\nNonce: {nonce_info_result}\nIssued At: {fmt_date}"
        sign_text_decode = eth_account.messages.encode_defunct(
            text=sign_text
        )
        sign_msg = self.w3.eth.account.sign_message(sign_text_decode, private_key=self.private_key).signature.hex()
        logger.info(f"🎉 {self.wallet_address} 获取到nonce: {nonce_info_result}")
        referrer = None
        if self.ref_invite_code is not None:
            referrer = self.ref_invite_code.replace("PLUME-", "")

        data = {"message": sign_text, "referrer": referrer, "signature": sign_msg,
                "strategy": "web3"}

        auth_info = requests.post("https://points-api.plumenetwork.xyz/authentication",
                                  json=data,
                                  headers={
                                      "accept": "*/*",
                                      "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                                      "content-type": "application/json",
                                      "priority": "u=1, i",
                                      "sec-fetch-dest": "empty",
                                      "sec-fetch-mode": "cors",
                                      "sec-fetch-site": "same-origin",
                                      "mode": "cors",
                                      "Referer": "https://miles.plumenetwork.xyz/",
                                      "Referrer-Policy": "strict-origin-when-cross-origin",
                                      **self.ua_info,
                                  },
                                  proxies=self.qg_proxy.get_proxies()
                                  )
        auth_info_result = auth_info.json()
        logger.info(f"🎉 {self.wallet_address} 获取到用户信息: {auth_info_result}")
        self.plume_account.total_points = int(auth_info_result['user']['totalPoints'])
        self.plume_account.invite_code = auth_info_result['user']['referralCode']
        self.plume_account.version = self.version
        self.plume_account.save()

    def __get_login_nonce(self):
        nonce_info = requests.post("https://points-api.plumenetwork.xyz/auth/nonce",
                                   headers={
                                       "accept": "*/*",
                                       "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                                       "content-type": "application/json",
                                       "priority": "u=1, i",
                                       "sec-fetch-dest": "empty",
                                       "sec-fetch-mode": "cors",
                                       "sec-fetch-site": "same-origin",
                                       "referrerPolicy": "strict-origin-when-cross-origin",
                                       "mode": "cors",
                                       "referrer": "https://miles.plumenetwork.xyz/",
                                       **self.ua_info,
                                   },
                                   proxies=self.qg_proxy.get_proxies()
                                   )
        nonce_info_result = nonce_info.text.replace('"', "")
        return nonce_info_result

    def is_today_check_in(self) -> bool:
        # 判断是否checkIn
        day_num = int(datetime.datetime.utcnow().strftime("%d"))

        contract_day_num = (
            self.check_in_contract.functions.getLastCheckinDay(Web3.to_checksum_address(self.wallet_address))
            .call())
        return contract_day_num == day_num

    @tx_record
    def invite_wallet(self):
        if os.getenv("enable_invite") != True:
            return

        if self.plume_account.invite_code is not None:
            wallet_info: list = wallet_util.create_wallet()
            new_plume = Plume(wallet_address=wallet_info[0], private_key=wallet_info[1],
                              qg_proxy=QgProxy(auth_key=os.getenv("qg_auth_key"), password=os.getenv("qg_authpwd")),
                              ref_invite_code=self.plume_account.invite_code.__str__(), version=3)
            new_plume.sign()
            logger.info(f"${self.wallet_address} 邀请 ${new_plume.wallet_address}")
            # new_plume.do_task_tx()

    @retry(stop=stop_after_attempt(3), wait=wait_random(min=1, max=3))
    def check_in(self):
        is_today_check_in = self.is_today_check_in()
        if is_today_check_in:
            logger.info(f"🎉 {self.wallet_address} 今日已经签到完成")
            return
        if self.w3.eth.get_balance(Web3.to_checksum_address(self.wallet_address)) == 0:
            logger.error(f"{self.wallet_address} gas 不足")
            return

        tx_hash = self.__contract_call(self.check_in_contract.functions.checkIn(), wait_tx=True)
        logger.info(f"🎉 {self.wallet_address} 签到 🔗 : {tx_hash.hex()}")

    def transfer_eth(self, to_address: str):
        transaction = {
            "to": Web3.to_checksum_address(to_address),
            "value": self.get_eth_gas_balance() - (21000 * self.w3.eth.gas_price),
            "gas": 21000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": self.w3.eth.get_transaction_count(Web3.to_checksum_address(self.wallet_address), 'pending'),
        }
        # 签名交易
        signed_tx = self.w3.eth.account.sign_transaction(transaction, self.private_key)
        # 发送原始的交易
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.info(f"{self.wallet_address} 转账到 {to_address}: {tx_hash.hex()}")

    def check_gas(self):
        '''
        检查gas是否够，否则会出现交互后不够gas领水
        '''
        eth_gas_balance = self.get_eth_gas_balance()
        if eth_gas_balance < 0.003:
            logger.info(f"{self.wallet_address} gas {eth_gas_balance}  过低，优先领水")
            self.eth_faucet()
            time.sleep(random.randint(5, 10))
            self.goon_faucet()
            time.sleep(random.randint(5, 10))
        self.plume_account.eth_balance = eth_gas_balance
        self.plume_account.save()

    @tx_record
    def game(self):
        game_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        # range_int = len(game_list)
        range_int = 1
        parties_index = random.sample(game_list, range_int)
        random.shuffle(parties_index)
        for e in range(0, range_int):
            try:
                pair_index = parties_index[e]
                is_long = bool(random.getrandbits(1))
                tx_hash = self.__contract_call(self.game_contract.functions.predictPriceMovement(pair_index, is_long),
                                               wait_tx=True)
                logger.info(
                    f"🎉 {self.wallet_address} game 🎮 {pair_index} 选择 - {'上涨' if is_long else '下跌'}  🔗 : {tx_hash.hex()}")
                time.sleep(random.randint(2, 4))
            except Exception as e:
                logger.warning(f"{self.wallet_address} game 出错 {e}")

    def __contract_call(self, call_able: ContractFunction, wait_tx: bool = False, custom_fee: dict = None) -> HexBytes:
        logger.debug(f"{self.wallet_address} 开始执行 __contract_call {call_able.fn_name}")
        if custom_fee is None:
            wait_time = random.randint(1, 10)
            logger.debug(f"{self.wallet_address} 执行前等待 {wait_time}s __contract_call {call_able.fn_name}")
            time.sleep(wait_time)
        max_fee_per_gas, max_priority_fee_per_gas = self.get_fee_pre_gas(custom_fee)
        tx_data = {
            'type': 2,
            'from': Web3.to_checksum_address(self.wallet_address),
            'maxFeePerGas': max_fee_per_gas,  # Maximum amount you’re willing to pay
            'maxPriorityFeePerGas': max_priority_fee_per_gas,  # Priority fee to include the transaction in the block
            'nonce': self.w3.eth.get_transaction_count(Web3.to_checksum_address(self.wallet_address), 'pending'),
        }

        transaction: TxParams = call_able.build_transaction(tx_data)
        signed_txn = self.w3.eth.account.sign_transaction(transaction,
                                                          private_key=self.private_key)
        logger.debug(
            f"{self.wallet_address} 签署 __contract_call {call_able.fn_name} 本地hash： {signed_txn.hash.hex()}")
        tx_hash = None
        try:
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        except Exception as ex:
            if str(ex).__contains__("nonce too low:"):
                tx = self.w3.eth.get_transaction(signed_txn.hash)
                if tx is not None:
                    logger.debug(f"{self.wallet_address} : {signed_txn.hash.hex()} 出现nonce太低报错，但是已经交易成功")
                    tx_hash = signed_txn.hash
            else:
                raise ex
        logger.debug(
            f"{self.wallet_address} 已提交 __contract_call {call_able.fn_name} 本地hash： {signed_txn.hash.hex()}")
        self.wait_tx_complete(call_able, tx_hash, True)
        return tx_hash

    def get_fee_pre_gas(self, custom_fee: dict = None):
        if custom_fee is not None:
            return custom_fee['maxFeePerGas'], custom_fee['maxPriorityFeePerGas']

        # Get and determine gas parameters
        latest_block: BlockData = self.w3.eth.get_block("latest")
        base_fee_per_gas = latest_block['baseFeePerGas']  # Base fee in the latest block (in wei)
        max_priority_fee_per_gas = Web3.to_wei(1.5, 'gwei')  # Priority fee to include the transaction in the block
        max_fee_per_gas = int(base_fee_per_gas * 1.2 + max_priority_fee_per_gas)  # Maximum amount you’re willing to pay
        logger.debug(
            f"{self.wallet_address} 获取到 base_fee_per_gas {base_fee_per_gas} wei -> {Web3.from_wei(base_fee_per_gas, 'gwei')} gwei,"
            f" max_fee_per_gas: {max_fee_per_gas} wei -> {Web3.from_wei(max_fee_per_gas, 'gwei')} gwei ")
        return max_fee_per_gas, max_priority_fee_per_gas

    def __contract_call_legend(self, call_able: ContractFunction, wait_tx: bool = False, custom_w3=None,
                               t_data: dict = None) -> HexBytes:
        logger.debug(f"{self.wallet_address} 开始执行 __contract_call_legend {call_able.fn_name}")
        if custom_w3 is None:
            w3 = self.w3
        else:
            w3 = custom_w3
        gas = int(call_able.estimate_gas(
            {
                'from': self.wallet_address,
                'nonce': w3.eth.get_transaction_count(account=Web3.to_checksum_address(self.wallet_address),
                                                      block_identifier='pending')
            }
        ) * 1.12)
        gas_price = int(w3.eth.gas_price * 1.1)
        transaction_data = {
            'from': Web3.to_checksum_address(self.wallet_address),
            'gas': gas,
            'gasPrice': gas_price,
            'nonce': w3.eth.get_transaction_count(Web3.to_checksum_address(self.wallet_address), 'pending'),
        }
        if t_data is not None:
            transaction_data = {
                **transaction_data,
                **t_data
            }

        transaction = call_able.build_transaction(transaction_data)
        signed_txn = w3.eth.account.sign_transaction(transaction,
                                                     private_key=self.private_key)
        logger.debug(
            f"{self.wallet_address} 签署 __contract_call_legend {call_able.fn_name} 本地hash： {signed_txn.hash.hex()}")
        tx_hash = None
        try:
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        except Exception as ex:
            if str(ex).__contains__("nonce too low:"):
                tx = w3.eth.get_transaction(signed_txn.hash)
                if tx is not None:
                    logger.debug(f"{self.wallet_address} : {signed_txn.hash.hex()} 出现nonce太低报错，但是已经交易成功")
                    tx_hash = signed_txn.hash
            else:
                raise ex
        logger.debug(
            f"{self.wallet_address} 已提交 __contract_call_legend {call_able.fn_name} 本地hash： {signed_txn.hash.hex()}")
        self.wait_tx_complete(call_able, tx_hash, wait_tx)
        return tx_hash

    def wait_tx_complete(self, call_able, tx_hash, wait_tx):
        if wait_tx:
            while True:
                tx_receipt: TxReceipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                if tx_receipt.status == 0:
                    raise Exception(
                        f"{tx_hash.hex()} 执行 {call_able.fn_name} 失败,合约地址： {tx_receipt.contractAddress} ")
                elif tx_receipt.status == 1:
                    break
                else:
                    time.sleep(1)
                    continue

    def claim_reward(self):
        unclaimed_miles = \
            self.nest_staking_contract.functions.getUnclaimedRewards(
                Web3.to_checksum_address(self.wallet_address)).call()[
                2]
        if unclaimed_miles > 0:
            tx_hash = self.__contract_call(self.nest_staking_contract.functions.claim())
            logger.info(f"🎉 {self.wallet_address} 领取奖励 🎁 完成 🔗 : {tx_hash.hex()}")

    def bridge_eth(self):
        if not self.low_eth_balance():
            return

        w3_sepolia = Web3(Web3.HTTPProvider("https://sepolia.drpc.org"))
        if not w3_sepolia.is_connected():
            raise Exception("Web3 not connected")

        f = open(os.path.dirname(__file__) + '/contract_abi.json', 'r', encoding='utf-8')
        full_abl_json = json.load(f)
        bridge_contract = w3_sepolia.eth.contract(abi=full_abl_json['bridge']['abi'],
                                                  address=Web3.to_checksum_address(
                                                      full_abl_json['bridge']['contractAddress']))
        amount = Web3.to_wei((random.randint(10, 15) / 10000), 'ether')

        tx_hash = self.__contract_call_legend(bridge_contract.functions.depositEth(),
                                              custom_w3=w3_sepolia,
                                              wait_tx=True, t_data={
                "value": amount
            })
        logger.info(f"{self.wallet_address} 跨链桥 {tx_hash.hex()}")

    def __do_faucet(self, token_name: str):
        yes_captcha = YesCaptcha(client_key=os.getenv("yescaptcha_clientkey"),
                                 website_url="https://miles.plumenetwork.xyz/faucet",
                                 website_key="0x4AAAAAAAViEapSHoQXHmzu",
                                 task_type="TurnstileTaskProxyless")
        captcha_result = yes_captcha.solve_captcha()

        faucet_info = requests.post("https://faucet.plumenetwork.xyz/api/faucet",
                                    json={"walletAddress": f"{self.wallet_address}", "token": token_name,
                                          "verified": captcha_result['token']},
                                    headers={
                                        "accept": "*/*",
                                        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                                        "content-type": "application/json",
                                        "priority": "u=1, i",
                                        "sec-fetch-dest": "empty",
                                        "sec-fetch-mode": "cors",
                                        "sec-fetch-site": "same-origin",
                                        "referrerPolicy": "strict-origin-when-cross-origin",
                                        "mode": "cors",
                                        "referrer": "https://faucet.plumenetwork.xyz/",
                                        **self.ua_info
                                    },
                                    proxies=self.qg_proxy.get_proxies()
                                    )
        faucet_json = faucet_info.json()
        if not faucet_json['walletAddress'] == self.wallet_address:
            logger.warning(f"{self.wallet_address} 领水 ${token_name} IP限制")

        tx_hash = self.__contract_call(self.faucet_contract.functions.getToken(token_name, faucet_json['salt'],
                                                                               faucet_json['signature']))
        logger.info(f"🎉 {self.wallet_address} 领水 🚰 ${token_name} 🔗 : {tx_hash.hex()}")


def daily_tx(plume: Plume):
    '''
    日常交互
    :param plume:
    :return:
    '''
    # if plume.version == 2:
    #     __do_tx_task_list([plume.eth_faucet, plume.goon_faucet, plume.invite_wallet], plume)
    #     return

    faucet_first = bool(random.getrandbits(1))
    faucet_tx = [plume.eth_faucet, plume.goon_faucet]
    daily_tx = [plume.game,
                plume.check_in,
                plume.swap_goon_to_gn_usd,
                plume.create_token,
                plume.mint_aick,
                plume.invite_wallet,
                plume.swap_usd_plus,
                plume.landshare,
                plume.vote,
                plume.perchy_safe_mint,
                plume.claim_reward]
    random.shuffle(faucet_tx)
    random.shuffle(daily_tx)
    try:
        plume.check_gas()
    except Exception as e:
        logger.warning(f"{plume.wallet_address} check gas error: {e}")
    if faucet_first:
        __do_tx_task_list(faucet_tx, plume)
        if not plume.low_eth_balance():
            __do_tx_task_list(daily_tx, plume)
        else:
            __do_tx_task_list([plume.check_in], plume)
    else:
        if not plume.low_eth_balance():
            __do_tx_task_list(daily_tx, plume)
        else:
            __do_tx_task_list([plume.check_in], plume)
        __do_tx_task_list(faucet_tx, plume)
    logger.info(f"🎉 {plume.wallet_address} {plume.version} 交互完成")


def try_sign(plume: Plume):
    try:
        plume.sign()
    except Exception as e:
        logger.warning(f"{plume.wallet_address} sign error: {e}")


def __do_tx_task_list(tx_task_list: List, plume: Plume):
    for func in tx_task_list:
        try:
            func()
        except Exception as e:
            logger.error(f"{plume.wallet_address} {func.__name__} 执行出错  {e}")
        if func.__name__ == 'swap_goon_to_gn_usd':
            time.sleep(random.randint(5, 10))
            __do_tx_task_list([plume.stake_gn_usd], plume)
        else:
            time.sleep(random.randint(5, 10))
