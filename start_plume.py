import fileinput
import os
import threading
from typing import List

from dotenv import load_dotenv
from loguru import logger

from plume import Plume, QgProxy, daily_tx

sem = threading.Semaphore(5)

load_dotenv()


def wrapper_thread(line: str, sem_target: threading.Semaphore, version: int = 1):
    plume = None
    with sem_target:
        try:
            spilt = str.split(line, ",")
            qg_proxy = QgProxy(auth_key=os.getenv("qg_auth_key"), password=os.getenv("qg_authpwd"))
            plume = Plume(wallet_address=spilt[0],
                          private_key=spilt[1],
                          qg_proxy=qg_proxy,
                          version=version)
            daily_tx(plume)
        except Exception as e:
            logger.error(f"{plume.wallet_address} 出错 {e}")


def read_address_line(files: List[str]) -> List[str]:
    result = []
    if len(files) != 0:
        for file in files:
            lines = fileinput.input(file)
            for line in lines:
                result.append(line.strip())
    return result


def plume_check():
    current_dir = os.path.dirname(__file__)
    lines = read_address_line([current_dir + "/wallet.txt"])
    for line in lines:
        spilt = str.split(line, ",")
        qg_proxy = QgProxy(auth_key=os.getenv("qg_auth_key"), password=os.getenv("qg_authpwd"))
        plume = Plume(wallet_address=spilt[0],
                      private_key=spilt[1],
                      qg_proxy=qg_proxy,
                      version=1)
        plume.check_in()


def start_plume():
    logger.info("------------------------开始执行------------------------")
    current_dir = os.path.dirname(__file__)
    lines = read_address_line([current_dir + "/wallet.txt"])
    while True:
        index = 0
        thread_list = []
        for line in lines:
            thread_list.append(threading.Thread(target=wrapper_thread, args=(line, sem, 1)))
        for t in thread_list:
            t.daemon = True  # 设置为守护线程，不会因主线程结束而中断
            t.start()
        for t in thread_list:
            t.join()  # 子线程全部加入，主线程等所有子线程运行完毕
            index += 1
            logger.info(f"-------------------------------完成进度 {index}/{len(lines)}-------------------------------")
        logger.info("完成一轮次")


if __name__ == '__main__':
    run_type = input(
        "选择:\n 1. plume日常交互 \n 2. plume签到检查 \n输入:")
    if run_type == "1":
        start_plume()
    elif run_type == "2":
        plume_check()
