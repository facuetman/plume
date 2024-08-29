import time

from curl_cffi import requests
from loguru import logger


class YesCaptchaException(Exception):
    pass


class YesCaptcha:
    def __init__(self, client_key, website_key, website_url, task_type, proxy: str = None):
        self.client_key = client_key
        self.website_key = website_key
        self.website_url = website_url
        self.task_type = task_type
        self.task_id = None
        self.proxy = proxy

    def create_task(self):
        url = "https://api.yescaptcha.com/createTask"
        data = {
            "clientKey": self.client_key,
            "task": {
                "websiteURL": self.website_url,
                "websiteKey": self.website_key,
                "type": self.task_type,
            },
            "softID": 48051
        }
        if self.task_type == "TurnstileTaskS2":
            data['task']['proxy'] = self.proxy

        try:
            # 发送JSON格式的数据
            result = requests.post(url, json=data, verify=False).json()
            task_id = result.get('taskId')
            if task_id is not None:
                self.task_id = task_id
            logger.info(f"获取到任务创建结果：{result}")
        except Exception as e:
            logger.exception(f"创建验证码识别任务失败 {self.website_url}", e)

    def get_task_result(self):
        if self.task_id is None:
            raise Exception("创建验证码识别任务失败")
        times = 0
        while times < 120:
            try:
                url = f"https://api.yescaptcha.com/getTaskResult"
                data = {
                    "clientKey": self.client_key,
                    "taskId": self.task_id
                }
                result = requests.post(url, json=data, verify=False).json()
                if result.get('errorId') > 0:
                    raise YesCaptchaException(f"验证码处理失败 {result.get('errorId')} : {result.get('errorCode')}")
                solution = result.get('solution', {})
                if solution:
                    logger.info(f"获取 验证结果 {solution}")
                    return solution
                logger.info(f"获取 任务结果 {result}")
            except YesCaptchaException as e:
                raise e
            except Exception as e:
                logger.exception("获取验证码失败", e)
            times += 3
            time.sleep(3)

    def solve_captcha(self) -> dict:
        self.create_task()
        return self.get_task_result()
