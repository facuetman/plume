# plume

plume 交互脚本

## 使用方法

1. 安装Python3
2. 重命名 .env.example 为 .env
3. 修改.evn 中的参数

- 注册 [yescaptcha](https://yescaptcha.com/i/15gh60) 打码平台，修改`yescaptcha_clientkey`为你的client key
- 注册[青果网络](https://www.qg.net/)
  ,购买短效代理ip(领水必须要ip)
  ，还算便宜（如果你们有更便宜的，可以告诉我，反正我没有找到），购买国内ip或者国外ip都可以，plume可以大陆直连，大陆的是按次数收费，国外按照流量收费（国外ip不支持大陆网络，必须用国外vps，如果是自己电脑跑，不能用，有科学上网也不行），看自己需求，注意：`通道提取没试过，可能有问题`
  。
- 购买后填入Authkey和 Authpwd到.env,并且根据套餐配置qg_url，国内和国外url不一样

4. 其他参数自己按需改

```shell
pip install -r requirements.txt
python start_plume.py
```

## 支持任务（随机交互）

1. 领水
2. landshare
3. soildviolet
4. kuma
5. perch
6. stake on nest
7. plume arc
8. swap
9. 领取质押奖励
10. ecosystem vote 投票
11. culture竞猜