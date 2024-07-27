import hashlib
import hmac
import json
import logging
import os
import time
from urllib import parse

import requests

# 消息推送部分 如有需求请自定义
def push_sendNotice(title, message):
  return

skyland_token = "请自行获取于 https://web-api.skland.com/account/info/hg" # 森空岛token

grant_code_url = "https://as.hypergryph.com/user/oauth2/v2/grant" # 使用token获得认证代码
cred_code_url = "https://zonai.skland.com/api/v1/user/auth/generate_cred_by_code" # 使用认证代码获得cred
binding_url = "https://zonai.skland.com/api/v1/game/player/binding" # 绑定的角色url
sign_url = "https://zonai.skland.com/api/v1/game/attendance" # 签到url
checkin_url = "https://zonai.skland.com/api/v1/score/checkin" # 登岛检票url

app_code = '4ca99fa6b56cc2ba'

account_num = 1

header = {
    'cred': '',
    'User-Agent': 'Skland/1.5.1 (com.hypergryph.skland; build:100501001; Android 34; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}

header_login = {
    'User-Agent': 'Skland/1.5.1 (com.hypergryph.skland; build:100501001; Android 34; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}

# 签名请求头一定要这个顺序，否则失败
# timestamp是必填的,其它三个随便填,不要为none即可
header_for_sign = {
    'platform': '1',
    'timestamp': '',
    'dId': '',
    'vName': '1.5.1'
}


sign_token = '' # 参数验证的token
run_message = '' # 消息内容



def generate_signature(token: str, path, body_or_query):
    """
    获得签名头
    接口地址+方法为Get请求？用query否则用body+时间戳+ 请求头的四个重要参数（dId，platform，timestamp，vName）.toJSON()
    将此字符串做HMAC加密，算法为SHA-256，密钥token为请求cred接口会返回的一个token值
    再将加密后的字符串做MD5即得到sign
    :param token: 拿cred时候的token
    :param path: 请求路径（不包括网址）
    :param body_or_query: 如果是GET，则是它的query。POST则为它的body
    :return: 计算完毕的sign
    """
    # 总是说请勿修改设备时间，怕不是yj你的服务器有问题吧，所以这里特地-2
    t = str(int(time.time()) - 2)
    token = token.encode('utf-8')
    header_ca = json.loads(json.dumps(header_for_sign))
    header_ca['timestamp'] = t
    header_ca_str = json.dumps(header_ca, separators=(',', ':'))
    s = path + body_or_query + t + header_ca_str
    hex_s = hmac.new(token, s.encode('utf-8'), hashlib.sha256).hexdigest()
    md5 = hashlib.md5(hex_s.encode('utf-8')).hexdigest().encode('utf-8').decode('utf-8')
    logging.info(f'算出签名: {md5}')
    return md5, header_ca


def get_sign_header(url: str, method, body, old_header): # 获取签名后的header
    h = json.loads(json.dumps(old_header))
    p = parse.urlparse(url)
    if method.lower() == 'get':
        h['sign'], header_ca = generate_signature(sign_token, p.path, p.query)
    else:
        h['sign'], header_ca = generate_signature(sign_token, p.path, json.dumps(body))
    for i in header_ca:
        h[i] = header_ca[i]
    return h


def copy_header(cred): # 深拷贝header
    """
    组装请求头
    :param cred: cred
    :return: 拼装后的请求头
    """
    v = json.loads(json.dumps(header))
    v['cred'] = cred
    return v


def login_by_token(token_code): # 通过token获得cred
    try:
        t = json.loads(token_code)
        token_code = t['data']['content']
    except:
        pass
    grant_code = get_grant_code(token_code)
    return get_cred(grant_code)


def get_cred(grant): # 获得cred
    rsp = requests.post(cred_code_url, json={
        'code': grant,
        'kind': 1
    }, headers=header_login).json()
    if rsp['code'] != 0:
        raise Exception(f'获得cred失败：{rsp["messgae"]}')
    global sign_token
    sign_token = rsp['data']['token']
    return rsp['data']['cred']


def get_grant_code(token): # 获得认证代码
    rsp = requests.post(grant_code_url, json={
        'appCode': app_code,
        'token': token,
        'type': 0
    }, headers=header_login).json()
    if rsp['status'] != 0:
        raise Exception(f'使用token: {token} 获得认证代码失败：{rsp["msg"]}')
    return rsp['data']['code']


def get_binding_list(cred): # 获取绑定的角色
    global run_message
    message: str
    v = []
    rsp = requests.get(binding_url, headers=get_sign_header(binding_url, 'get', None, copy_header(cred))).json()
    if rsp['code'] != 0:
        message = f"请求角色列表出现问题：{rsp['message']}"
        run_message += message + '\n'
        logging.error(message)
        if rsp.get('message') == '用户未登录':
            message = f'用户登录可能失效了，请重新登录！'
            run_message += message + '\n'
            logging.error(message)
            return v
    for i in rsp['data']['list']:
        if i.get('appCode') != 'arknights':
            continue
        v.extend(i.get('bindingList'))
    return v


def do_sign(cred): # 进行签到
    global run_message
    characters = get_binding_list(cred)
    global account_num
    for i in characters:
        body = {
            'uid': i.get('uid'),
            'gameId': i.get("channelMasterId")
        }
        rsp = requests.post(sign_url, headers=get_sign_header(sign_url, 'post', body, copy_header(cred)), json=body).json()
        print(rsp)
        
        if rsp['code'] != 0:
            fail_message = f'{i.get("nickName")}（{i.get("channelName")}）\n签到失败：{rsp.get("message")}\n'
            run_message += f'{fail_message}'
            print(fail_message)
            account_num += 1
            continue
        awards = rsp['data']['awards']
        for j in awards:
            res = j['resource']
            success_message = f'{i.get("nickName")}（{i.get("channelName")}）\n签到成功：{res["name"]}x{j.get("count") or 1}\n'
            run_message += f'{success_message}'
            account_num += 1
            print(success_message)

sklandBoard = {
  1: '明日方舟',
  2: '来自星辰',
  3: '明日方舟: 终末地',
  4: '泡姆泡姆',
  100: '纳斯特港',
  101: '开拓芯',
}

def do_checkin(cred): # 进行登岛检票
    global run_message
    for i in sklandBoard:
        time.sleep(2)
        body = {
            'gameId': str(i),
        }
        rsp = requests.post(checkin_url, headers=get_sign_header(checkin_url, 'post', body, copy_header(cred)), json=body).json()
        print(rsp)
        
        if rsp['code'] == 0:
            run_message += f'\n{sklandBoard[i]} 检票成功：{rsp.get("message")}'
        else:
            run_message += f'\n{sklandBoard[i]} 检票失败：{rsp.get("message")}'
            
def start(token):
    global run_message
    try:
        cred = login_by_token(token)
        time.sleep(1)
        do_sign(cred)
        time.sleep(1)
        do_checkin(cred)
    except Exception as ex:
        run_message += f'\n\n 签到完全失败了: {ex}'
        logging.error('签到完全失败了！: ', exc_info=ex)


def main():
    global run_message
    start(skyland_token)
    
    # 发送消息
    push_sendNotice('明日方舟签到', run_message)


if __name__ == "__main__":
    main()
