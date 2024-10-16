import os
import sys
import subprocess
import requests
import time
import json
import base64
import frida
from termcolor import colored
from protocol_depend.do_matchV2_byDataDecryptCommandl import FridaResponseDecrypt  # 用于解密试题
from protocol_depend.do_answer_encrypt_model import FridaRequestEncrypt  # 用于加密答案

def is_frida_running():
    """检查是否有 frida 相关进程正在运行"""
    try:
        result = subprocess.run(
            ['adb', 'shell', 'ps | grep frida'],
            capture_output=True, text=True
        )
        output = result.stdout.strip()
        return bool(output)  # 如果有输出，说明 frida 正在运行
    except Exception as e:
        print(f"检查 Frida 运行状态时出错: {e}")
        return False


def kill_frida_processes():
    """查找并杀掉所有 frida 相关的进程"""
    try:
        result = subprocess.run(
            ['adb', 'shell', 'ps | grep frida'],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        if output:
            lines = output.splitlines()
            for line in lines:
                pid = line.split()[1]
                kill_command = f'adb shell "su -c \'kill -9 {pid}\'"'
                subprocess.run(kill_command, shell=True, check=True, timeout=5)
                print(f"Frida 进程 {pid} 已被杀掉")
            print("所有 Frida 相关进程已杀掉。")
        else:
            print("没有找到任何 Frida 相关的进程。")
    except subprocess.TimeoutExpired:
        print("杀掉 Frida 进程时超时")
    except Exception as e:
        print(f"杀掉 Frida 进程时出错: {e}")


def start_frida_server():
    """检查并启动 frida-server"""
    if is_frida_running():
        print("检测到 frida 相关进程，正在杀掉...")
        kill_frida_processes()
    try:
        print("正在后台启动 Frida-server...")
        # 使用 Popen 在后台启动 frida-server
        start_frida_command = 'adb shell "su -c \'./data/local/tmp/frida-server-16.5.5-android-x86_64 &\'"'
        process = subprocess.Popen(start_frida_command, shell=True)
        print("Frida-server 已在后台启动！")
    except Exception as e:
        print(f"启动 Frida-server 时出错: {e}")

def get_pk_topic():
    """
    获取及解密试题部分
    """
    p_cookie = get_cookie_now()
    sign = get_sign_now()
    yfdu = get_yfdu_now()
    # 使用`gan_sign`生成`sign`值, 向`https://xyks.yuanfudao.com/leo-game-pk/android/math/pk/match/v2?
    # pointId=2&_productId=611&platform=android32&version=3.93.2&vendor=xiao_mi&av=5&sign=0e40a461631880b0937515fd93fe87b6&deviceCategory=pad`发起post请求
    match_v2_url = ("https://xyks.yuanfudao.com/leo-game-pk/android/math/pk/match/v2?"
                    "pointId=69&_productId=611&platform=android32&version=3.93.3&vendor=baidu&av=5&"
                    "sign={}&deviceCategory=phone").format(sign)
    match_v2_head = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate",
        "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-length": "0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://xyks.yuanfudao.com",
        "pragma": "no-cache",
        "referer": "https://xyks.yuanfudao.com/bh5/leo-web-oral-pk/exercise.html?"
                   "pointId=69&isFromInvite=undefined&_productId=611&vendor=baidu&phaseId=3&from=yuansoutikousuan&"
                   f"YFD_U={yfdu}&version=3.93.3&siwr=false&keypath=",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Linux; Android 12; SDY-AN00 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, "
                      "like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 YuanSouTiKouSuan/3.93.3",
        "x-requested-with": "com.fenbi.android.leo",
        "cookie": f"{p_cookie}"
    }

    # print("请求头:", match_v2_head)
    # requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # 发起post请求
    match_v2_response = requests.post(match_v2_url, headers=match_v2_head, verify=True)
    # 输出返回结果长度, 应注意这是二进制乱码, 长度仅供参考有无获取成功, pk试题一般在400-500左右
    print("获取到试题未解密大概长度", len(match_v2_response.text))
    # 确认响应的二进制内容 (gpt的迷惑行为)
    binary_content = match_v2_response.content  # 这是二进制数据
    # 将二进制数据进行 Base64 编码
    encoded_content = base64.b64encode(binary_content).decode('utf-8')

    """
    解密试题部分
    """
    decrypt = FridaResponseDecrypt("com.fenbi.android.leo",
                                   "protocol_depend/js/do_matchV2_byDataDecryptCommand.js",
                                   None)  # 第3个是小袁口算的pid; 如果知道的话就传pid, 能免去adb查找, 提高效率; 不知道就传None
    decrypt.start()
    match_question = decrypt.getstr(encoded_content)
    print("解密试题: ", match_question)

    """
    生成答案数据包部分， 这里适配pk答题
    1. 把试题包examVO下的所有内容抄一遍, 变成根
    2. 把correctCnt改成试题数量
       把costTime改成答题用时
       把updatedTime改成当前时间戳
    3. 把questions列表下的:
         每个status改成1
         每个userAnswer改成answer列表的第0个
         每个script用户答题痕迹改成"", 不生成用户答题痕迹
         不要给没加引号的null加上引号, hook调用里会加上引号 // 坑, 未来优化调用要注意
         加上这样的json:
            "curTrueAnswer": {
                "recognizeResult": ">",
                "pathPoints": [],
                "answer": 1,
                "showReductionFraction": 0
            }
    """
    match_question_json = json.loads(match_question)
    answer_json = match_question_json["examVO"]
    answer_json["correctCnt"] = answer_json["questionCnt"]
    answer_json["costTime"] = 100
    answer_json["updatedTime"] = int(time.time() * 1000)
    for question in answer_json["questions"]:
        question["status"] = 1
        question["userAnswer"] = question["answer"][0]
        question["script"] = ""
        question["curTrueAnswer"] = {
            "recognizeResult": question["answer"][0],
            "pathPoints": [],
            "answer": 1,
            "showReductionFraction": 0
        }
    # print(answer_json)
    answer_data = json.dumps(answer_json, ensure_ascii=False)  # 生成答案数据包
    print(colored("生成答案: ", 'red') + answer_data)

    """
    提交答案部分
    答案gzip压缩一下, 传给服务器
    目标url = https://xyks.yuanfudao.com/leo-game-pk/android/math/pk/submit?_productId=611&platform=android32&version=3.93.2&vendor=xiao_mi&av=5&sign=2147537776d49902270b5a6b27686beb&deviceCategory=pad
    """
    answer_data_base64 = base64.b64encode(answer_data.encode('utf-8')).decode('utf-8')
    request_encrypt = FridaRequestEncrypt("com.fenbi.android.leo", "protocol_depend/js/do_answer_encrypt_model.js",
                                          None)
    request_encrypt.start()
    answer_encrypt_base64 = request_encrypt.get_request_encrypt(answer_data_base64)

    upAnswer_url = (
        "https://xyks.yuanfudao.com/leo-game-pk/android/math/pk/submit?_productId=611&platform=android32&version=3.93.3&vendor=baidu&av=5&sign={}&deviceCategory=phone").format(
        sign)
    upAnswer_head = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate",
        "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "no-cache",
        "content-type": "application/octet-stream",
        "origin": "https://xyks.yuanfudao.com",
        "referer": "https://xyks.yuanfudao.com/bh5/leo-web-oral-pk/result.html?",
        "user-agent": "Mozilla/5.0 (Linux; Android 12; SDY-AN00 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 YuanSouTiKouSuan/3.93.3",
        "x-requested-with": "com.fenbi.android.leo",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "cookie": f"{p_cookie}"
    }
    upanswer_response = requests.put(url=upAnswer_url, headers=upAnswer_head,
                                     data=base64.b64decode(answer_encrypt_base64),
                                     verify=True)
    # 不是{"timestamp":1728884050091,"status":400,"message":"error"}就是成功了
    print(colored("提交结果： ",
                  'green') + str(upanswer_response.status_code))


def inject_script(s_pid, num_pk):
    try:
        device = frida.get_usb_device()
        session = device.attach(s_pid)
        print(f"get_cookie_js Attached to PID: {s_pid}")

        with open("protocol_depend/js/get_cookie_sign.js", 'r', encoding='utf-8') as f:
            script_content = f.read()

        script = session.create_script(script_content)

        # 初始化变量，确保只有在所有值都获取到时才执行后续操作
        originalCookie = None
        s_sign = None
        yfdu = None

        def check_and_execute(num_pk):
            # 检查 originalCookie, s_sign, yfdu 是否都获取到
            if originalCookie and s_sign and yfdu:
                print("All values obtained, executing get_pk_topic()")
                # get_pk_topic()
                for i in range(num_pk):
                    get_pk_topic()
                    # time.sleep(1)

        def on_message(message, data):
            nonlocal originalCookie, s_sign, yfdu

            if message['type'] == 'send':
                payload = message['payload']

                # 获取并保存 originalCookie、s_sign、yfdu
                originalCookie = payload.get('originalCookie')
                s_sign = payload.get('result')
                yfdu = payload.get('yfdU')

                # 定义目录路径
                directory_path = 'protocol_depend/protocol_information/'

                # 检查目录是否存在
                if not os.path.exists(directory_path):
                    # 如果目录不存在，则创建该目录
                    os.makedirs(directory_path)
                    print(f"目录 '{directory_path}' 已创建")
                else:
                    print(f"目录 '{directory_path}' 已存在")

                # 保存数据到文件
                if originalCookie:
                    save_cookie_to_file(originalCookie)
                if s_sign:
                    save_sign_to_file(s_sign)
                if yfdu:
                    save_yfdu_to_file(yfdu)

                # 检查是否所有值都获取到
                check_and_execute(num_pk)

            elif message['type'] == 'error':
                print(f"Error: {message['stack']}")

        script.on('message', on_message)
        script.load()

    except Exception as e:
        print(f"Error injecting script: {e}")
        sys.exit(1)

    return originalCookie


def save_sign_to_file(s_sign):
    try:
        with open('protocol_depend/protocol_information/xiaoyuan_sign.txt', 'w', encoding='utf-8') as file:
            file.write(s_sign)
        print("Original sign 已保存到 xiaoyuan_sign.txt")
    except Exception as e:
        print(f"保存 sign 时出错: {e}")


# 将 Cookie 保存到文件
def save_cookie_to_file(cookie):
    try:
        with open('protocol_depend/protocol_information/xiaoyuan_cookie.txt', 'w', encoding='utf-8') as file:
            file.write(cookie)
        print("Original Cookie 已保存到 xiaoyuan_cookie.txt")
    except Exception as e:
        print(f"保存 Cookie 时出错: {e}")


def save_yfdu_to_file(yfdu):
    try:
        with open('protocol_depend/protocol_information/xiaoyuan_yfdU.txt', 'w', encoding='utf-8') as file:
            file.write(yfdu)
        print("Original yfdu 已保存到 xiaoyuan_yfdu.txt")
    except Exception as e:
        print(f"保存 yfdu 时出错: {e}")


def get_pid_from_adb(package_name):
    try:
        result = subprocess.run(['adb', 'shell', 'ps | grep ' + package_name],
                                capture_output=True, text=True)
        output = result.stdout.strip()
        if output:
            g_pid = int(output.split()[1])
            print(f"通过 adb 找到 PID: {g_pid}")
            return g_pid
        else:
            print("adb 没有找到该应用的 PID")
            return None
    except Exception as e:
        print(f"adb 获取 PID 时出错: {e}")
        return None


def start_app(package_name, activity_name):
    """通过 adb 命令启动指定应用"""
    try:
        # 使用 adb 命令启动应用
        adb_command = f'adb shell am start -n {package_name}/{activity_name}'
        subprocess.run(adb_command, shell=True, check=True)
        print(f"应用 {package_name} 成功启动！")
    except subprocess.CalledProcessError as e:
        print(f"启动应用时出错: {e}")


def get_cookie_now():
    with open("protocol_depend/protocol_information/xiaoyuan_cookie.txt", 'r', encoding='utf-8') as f:
        cookie = f.read()
    # print(cookie)
    return cookie


def get_sign_now():
    with open("protocol_depend/protocol_information/xiaoyuan_sign.txt", 'r', encoding='utf-8') as f:
        sign = f.read()
    # print(sign)
    return sign


def get_yfdu_now():
    with open("protocol_depend/protocol_information/xiaoyuan_yfdu.txt", 'r', encoding='utf-8') as f:
        yfdu = f.read()
    # print(yfdu)
    return yfdu


def adb_connect_device():
    """重连到设备"""
    try:
        adb_command = "adb connect 127.0.0.1:16384"
        subprocess.run(adb_command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"ADB 命令执行失败: {e}. 连接设备失败...")


if __name__ == "__main__":
    # 设置PK次数
    num = 10
    adb_flag = adb_connect_device()
    if adb_flag:
        start_frida_server()
        pid = get_pid_from_adb("com.fenbi.android.leo")
        if pid is None:
            start_app("com.fenbi.android.leo", ".activity.RouterActivity")
            print("小猿口算启动！")
            time.sleep(3)
            new_pid = get_pid_from_adb("com.fenbi.android.leo")
            inject_script(new_pid, num)
            # get_pk_topic()
            # 保持脚本运行
            sys.stdin.read()
        else:
            inject_script(pid, num)
            # get_pk_topic()
            # 保持脚本运行
            sys.stdin.read()
