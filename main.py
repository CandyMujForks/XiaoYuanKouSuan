import argparse
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from functools import lru_cache
from tkinter import messagebox

from mitmproxy import http
from mitmproxy.tools.main import mitmdump

# CONFIG
is_game_ended = True
WAITING_TIME = 12
BASE_RESOLUTION = [1440, 2880]
NEXT_BUTTON_COORDINATES = {
    # 进行下一场所要点击的按钮位置
    "next_1": [720, 2060],
    "next_2": [1050, 2760],
    "next_3": [950, 2420],
}


def response(flow: http.HTTPFlow) -> None:
    global is_game_ended
    url = flow.request.url
    print(f"Response: {flow.response.status_code} {url}")

    if "https://leo.fbcontent.cn/bh5/leo-web-oral-pk/exercise_" in url:
        # 找到需要替换的js
        responsetext = flow.response.text
        print(f"匹配到指定的 URL: {url}")
        funname = re.search(r"(?<=isRight:)[^,]*?\(.*?\).*?(?=\|)", responsetext).group()
        flow.response.text = responsetext.replace(funname, f"{funname}||true")
        threading.Thread(target=show_message_box, args=("过滤成功", f"函数 {funname} 替换成功!")).start()

    elif "https://xyks.yuanfudao.com/leo-game-pk/android/math/pk/match/v2?" in url:
        # 检测到匹配成功
        is_game_ended = False
        threading.Timer(interval=WAITING_TIME, function=answer_input).start()

    elif "https://xyks.yuanfudao.com/bh5/leo-web-oral-pk/result" in url:
        # 结束对战
        is_game_ended = True

    if "https://xyks.yuanfudao.com/leo-star/android/exercise/rank/list" in url:
        # 进入结算界面，并自动进行下一局
        threading.Timer(interval=5, function=next_round).start()


def show_message_box(title, message):
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(title, message)
    root.destroy()


def answer_input():
    global is_game_ended
    current_resolution = get_device_resolution()
    # adb点击作答
    while True:
        if not is_game_ended:
            adb_command = f"input tap {current_resolution[0] * 0.5} {current_resolution[1] * 0.7} \n" * 15
            subprocess.run(["adb", "shell"], input=adb_command, text=True)
        else:
            return


def next_round():
    next_commands = [f"input tap {NEXT_BUTTON_COORDINATES['next_1'][0]} {NEXT_BUTTON_COORDINATES['next_1'][1]}",
                     f"input tap {NEXT_BUTTON_COORDINATES['next_2'][0]} {NEXT_BUTTON_COORDINATES['next_2'][1]}",
                     f"input tap {NEXT_BUTTON_COORDINATES['next_3'][0]} {NEXT_BUTTON_COORDINATES['next_3'][1]}"]

    for i in range(next_commands.__len__()):
        subprocess.run(["adb", "shell"], input=next_commands[i], text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        time.sleep(1)


# 检查 adb 是否安装
def check_adb_installed():
    try:
        result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            show_message_box("提示", "ADB 连接检查失败")
            sys.exit(1)
    except FileNotFoundError:
        show_message_box("提示", "ADB 未找到，请先安装 ADB 工具。")
        sys.exit(1)


# ADB 无线调试连接设备
def connect_adb_wireless(adb_ip):
    try:
        result = subprocess.run(["adb", "connect", adb_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "connected" not in result.stdout:
            show_message_box("提示", f"ADB 连接失败: {result.stderr}")
            sys.exit(1)
        # show_message_box("提示", f"已连接到 {adb_ip}")
        print(f"ADB 已连接到 {adb_ip}")
    except subprocess.CalledProcessError as e:
        show_message_box("提示", f"ADB 连接错误: {e}")
        sys.exit(1)


# 检查 adb 是否已正常连接
def check_adb_connected():
    result = subprocess.run(["adb", "get-state"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        show_message_box("提示", f"ADB 连接错误\n{result.stderr}")
        sys.exit(1)
    else:
        print("ADB 已成功连接！")


@lru_cache
def get_device_resolution():
    # 获取设备的物理分辨率，并缓存
    result = subprocess.run(["adb", "shell", "wm", "size"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout
    if "Physical size" in output:
        resolution_str = output.split(":")[-1].strip()
        width, height = map(int, resolution_str.split("x"))
        print(f"设备分辨率为: {width}x{height}")
        return width, height
    else:
        raise Exception("无法获取设备分辨率")


if __name__ == "__main__":
    check_adb_installed()

    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Mitmproxy script")
    parser.add_argument("-P", "--port", type=int, default=9000, help="Port to listen on")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0", help="Host to listen on")
    parser.add_argument("-AI", "--adb-ip", type=str,
                        help="IP and port for ADB wireless connection (e.g., 192.168.0.101:5555)")

    args = parser.parse_args()

    if args.adb_ip:
        connect_adb_wireless(args.adb_ip)

    check_adb_connected()

    # 运行mitmdump
    sys.argv = ["mitmdump", "-s", __file__, "--listen-host", args.host, "--listen-port", str(args.port)]

    mitmdump()
