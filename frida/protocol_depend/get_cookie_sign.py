import frida
import sys


# 获取目标应用的 PID
def _get_pid_from_adb(package_name):
    import subprocess
    try:
        # 使用 adb 获取进程列表，并查找目标应用的 PID
        result = subprocess.run(['adb', 'shell', 'ps | grep ' + package_name],
                                capture_output=True, text=True)
        output = result.stdout.strip()
        if output:
            # 从 adb 输出中提取 PID
            pid = int(output.split()[1])
            print(f"通过 adb 找到 PID: {pid}")
            return pid
        else:
            print("adb 没有找到该应用的 PID")
            return None
    except Exception as e:
        print(f"adb 获取 PID 时出错: {e}")
        return None


# 注入 Frida 脚本
def inject_script(s_pid):
    try:
        device = frida.get_usb_device()
        session = device.attach(s_pid)
        print(f"get_cookie_js Attached to PID: {s_pid}")

        with open("protocol_depend/js/get_cookie_sign.js", 'r', encoding='utf-8') as f:
            script_content = f.read()
            # print(f"Loaded script content: {script_content[:100]}...")  # 打印部分内容

        script = session.create_script(script_content)
        originalCookie = {}
        sign = None

        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                # url = payload['url']
                yfdu = payload['yfdU']
                originalCookie = payload['originalCookie']
                # userAgent = payload['userAgent']
                s_sign = payload['result']
                # print(f"URL: {url}")
                # print(f"YFD_U: {yfdU}")
                # print(f"Original Cookie: {originalCookie}")
                # print(f"User-Agent: {userAgent}")

                # 存储数据
                # data['url'] = url
                # data['yfdU'] = yfdU
                # data['originalCookie'] = originalCookie
                # data['userAgent'] = userAgent

                # 保存 originalCookie 到文件
                save_cookie_to_file(originalCookie)
                save_yfdu_to_file(yfdu)
                save_sign_to_file(s_sign)
            elif message['type'] == 'error':
                print(f"Error: {message['stack']}")

        script.on('message', on_message)
        script.load()

        # print(f"Script injected into PID {s_pid}")
        # sys.stdin.read()  # 保持脚本运行
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


if __name__ == "__main__":
    pid = _get_pid_from_adb("com.fenbi.android.leo")
    inject_script(pid)
