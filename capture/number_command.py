import time
import subprocess
from functools import lru_cache
from typing import List, Tuple, Union

# 以作者的测试平板分辨率为基准（1800x2880）
# 已在小米 13 测试（1080x2400）
BASE_RESOLUTION = (1800, 2880)

# 坐标点信息
BASE_COORDINATES = {
    "1": [[1480, 1050], [1440, 1470]],
    "2": [[1255, 1100], [1700, 1100], [1255, 1470], [1700, 1470]],
    "3": [[1344, 1040], [1600, 1200], [1270, 1323], [1635, 1379], [1249, 1588]],
    "4": [[1716, 1274], [1245, 1296], [1450, 1030], [1450, 1466]],
    "5": [[1558, 1020], [1290, 1211], [1600, 1348], [1300, 1472]],
    "6": [[1533, 1027], [1265, 1428], [1663, 1439]],
    ">": [[[1350, 1080], [1545, 1172], [1295, 1297]]],
    "<": [[[1578, 1058], [1308, 1231], [1560, 1292]]],
    "=": [[[1284, 1122], [1700, 1122], [1280, 1300], [1700, 1300]]],
    ".": [1350, 1080]  # 单独的点
}

NEXT_BUTTON_COORDINATES = {
    "next_1": [1400, 900], 
    "next_2": [2160, 1720], 
    "next_3": [1475, 1490], 
}

scale_x = 1
scale_y = 1

@lru_cache()
def get_device_resolution():
    # 获取设备的物理分辨率，并缓存
    result = subprocess.run(["adb", "shell", "wm", "size"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout
    if "Physical size" in output:
        resolution_str = output.split(":")[-1].strip()
        width, height = map(int, resolution_str.split("x"))
        return width, height
    else:
        raise Exception("无法获取设备分辨率")

def run_adb_command(commands):

    # 执行 ADB 命令，减少 subprocess 调用次数
    try:
        command_str = "\n".join(commands) + "\n"
        result = subprocess.run(["adb", "shell"], input=command_str, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            print(f"ADB 错误: {result.stderr}")
        return result.stdout
    except Exception as e:
        print(f"ADB 命令执行失败: {e}")
        return None
    
def get_tap_coordinates(command_str):
    current_resolution = get_device_resolution()
    scale_x = current_resolution[0] / BASE_RESOLUTION[0]
    scale_y = current_resolution[1] / BASE_RESOLUTION[1]

    xy_paths = str_to_xy(command_str, scale_x, scale_y)
    return xy_paths  # 返回坐标而不是发送命令

def prepare_tap_commands(command_str: str, times: int) -> List[str]:
    xy_paths = str_to_xy(command_str, *map(lambda x: get_device_resolution()[x] / BASE_RESOLUTION[x], (0, 1)))
    adb_commands = []

    if xy_paths:
        if isinstance(xy_paths[0], tuple):
            x, y = xy_paths[0]
            adb_commands.extend([f"input tap {x} {y}" for _ in range(times)])
        else:
            for path in xy_paths:
                x, y = path[0]  # 假设每个路径只有一个点
                adb_commands.extend([f"input tap {x} {y}" for _ in range(times)])
    return adb_commands

def tap_screen(command_str: str):
    adb_commands = prepare_tap_commands(command_str, 1)
    if adb_commands:
        run_adb_command(adb_commands)

def tap_screen_multiple(command_str: str, times: int):
    adb_commands = prepare_tap_commands(command_str, times)
    if adb_commands:
        run_adb_command(adb_commands)

def scale_coordinates(base_coordinates, scale_x, scale_y):
    # 根据设备分辨率缩放坐标
    if isinstance(base_coordinates[0], list):
        return [[(int(x * scale_x), int(y * scale_y)) for (x, y) in path] for path in base_coordinates]
    else:
        x, y = base_coordinates
        return [(int(x * scale_x), int(y * scale_y))]

def scale_coordinates_for_tap(coordinate, scale_x, scale_y):
    # 缩放一个点坐标
    return [int(coordinate[0] * scale_x), int(coordinate[1] * scale_y)]

def str_to_xy(command_str, scale_x, scale_y):
    # 将指令转换为坐标
    if command_str in BASE_COORDINATES:
        return scale_coordinates(BASE_COORDINATES[command_str], scale_x, scale_y)
    return None

def click_screen(xy):
    command = [f"input tap {xy[0]} {xy[1]}"]
    run_adb_command(command)

def next_round():
    click_screen(scale_coordinates_for_tap(NEXT_BUTTON_COORDINATES["next_1"], scale_x, scale_y))
    time.sleep(0.5)
    click_screen(scale_coordinates_for_tap(NEXT_BUTTON_COORDINATES["next_2"], scale_x, scale_y))
    time.sleep(0.5)
    click_screen(scale_coordinates_for_tap(NEXT_BUTTON_COORDINATES["next_3"], scale_x, scale_y))

# 未采用
def test_root():
    test_command = "id"
    full_command = f"su -c \"{test_command}\""
    result = subprocess.run(["adb", "shell", full_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"Root 权限成功: {result.stdout}")
    else:
        print(f"Root 权限失败: {result.stderr}")

if __name__ == "__main__":

    # 确保以 root 权限运行
    subprocess.run(["adb", "root"])  # 启动 adb root 权限
    subprocess.run(["adb", "wait-for-device"])  # 等待设备准备好
    # 执行点击操作
    tap_screen("<")
    tap_screen("=")

    test_root()
    # 执行滑动操作
