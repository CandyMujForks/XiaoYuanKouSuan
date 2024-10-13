import re

from mitmproxy import http
from mitmproxy.tools.main import mitmdump
import sys
import argparse


def response(flow: http.HTTPFlow) -> None:
    # 处理响应
    print(f"Response: {flow.response.status_code} {flow.request.url}")

    if "https://leo.fbcontent.cn/bh5/leo-web-oral-pk/exercise_" in flow.request.url:
        funname = re.search(r"(?<=isRight:)[^,]*?\(.*?\).*?(?=\|)", flow.response.text).group()
        flow.response.text = flow.response.text.replace(funname, funname + "||true")
        print("修改成功")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mitmproxy script")
    parser.add_argument("-P", "--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0", help="Host to listen on")
    args = parser.parse_args()

    sys.argv = ["mitmdump", "-s", __file__, "--listen-host", args.host, "--listen-port", str(args.port)]

    mitmdump()
