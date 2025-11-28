import socket
import random
import string

def decrypt(cypher):
    flag = 'THM{thisisafakeflag}'
    unhexed = bytes.fromhex(cypher)
    result = ''
    for i in range(4):
        result += chr(ord(flag[i]) ^ unhexed[i])
    return result

def decrypt_flag(cypher, key):
    unhexed = bytes.fromhex(cypher)
    result = ''
    for i in range(4):
        result += chr(ord(cypher[i]) ^ unhexed[i % len(unhexed)])
    return result

def start_client():
    HOST = '10.82.130.241'
    PORT = 1337 
    while True:

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                print(f"Подключение к {HOST}:{PORT} установлено")

                data = s.recv(4096).decode()
                _ = s.recv(4096)
                print(f"Получил {data}")
                hexed_data = data[data.index(":") + 2:]
                print(f"Расшифровываю ключ: {hexed_data}")
                possible_key = decrypt(hexed_data) + random.choices(string.ascii_letters + string.digits, k=1)[0]
                s.sendall(possible_key.encode())
                print(f"Отправил ключ: {possible_key}")

                data = s.recv(4096).decode()

                print(f"Ответ сервера: {data}")
                if "Congrats" in data:
                    print(data, possible_key, decrypt_flag(hexed_data, possible_key))
                    exit()

        except Exception as e:
            print(e)
            continue;

if __name__ == "__main__":
    start_client()
