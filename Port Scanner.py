
import psutil
import socket
import sys
import time


def print_animated_banner():
    banner = r"""
          _____                    _____                    _____                    _____                    _____          
         /\    \                  /\    \                  /\    \                  /\    \                  /\    \         
        /::\    \                /::\    \                /::\    \                /::\____\                /::\    \        
       /::::\    \              /::::\    \              /::::\    \              /:::/    /               /::::\    \       
      /::::::\    \            /::::::\    \            /::::::\    \            /:::/    /               /::::::\    \      
     /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/    /               /:::/\:::\    \     
    /:::/__\:::\    \        /:::/__\:::\    \        /:::/  \:::\    \        /:::/    /               /:::/__\:::\    \    
   /::::\   \:::\    \      /::::\   \:::\    \      /:::/    \:::\    \      /:::/    /                \:::\   \:::\    \   
  /::::::\   \:::\    \    /::::::\   \:::\    \    /:::/    / \:::\    \    /:::/    /      _____    ___\:::\   \:::\    \  
 /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\  /:::/    /   \:::\ ___\  /:::/____/      /\    \  /\   \:::\   \:::\    \ 
/:::/  \:::\   \:::\____\/:::/  \:::\   \:::|    |/:::/____/  ___\:::|    ||:::|    /      /::\____\/::\   \:::\   \:::\____\
\::/    \:::\  /:::/    /\::/   |::::\  /:::|____|\:::\    \ /\  /:::|____||:::|____\     /:::/    /\:::\   \:::\   \::/    /
 \/____/ \:::\/:::/    /  \/____|:::::\/:::/    /  \:::\    /::\ \::/    /  \:::\    \   /:::/    /  \:::\   \:::\   \/____/ 
          \::::::/    /         |:::::::::/    /    \:::\   \:::\ \/____/    \:::\    \ /:::/    /    \:::\   \:::\    \     
           \::::/    /          |::|\::::/    /      \:::\   \:::\____\       \:::\    /:::/    /      \:::\   \:::\____\    
           /:::/    /           |::| \::/____/        \:::\  /:::/    /        \:::\__/:::/    /        \:::\  /:::/    /    
          /:::/    /            |::|  ~|               \:::\/:::/    /          \::::::::/    /          \:::\/:::/    /     
         /:::/    /             |::|   |                \::::::/    /            \::::::/    /            \::::::/    /      
        /:::/    /              \::|   |                 \::::/    /              \::::/    /              \::::/    /       
        \::/    /                \:|   |                  \::/____/                \::/____/                \::/    /        
         \/____/                  \|___|                                            ~~                       \/____/     
"""
    green_color = "\033[92m"
    reset_color = "\033[0m"
    for line in banner.splitlines():
        print(green_color + line + reset_color)
        time.sleep(0.05)

print_animated_banner()

def fmt_addr(addr):
    if not addr:
        return "None"
    try:
        ip, port = addr[:2]
        return f"{ip}:{port}"
    except Exception:
        return str(addr)

def get_proc_name(pid):
    if not pid:
        return "None"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "None"

def port_scan():
    socket_types = {
        socket.SOCK_STREAM: "TCP",
        socket.SOCK_DGRAM: "UDP",
        socket.SOCK_RAW: "RAW",
        socket.SOCK_SEQPACKET: "SEQPACKET",
        socket.SOCK_RDM: "RDM"
    }

    print()
    print(f"{'Proto':15} {'Local':50} {'Remote':30} {'State':20} {'PID':7} {'Process'}")
    print("-" * 160)

    try:
        conns = psutil.net_connections(kind='all')
    except Exception as e:
        print("Не удалось получить соединения (возможно, нужны права администратора).")
        print("Ошибка:", e)
        return

    def sort_key(c):
        try:
            l = c.laddr
            ip = l.ip if hasattr(l, "ip") else (l[0] if l else "")
            port = l.port if hasattr(l, "port") else (l[1] if l else 0)
            return (str(c.type), str(ip), int(port) if port else 0)
        except Exception:
            return (str(c.type), "", 0)

    for c in sorted(conns, key=sort_key):
        proto = socket_types.get(c.type, str(c.type))
        laddr = fmt_addr(c.laddr)
        raddr = fmt_addr(c.raddr) if c.raddr else "None"
        state = c.status or "None"
        pid = c.pid or "None"
        pname = get_proc_name(pid)
        print(f"{proto:15} {laddr:50} {raddr:30} {state:20} {str(pid):7} {pname}")

    print("-" * 160)
    print(f"Всего соединений: {len(conns)}")
    print()

def main_menu():
    while True:
        print("Этот софт предназначен для работы с портами.")
        print("1 - Выйти")
        print("2 - Сканировать порты (показать все соединения)")
        choice = input("Выберите пункт: ").strip()

        if choice == "1":
            print("Выход...")
            time.sleep(0.3)
            sys.exit(0)
        elif choice == "2":
            try:
                port_scan()
            except KeyboardInterrupt:
                print("\nОперация прервана пользователем.")
        else:
            print("Неверный ввод, попробуйте 1 или 2.")
        time.sleep(0.2)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nПрограмма завершена (Ctrl+C).")
