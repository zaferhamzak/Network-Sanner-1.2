import asyncio
import concurrent.futures
import subprocess
import os
import ipaddress
import platform
from scapy.all import ARP, Ether, srp
import socket
# Kütüphane adlarını ve komutları belirleyin
kutuphaneler = ["os", "ipaddress", "platform", "scapy"]

for kutuphane in kutuphaneler:
    komut = f"pip install {kutuphane}"

    try:
        # Komutu çalıştırın
        subprocess.check_call(komut, shell=True)
        print(f"\033[92m{kutuphane} başarıyla indirildi.\033[0m")  # Yeşil renkte çıktı
    except subprocess.CalledProcessError:
        print(f"\033[91m{kutuphane} indirme işlemi sırasında bir hata oluştu.\033[0m")  # Kırmızı renkte hata çıktısı

# Ekranı temizle
os.system("cls" if platform.system() == "Windows" else "clear")

# Log dosyasını aç
log_file = open("network_tool_log.txt", "a", encoding="utf-8")

def log(message):
    # Mesajı hem konsola hem de log dosyasına yaz
    print("\033[92m" + message + "\033[0m")  # Yeşil renkte çıktı
    log_file.write(message + "\n")

log("""
    ██████╗ ███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝
    ██║  ██║█████╗  ███████║███████║██║     █████╔╝ 
    ██║  ██║██╔══╝  ██╔══██║██╔══██║██║     ██╔═██╗ 
    ██████╔╝███████╗██║  ██║██║  ██║╚██████╗██║  ██╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
              DeHack Network Scan Tool                                    
""")

def vulnerability_scan(ip_address):
    vulnerabilities = 0

    # Zafiyet taraması yapılacak portları belirtin
    target_ports = [21, 22, 80, 443, 3389]  # Örnek olarak FTP, SSH, HTTP, HTTPS, RDP portları

    for port in target_ports:
        # Socket oluştur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Zaman aşımını belirt

        # Portu kontrol et
        result = sock.connect_ex((ip_address, port))

        # Bağlantı başarılıysa, port açıktır
        if result == 0:
            print()
        else:
            vulnerabilities += 1


        # Soketi kapat
        sock.close()

    return vulnerabilities
def log_to_console(message):
    # Mesajı sadece konsola yaz
    print("\033[92m" + message + "\033[0m")  # Yeşil renkte çıktı

def get_devices(ip_range):
    try:
        # ARP isteği oluştur
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # ARP isteğini gönder ve yanıtları al
        result = srp(packet, timeout=3, verbose=False)[0]

        # IP adresi ve MAC adresi bilgilerini çıkart
        devices = []
        for sent, received in result:
            ip_address = received.psrc
            mac_address = received.hwsrc
            firewall_status = check_firewall_status(ip_address)
            vulnerabilities_count = vulnerability_scan(ip_address)
            devices.append({'ip': ip_address, 'mac': mac_address, 'firewall': firewall_status,
                            'vulnerabilities': vulnerabilities_count})

        # Başlık satırını yazdır
        log_to_console(" Numara    IP Address          MAC Address\t    Firewall    Zafiyet Sayısı")
        log_to_console("--------------------------------------------------------------------------------")

        # Cihazları numaralandırarak listeleyin ve formatlayın
        for i, device in enumerate(devices, start=1):
            selected_ip = device['ip']
            device_info = f"{i}\t - {device['ip'].ljust(20)}{device['mac']}\t{device['firewall']}\t    {device['vulnerabilities']}"
            log_to_console(device_info)

        return devices

    except Exception as e:
        error_message = f"Hata: {e}"
        log_to_console(error_message)
        return None


def nmap_auto(target_host):
    try:
        # Otomatik Nmap komutunu çalıştır
        nmap_command = f"nmap -p 1-65535 -T4 {target_host}"
        result = subprocess.check_output(nmap_command, shell=True, text=True)

        # Tarama sonuçlarını yazdır ve log dosyasına ekle
        log("\nOtomatik Nmap Sonuçları:")
        log(result)

    except Exception as e:
        error_message = f"Hata: {e}"
        log(error_message)
async def nmap_auto_async(target_host):
    try:
        loop = asyncio.get_running_loop()
        nmap_command = f"nmap -p 1-65535 -T4 {target_host}"
        result = await loop.run_in_executor(None, lambda: subprocess.check_output(nmap_command, shell=True, text=True))

        log("\nOtomatik Nmap Sonuçları:")
        log(result)

    except Exception as e:
        error_message = f"Hata: {e}"
        log(error_message)

async def nmap_manual_async():
    try:
        loop = asyncio.get_running_loop()
        target_host = input("Manuel Nmap komutunu girin (örneğin, 'nmap 192.168.1.1'): ")
        nmap_command = f"nmap {target_host}"
        result = await loop.run_in_executor(None, lambda: subprocess.check_output(nmap_command, shell=True, text=True))

        log("\nManuel Nmap Sonuçları:")
        log(result)

    except Exception as e:
        error_message = f"Hata: {e}"
        log(error_message)
def nmap_manual():
    try:
        # Kullanıcıdan elle Nmap komutunu al
        target_host = input("Manuel Nmap komutunu girin (örneğin, 'nmap 192.168.1.1'): ")
        nmap_command = f"nmap {target_host}"
        result = subprocess.check_output(nmap_command, shell=True, text=True)

        # Tarama sonuçlarını yazdır ve log dosyasına ekle
        log("\nManuel Nmap Sonuçları:")
        log(result)

    except Exception as e:
        error_message = f"Hata: {e}"
        log(error_message)

def whois_lookup(target_ip):
    try:
        if platform.system() == "Windows":  # İşletim sistemi Windows ise
            error_message = "İşletim sisteminizden kaynaklı olarak bu işlevi çalıştıramazsınız."
            log(error_message)
            return

        # Whois sorgusu yap
        whois_command = f"whois {target_ip}"
        result = subprocess.check_output(whois_command, shell=True, text=True)

        # Whois sonuçlarını yazdır ve log dosyasına ekle
        log("\nWhois Sonuçları:")
        log(result)

    except Exception as e:
        error_message = f"Hata: {e}"
        log(error_message)

def check_firewall_status(ip_address):
    try:
        # 'nmap' komutunu kullanarak güvenlik duvarı taraması yap
        nmap_command = f"nmap -Pn -p 80,443 {ip_address}"  # Örnek olarak HTTP (80) ve HTTPS (443) portlarını tarıyoruz
        result = subprocess.check_output(nmap_command, shell=True, text=True)

        # Tarama sonuçlarında güvenlik duvarı durumu kontrol edin
        if "open" in result:
            return "✔"
        else:
            return "✖"

    except Exception as e:
        return "✖"

async def main():
    while True:  # Sonsuz bir döngü
        # Ağdaki cihazları alın
        target_network = "192.168.1.0/24"
        devices = get_devices(target_network)

        if devices:
            # Kullanıcıdan seçilen cihazın numarasını alın
            selected_device_num = int(input("Hangi cihazı seçmek istersiniz (Numara): "))

            if 1 <= selected_device_num <= len(devices):
                selected_device = devices[selected_device_num - 1]
                selected_ip = selected_device['ip']

                # Kullanıcıya hangi işlemi yapmak istediğini sor
                log("\nNe yapmak istersiniz?")
                log("1. Whois sorgusu")
                log("2. Otomatik Port taraması")
                log("3. Manuel Port taraması")
                choice = int(input("Seçiminizi yapın (1/2/3): "))

                if choice == 1:
                    # Seçilen IP adresine Whois sorgusu uygula ve sonuçları log dosyasına kaydet
                    whois_lookup(selected_ip)
                elif choice == 2:
                    # Otomatik Nmap taraması ve sonuçları log dosyasına kaydet
                    nmap_auto(selected_ip)
                elif choice == 3:
                    # Manuel Nmap taraması ve sonuçları log dosyasına kaydet
                    nmap_manual()
                else:
                    log("Geçersiz seçim.")
            else:
                log("Geçersiz cihaz numarası.")
        else:
            log("Cihazlar listelenemedi. Lütfen ARP komutunun çalıştığından emin olun.")

        restart = input("\nYeniden başlatmak ister misiniz? (Evet/Hayır): ")
        if restart.lower() != "evet":
            break  # Döngüyü sonlandır

        log("\n" + "-" * 50 + "\n")

# Log dosyasını kapat
if __name__ == "__main__":
    asyncio.run(main())
    log_file.close()