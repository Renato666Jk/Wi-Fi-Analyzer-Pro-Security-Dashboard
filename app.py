import os
import time
import json
import urllib.request
import socket
import threading
import subprocess
import re
import ssl
import csv
import io
import requests
from flask import Flask, render_template, jsonify, send_file

try:
    import pywifi
    from pywifi import const
except ImportError:
    print("ERRO: PyWiFi nao encontrado.")
    exit(1)

# Desativas verificacoes SSL chatas no Python para o urllib (para a API de MAC)
ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__)
mac_cache = {}
last_scan_data = []

def get_mac_vendor(mac_address):
    prefixo = mac_address.upper()[:8]
    if prefixo in mac_cache:
        return mac_cache[prefixo]
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.5) as response:
            data = json.loads(response.read().decode())
            if data.get('success') and data.get('found'):
                fabricante = data.get('company', 'Desconhecido')[:20]
                mac_cache[prefixo] = fabricante
                return fabricante
            else:
                mac_cache[prefixo] = "A. Anonimo"
                return "A. Anonimo"
    except Exception:
        mac_cache[prefixo] = "Desconhecido"
        return "Desconhecido"

def get_security_info(network):
    auth_suites = network.akm
    if const.AKM_TYPE_WPA2 in auth_suites or const.AKM_TYPE_WPA2PSK in auth_suites:
        return {"level": "Seguro", "protocol": "WPA2/WPA3"}
    elif const.AKM_TYPE_WPA in auth_suites or const.AKM_TYPE_WPAPSK in auth_suites:
        return {"level": "Obsoleto", "protocol": "WPA(V1)"}
    elif const.AKM_TYPE_NONE in auth_suites:
        if network.cipher == const.CIPHER_TYPE_WEP:
            return {"level": "Vulneravel", "protocol": "WEP"}
        else:
            return {"level": "Vulneravel", "protocol": "ABERTA"}
    elif network.cipher == const.CIPHER_TYPE_WEP:
        return {"level": "Vulneravel", "protocol": "WEP"}
    else:
        return {"level": "Indefinido", "protocol": "Desconhecido"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def scan():
    global last_scan_data
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        
        iface.scan()
        time.sleep(4) # Espera 4 seg para a placa ouvir o ambiente
        
        results = iface.scan_results()
        
        unique_nets = {}
        for net in results:
            bssid = net.bssid
            if bssid not in unique_nets or net.signal > unique_nets[bssid].signal:
                unique_nets[bssid] = net
                
        sorted_nets = sorted(unique_nets.values(), key=lambda x: x.signal, reverse=True)
        
        data = []
        for net in sorted_nets:
            ssid = net.ssid if net.ssid else "<Rede Oculta>"
            ssid_safe = ssid.encode('ascii', errors='ignore').decode('ascii')
            if not ssid_safe.strip(): ssid_safe = "<Caracteres Especiais>"
            
            bssid = net.bssid
            fabricante = get_mac_vendor(bssid)
            security = get_security_info(net)
            
            # Transforma o sinal em dBm (-100 a -50) em porcentagem de preenchimento da barra (0 a 100%)
            quality = min(max(2 * (net.signal + 100), 0), 100)
            
            data.append({
                "ssid": ssid_safe,
                "bssid": bssid,
                "fabricante": fabricante,
                "signal": net.signal,
                "quality": quality,
                "security": security
            })
            
        last_scan_data = data
        return jsonify({"success": True, "networks": data, "interface": iface.name()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/export')
def export_csv():
    global last_scan_data
    if not last_scan_data:
        # Retorna erro se nenhum scan foi feio ainda
        return "Nenhum dado para exportar. Faça um scan primeiro.", 400

    csv_io = io.StringIO()
    writer = csv.writer(csv_io, delimiter=';')
    writer.writerow(['SSID', 'BSSID (MAC)', 'Fabricante', 'Sinal (dBm)', 'Qualidade (%)', 'Nivel de Seguranca', 'Protocolo'])

    for net in last_scan_data:
        writer.writerow([
            net['ssid'], 
            net['bssid'], 
            net['fabricante'], 
            net['signal'], 
            round(net['quality']),
            net['security']['level'],
            net['security']['protocol']
        ])
    
    mem_file = io.BytesIO()
    mem_file.write(csv_io.getvalue().encode('utf-8-sig'))
    mem_file.seek(0)
    
    filename = f"Relatorio_WiFi_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(mem_file, mimetype='text/csv', as_attachment=True, download_name=filename)


@app.route('/api/scan_lan')
def scan_lan():
    def check_port(ip, port, result_list):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            if s.connect_ex((ip, port)) == 0:
                result_list.append(port)
            s.close()
        except:
            pass

    cameras = []
    try:
        # Pede para o Windows a tabela ARP para descobrir todos IPs na area!
        output = subprocess.check_output("arp -a", shell=True).decode('latin1')
        pattern = re.compile(r"^\s*([0-9\.]+)\s+([0-9a-f\-]+)\s+", re.IGNORECASE | re.MULTILINE)
        devices = pattern.findall(output)
        
        threads = []
        device_results = {}
        
        for ip, mac in devices:
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                continue # Ignora redes de broadcast (inuteis)
                
            mac_formatted = mac.replace('-', ':').upper()
            device_results[ip] = {'mac': mac_formatted, 'ports': []}
            
            # Tenta portas chaves (80 web, 8080 mjpeg, 554 RTSP padrao de DVR)
            for port in [80, 8080, 554, 81]:
                t = threading.Thread(target=check_port, args=(ip, port, device_results[ip]['ports']))
                threads.append(t)
                t.start()
                
        for t in threads:
            t.join(timeout=1.0)
            
        for ip, info in device_results.items():
            if info['ports']:
                fabricante = get_mac_vendor(info['mac'])
                cam_type = "Aparelho Web"
                if 554 in info['ports']: cam_type = "DVR / Câmera RTSP"
                elif 8080 in info['ports'] or 81 in info['ports']: cam_type = "Webcam IP"
                elif 80 in info['ports']: cam_type = "Painel Automação / Câmera"
                
                # Fabricantes Classicos de Cameras
                is_cam = "sim" if any(f.lower() in fabricante.lower() for f in ['intelbras', 'hikvision', 'dahua', 'foscam', 'axis', 'tp-link', 'ezviz']) else "talvez"
                
                # Constrói o Link de visualização
                url = f"http://{ip}:{info['ports'][0]}"
                if 554 in info['ports']:
                    url = f"rtsp://{ip}:554/1"

                cameras.append({
                    "ip": ip,
                    "mac": info['mac'],
                    "fabricante": fabricante,
                    "ports": ", ".join(map(str, info['ports'])),
                    "type": cam_type,
                    "is_cam": is_cam,
                    "url": url
                })
                
        return jsonify({"success": True, "devices": cameras})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/isp')
def get_isp_info():
    """Descobre a operadora e o IP público atual."""
    try:
        # Usa a API do ip-api (gratuita) para descobrir detalhes da conexão
        res = requests.get("http://ip-api.com/json/", timeout=2).json()
        return jsonify({
            "success": True,
            "isp": res.get("isp", "Desconhecido"),
            "city": res.get("city", "Desconhecida"),
            "ip": res.get("query", "0.0.0.0"),
            "org": res.get("as", "")
        })
    except:
        return jsonify({"success": False, "error": "Offline"})

@app.route('/api/speedtest')
def speed_test_data():
    """Gera 1MB de dados aleatórios para testar velocidade de download."""
    data = b"0" * (1024 * 1024) # 1 MB de dados
    return data

@app.route('/api/ping')
def get_ping():
    """Mede a latência real com o Google (DNS)."""
    try:
        start = time.time()
        socket.create_connection(("8.8.8.8", 53), timeout=1.5)
        latency = round((time.time() - start) * 1000)
        return jsonify({"success": True, "ping": latency})
    except:
        return jsonify({"success": False, "ping": 999})

@app.route('/api/audit/<ip>')
def audit_device(ip):
    report = []
    
    def test_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex((ip, port)) == 0
        except: return False

    # 1. Checa por Telnet e FTP (Criptografia Zero, Texto Limpo)
    if test_port(21): report.append("⚠️ Risco Crítico: Serviço FTP (Porta 21) está escancarado. Transferências não são criptografadas e senhas podem ser interceptadas na rede.")
    if test_port(23): report.append("⚠️ Risco Crítico: Serviço Telnet (Porta 23) ativo. Essa tecnologia é defasada e permite invasão usando força-bruta passiva de senhas!")

    # 2. Avalia a Camada Web HTTP
    if test_port(80):
        try:
            res = requests.get(f"http://{ip}", timeout=1.5, allow_redirects=False)
            server = res.headers.get('Server', 'Desconhecido')
            
            if 'Desconhecido' not in server:
                report.append(f"ℹ️ Informação Vazada: O servidor web do aparelho responde como '{server}'. Invasores usam isso para pesquisar vulnerabilidades exatas no Google.")
                
            if res.status_code == 401 and 'Basic' in res.headers.get('WWW-Authenticate', ''):
                report.append("⚠️ Vulnerabilidade Grave de Autenticação: O painel usa 'HTTP Basic Auth' sem criptografia. Ao digitar admin/senha na tela, os vizinhos da Wi-Fi capturam sua senha em texto limpo no ar.")
            elif res.status_code == 200:
                report.append("⚠️ Aviso: A interface de configuração do dispositivo está aberta via HTTP. Qualquer usuário na tela preta poderá assistir ou alterar os dados enviados.")
        except requests.exceptions.RequestException: pass

    # 3. Avalia HTTPS Seguro
    if test_port(443):
        report.append("✅ Ponto Positivo: O dispositivo oferece criptografia moderna (HTTPS) na porta 443. É recomendado desligar a Porta 80 nas configurações e usar somente esta!")
    else:
        report.append("❌ Falha de Segurança Moderna: Este equipamento de rede NÃO suporta HTTPS Ativo. Todas as comunicações são suscetíveis a interceptação.")

    if not report:
        report.append("ℹ️ O equipamento está rodando de portas fechadas e seguro, ou a comunicação foi bloqueada pelo roteador principal.")

    return jsonify({"success": True, "ip": ip, "audit": report})

if __name__ == '__main__':
    # Roda o servidor web do Windows na porta 5000
    app.run(port=5000, debug=True)
