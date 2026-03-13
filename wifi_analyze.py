import time
import os
import csv
from datetime import datetime
import sys
import threading
import json
import urllib.request
import ssl

try:
    import pywifi
    from pywifi import const
    from win10toast import ToastNotifier
except ImportError:
    print("ERRO: Faltam bibliotecas.")
    print("Por favor, instale executando: pip install pywifi comtypes win10toast")
    sys.exit(1)

# Desativas verificacoes SSL chatas no Python para o urllib (para a API de MAC)
ssl._create_default_https_context = ssl._create_unverified_context

class C:
    GREEN = ''
    YELLOW = ''
    RED = ''
    CYAN = ''
    RESET = ''
    BOLD = ''

if os.name == 'nt':
    os.system('color')

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

class WiFiAnalyzerPro:
    def __init__(self):
        try:
            self.wifi = pywifi.PyWiFi()
            self.iface = self.wifi.interfaces()[0]
            self.last_scan_results = []
            
            # Inicializando Notificador do Windows (Nível 1)
            self.toaster = ToastNotifier()
            self.mac_cache = {} # Cache local de MAC -> Fabricante
            self.redes_alertadas = set() # Redes que já disparamos alerta
            
        except Exception as e:
            print(f"{C.RED}Erro: Nenhuma interface Wi-Fi encontrada ou sem permissao.{C.RESET}")
            print(f"Detalhe: {e}")
            sys.exit(1)

    def get_mac_vendor(self, mac_address):
        """Nova Funcionalidade Nivel 1: Descobre Fabricante via BSSID(MAC)."""
        # Formata MAC padrao 'XX:XX:XX:XX:XX:XX' para pesquisar 
        prefixo = mac_address.upper()[:8]
        
        # Se já conhecemos, retorna do cache rápido
        if prefixo in self.mac_cache:
            return self.mac_cache[prefixo]
            
        try:
            # API publica gratuita de pesquisa de endereço MAC
            url = f"https://api.maclookup.app/v2/macs/{mac_address}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                data = json.loads(response.read().decode())
                if data.get('success') and data.get('found'):
                    fabricante = data.get('company', 'Desconhecido')
                    fabricante = fabricante[:15] # Trunca nome da empresa
                    self.mac_cache[prefixo] = fabricante
                    return fabricante
                else:
                    self.mac_cache[prefixo] = "A. Anonimo"
                    return "A. Anonimo"
        except Exception:
            self.mac_cache[prefixo] = "Desconhecido"
            return "Desconhecido"

    def emitir_alerta_windows(self, titulo, mensagem):
        """Nova Funcionalidade Nivel 1: Alerta no Windows!"""
        # Rodar o Toast em uma Thread para não paralisar o programa
        def show_toast():
            try:
                self.toaster.show_toast(titulo, mensagem, duration=5, threaded=True)
            except Exception:
                pass
        threading.Thread(target=show_toast, daemon=True).start()

    def scan_networks(self):
        """Realiza a varredura e filtra duplicatas."""
        self.iface.scan()
        time.sleep(4) 
        
        results = self.iface.scan_results()
        
        unique_nets = {}
        for net in results:
            bssid = net.bssid
            if bssid not in unique_nets or net.signal > unique_nets[bssid].signal:
                unique_nets[bssid] = net
                
        sorted_nets = sorted(unique_nets.values(), key=lambda x: x.signal, reverse=True)
        self.last_scan_results = sorted_nets
        return sorted_nets

    def get_signal_info(self, rssi):
        if rssi >= -50: return ("[====] Excelente", C.GREEN)
        elif rssi >= -65: return ("[=== ] Bom", C.GREEN)
        elif rssi >= -80: return ("[==  ] Medio", C.YELLOW)
        elif rssi >= -90: return ("[=   ] Fraco", C.RED)
        else: return ("[    ] Pessimo", C.RED)

    def get_security_info(self, network):
        auth_suites = network.akm
        if const.AKM_TYPE_WPA2 in auth_suites or const.AKM_TYPE_WPA2PSK in auth_suites:
            return ("WPA2/WPA3", C.GREEN, "Seguro")
        elif const.AKM_TYPE_WPA in auth_suites or const.AKM_TYPE_WPAPSK in auth_suites:
            return ("WPA(V1)", C.YELLOW, "Obsoleto")
        elif const.AKM_TYPE_NONE in auth_suites:
            if network.cipher == const.CIPHER_TYPE_WEP: return ("WEP", C.RED, "VULNERAVEL")
            else: return ("ABERTA", C.RED, "VULNERAVEL")
        elif network.cipher == const.CIPHER_TYPE_WEP: return ("WEP", C.RED, "VULNERAVEL")
        else: return ("Outro", C.CYAN, "Indefinido")

    def print_table(self, networks):
        if not networks:
            print(f"{C.RED}Nenhuma rede encontrada.{C.RESET}")
            return

        print(f"\n{C.BOLD}{C.CYAN}--- Relatorio detalhado de Redes Wi-Fi ---{C.RESET}")
        print(f"{'SSID':<25} | {'Fabricante (MAC)':<16} | {'Sinal Visual':<17} | {'Seguranca':<15} | {'Observacao':<15}")
        print("-" * 100)
        
        # Analisa uma por uma e dispara alertas, se necessario
        redes_perigosas_encontradas = 0

        for net in networks:
            ssid = net.ssid if net.ssid else "<Rede Oculta>"
            ssid_safe = ssid.encode('ascii', errors='ignore').decode('ascii')
            if not ssid_safe.strip(): ssid_safe = "<Caracteres Especiais>"
            ssid_padded = f"{ssid_safe[:24]:<25}" 
            
            bssid = net.bssid
            
            # Chama a função nova Level 1 do Fabricante
            fabricante = self.get_mac_vendor(bssid)
            
            sig_text, sig_color = self.get_signal_info(net.signal)
            sig_colored = f"{sig_color}{sig_text:<17}{C.RESET}"

            auth, auth_color, obs = self.get_security_info(net)
            auth_colored = f"{auth_color}{auth:<15}{C.RESET}"
            obs_colored = f"{auth_color}{obs:<15}{C.RESET}"
            
            # Funcionalidade Alerta (Evitar floodar mesmo alerta 2 vezes pra mesma rede)
            if "VULNERAVEL" in obs and bssid not in self.redes_alertadas:
                redes_perigosas_encontradas += 1
                self.redes_alertadas.add(bssid)
                self.emitir_alerta_windows("Risco Wi-Fi Detectado!", f"Rede Aberta/Vulneravel: {ssid_safe} ({fabricante}) próspera a ataques.")

            print(f"{ssid_padded} | {fabricante:<16} | {sig_colored} | {auth_colored} | {obs_colored}")

        print(f"\n{C.CYAN}Total de redes unicas encontradas: {len(networks)}{C.RESET}")

    def export_csv(self):
        if not self.last_scan_results:
            print(f"{C.YELLOW}Aviso: Nenhuna varredura recente. Faca um scan primeiro.{C.RESET}")
            return
        filename = f"wifi_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow(['SSID', 'BSSID', 'Fabricante', 'Sinal (dBm)', 'Qualidade', 'Seguranca', 'Observacao'])
                
                for net in self.last_scan_results:
                    ssid = net.ssid if net.ssid else "Rede Oculta"
                    fabricante = self.get_mac_vendor(net.bssid)
                    sig_text, _ = self.get_signal_info(net.signal)
                    auth, _, obs = self.get_security_info(net)
                    writer.writerow([ssid, net.bssid, fabricante, net.signal, sig_text, auth, obs])
                    
            print(f"{C.GREEN}[+] Sucesso! Relatorio salvo em: {os.path.abspath(filename)}{C.RESET}")
        except Exception as e:
            print(f"{C.RED}Erro ao salvar CSV: {e}{C.RESET}")

    def run_radar_mode(self):
        print(f"{C.YELLOW}Entrando no Modo Radar. Pressione CTRL+C para sair.{C.RESET}")
        time.sleep(2)
        try:
            while True:
                limpar_tela()
                print(f"{C.BOLD}{C.YELLOW}[ MODO RADAR ATIVO ] - Atualizando... (CTRL+C para sair){C.RESET}")
                nets = self.scan_networks()
                self.print_table(nets)
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{C.CYAN}Saindo do modo radar...{C.RESET}")

    def menu(self):
        while True:
            print(f"\n{C.CYAN}{C.BOLD}=== Wi-Fi Analyzer Pro (Level 1) ==={C.RESET}")
            print(f"Interface em uso: {C.GREEN}{self.iface.name()}{C.RESET}\n")
            print("1. Escanear Redes (Scan Unico com API de MAC)")
            print("2. Modo Radar (Atualizacao em Tempo Real + Alertas)")
            print("3. Exportar Ultimo Scan para CSV")
            print("4. Sair")
            
            escolha = input(f"\n{C.BOLD}Escolha uma opcao: {C.RESET}")
            
            if escolha == '1':
                print(f"\n{C.YELLOW}Iniciando varredura e consultando fabricantes nas APIs...{C.RESET}")
                nets = self.scan_networks()
                self.print_table(nets)
            elif escolha == '2':
                self.run_radar_mode()
            elif escolha == '3':
                self.export_csv()
            elif escolha == '4':
                print(f"{C.GREEN}Encerrando o programa... Ate logo!{C.RESET}")
                break
            else:
                print(f"{C.RED}Opcao invalida! Tente novamente.{C.RESET}")


if __name__ == "__main__":
    app = WiFiAnalyzerPro()
    app.menu()
