import socket
import ssl
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_certificate_info(ip, port=443):
    try:
        cmd = ['openssl', 's_client', '-connect', f'{ip}:{port}', '-servername', ip]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = process.communicate(input=b'\n', timeout=5)
        
        if process.returncode != 0:
            print(f"[{ip}:{port}] Erro na conexão SSL")
            return None
            
        output = stdout.decode()
        
        if "BEGIN CERTIFICATE" not in output:
            print(f"[{ip}:{port}] Certificado não encontrado")
            return None
            
        
        cmd = ['openssl', 'x509', '-noout', '-text', '-nameopt', 'oneline,-align']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = process.communicate(input=stdout)
        
        if process.returncode != 0:
            print(f"[{ip}:{port}] Erro ao processar certificado")
            return None
            
        cert_text = stdout.decode()
        
        
        cert_info = {
            'ip': ip,
            'port': port,
            'subject': {},
            'issuer': {},
            'valid_from': '',
            'valid_until': '',
            'san': []
        }
        
        
        for line in cert_text.split('\n'):
            line = line.strip()
            
            if "Subject:" in line:
                parts = line.split("Subject:")[1].strip().split("/")
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        cert_info['subject'][key.strip()] = value.strip()
            
            elif "Issuer:" in line:
                parts = line.split("Issuer:")[1].strip().split("/")
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        cert_info['issuer'][key.strip()] = value.strip()
            
            elif "Not Before:" in line:
                cert_info['valid_from'] = line.split("Not Before:", 1)[1].strip()
            
            elif "Not After :" in line:
                cert_info['valid_until'] = line.split("Not After :", 1)[1].strip()
            
            elif "DNS:" in line:
                dns_names = [x.split("DNS:")[1].strip().rstrip(",") for x in line.split() if "DNS:" in x]
                cert_info['san'].extend(dns_names)
        
        
        print(f"\n[+] Certificado encontrado para {ip}:{port}")
        if cert_info['subject'].get('CN'):
            print(f"    Common Name: {cert_info['subject']['CN']}")
        if cert_info['subject'].get('O'):
            print(f"    Organização: {cert_info['subject']['O']}")
        if cert_info['subject'].get('C'):
            print(f"    País: {cert_info['subject']['C']}")
        if cert_info['subject'].get('ST'):
            print(f"    Estado: {cert_info['subject']['ST']}")
        if cert_info['issuer'].get('O'):
            print(f"    Emissor: {cert_info['issuer']['O']}")
        print(f"    Válido desde: {cert_info['valid_from']}")
        print(f"    Válido até: {cert_info['valid_until']}")
        if cert_info['san']:
            print("    Domínios (SAN):")
            for san in cert_info['san']:
                print(f"      - {san}")
        
        return cert_info
        
    except subprocess.TimeoutExpired:
        print(f"[{ip}:{port}] Timeout na conexão")
        return None
    except Exception as e:
        print(f"[{ip}:{port}] Erro: {str(e)}")
        return None

def check_multiple_ips(filename, ports=[443]):
    results = []
    
    try:
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Arquivo {filename} não encontrado!")
        return
    
    total_ips = len(ips)
    print(f"\nVerificando certificados SSL para {total_ips} IPs...")
    print("=" * 50)
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_ip = {}
        for ip in ips:
            for port in ports:
                future = executor.submit(get_certificate_info, ip, port)
                future_to_ip[future] = (ip, port)
        
        for future in as_completed(future_to_ip):
            ip, port = future_to_ip[future]
            try:
                cert_info = future.result()
                if cert_info:
                    results.append(cert_info)
            except Exception as e:
                print(f"\nErro ao verificar {ip}:{port} - {str(e)}")
    
    print("\n" + "=" * 50)
    print("Verificação concluída!")
    
    if results:
        
        output_file = 'certificados_encontrados.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"Resultados salvos em {output_file}")
        
        
        txt_file = 'certificados_validos.txt'
        with open(txt_file, 'w', encoding='utf-8') as f:
            for cert in results:
                f.write(f"\nIP: {cert['ip']}:{cert['port']}\n")
                f.write("=" * 40 + "\n")
                
                if cert['subject'].get('CN'):
                    f.write(f"Common Name: {cert['subject']['CN']}\n")
                if cert['subject'].get('O'):
                    f.write(f"Organização: {cert['subject']['O']}\n")
                if cert['subject'].get('C'):
                    f.write(f"País: {cert['subject']['C']}\n")
                if cert['subject'].get('ST'):
                    f.write(f"Estado: {cert['subject']['ST']}\n")
                if cert['issuer'].get('O'):
                    f.write(f"Emissor: {cert['issuer']['O']}\n")
                
                f.write(f"Válido desde: {cert['valid_from']}\n")
                f.write(f"Válido até: {cert['valid_until']}\n")
                
                if cert['san']:
                    f.write("Domínios (SAN):\n")
                    for san in cert['san']:
                        f.write(f"  - {san}\n")
                f.write("\n")
                
        print(f"Resultados também salvos em {txt_file}")
        print(f"Total de certificados encontrados: {len(results)}")
    else:
        print("Nenhum certificado SSL encontrado.")

if __name__ == "__main__":
    input_file = 'lista_ip.txt'
    ports_to_check = [443]
    check_multiple_ips(input_file, ports_to_check)
