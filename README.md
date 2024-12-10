# Verificador de Certificados SSL/TLS

Uma ferramenta em Python para verificar certificados SSL/TLS de múltiplos endereços IP simultaneamente. Esta ferramenta auxilia profissionais de segurança e administradores de sistemas na verificação de informações de certificados de múltiplos servidores de forma eficiente.

## Funcionalidades

- Verificação de certificados em múltiplas threads
- Suporte para verificação de múltiplas portas
- Extração detalhada de informações dos certificados, incluindo:
  - Detalhes do sujeito (subject)
  - Informações do emissor (issuer)
  - Período de validade
  - Fingerprints do certificado
- Salva resultados em formatos JSON e TXT

## Pré-requisitos

- Python 3.6 ou superior
- Ferramenta de linha de comando OpenSSL
- Módulos Python necessários:
  ```
  socket
  ssl
  json
  subprocess
  concurrent.futures
  ```

## Instalação

1. Clone este repositório:
   ```bash
   git clone [url-do-seu-repositorio]
   cd [nome-do-repositorio]
   ```

2. Certifique-se de ter o OpenSSL instalado no seu sistema:
   ```bash
   openssl version
   ```

## Como Usar

1. Crie um arquivo de texto (`lista_ip.txt`) contendo os endereços IP que deseja verificar, um por linha:
   ```
   192.168.1.1
   10.0.0.1
   exemplo.com.br
   ```

2. Execute o script:
   ```bash
   python3 check_certificados.py
   ```

Por padrão, o script irá:
- Verificar a porta 443 para cada endereço IP
- Salvar certificados válidos em `certificados_validos.txt`
- Gerar saída JSON detalhada para cada certificado

### Personalizando Portas

Para verificar diferentes portas, modifique a lista `ports_to_check` no script:

```python
ports_to_check = [443, 8443]  # Exemplo para verificar as portas 443 e 8443
```

## Saída

O script gera dois tipos de saída:

1. `certificados_validos.txt`: Uma lista simples de certificados válidos com informações básicas
2. Saída JSON detalhada no console mostrando informações completas dos certificados

## Tratamento de Erros

O script lida com vários cenários de erro:
- Timeouts de conexão
- Certificados inválidos
- Hosts que não respondem
- Falhas no handshake SSL/TLS

## Contribuindo

Sinta-se à vontade para enviar issues e solicitações de melhorias!

## Licença

[Sua licença escolhida]

## Autor

[Seu nome/organização]
