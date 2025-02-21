import socket
import random
import base64

def caesar_encrypt_bytes(text, shift):
    """
    Converte o texto para bytes (UTF-8), aplica o shift (módulo 256) em cada byte
    e retorna uma string Base64 com os bytes cifrados.
    """
    byte_data = text.encode('utf-8')
    encrypted_bytes = bytearray()
    for byte in byte_data:
        encrypted_bytes.append((byte + shift) % 256)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def caesar_decrypt_bytes(encoded_text, shift):
    """
    Decodifica a string Base64 para bytes, desfaz o shift (módulo 256) em cada byte
    e converte de volta para texto (UTF-8).
    """
    encrypted_bytes = base64.b64decode(encoded_text)
    decrypted_bytes = bytearray()
    for byte in encrypted_bytes:
        decrypted_bytes.append((byte - shift) % 256)
    return decrypted_bytes.decode('utf-8')

# Shifts fixos para criptografia dos parâmetros e das chaves públicas
params_shift = 3
public_key_shift = 3

HOST = '10.1.70.34'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("Servidor aguardando conexão...")
    conn, addr = s.accept()
    with conn:
        print('Conectado por', addr)
        
        # Recebe os parâmetros criptografados enviados pelo cliente (formato "G,P")
        encrypted_params = conn.recv(1024).decode('utf-8')
        if not encrypted_params:
            print("Nenhum parâmetro recebido.")
            exit(1)
        print("Parâmetros recebidos (criptografados):", encrypted_params)
        params_str = caesar_decrypt_bytes(encrypted_params, params_shift)
        print("Parâmetros decifrados:", params_str)
        # Extrai G e P
        try:
            parts = params_str.split(',')
            if len(parts) != 2:
                print("Formato de parâmetros inválido.")
                exit(1)
            G = int(parts[0].strip())
            P = int(parts[1].strip())
        except Exception as e:
            print("Erro ao processar os parâmetros:", e)
            exit(1)
        
        print("G recebido:", G)
        print("P recebido:", P)
        
        # Gera a chave privada do servidor e calcula sua chave pública
        server_secret = random.randint(1, P - 2)
        server_public = pow(G, server_secret, P)
        print("Servidor - Chave privada:", server_secret)
        print("Servidor - Chave pública:", server_public)
        
        # Envia a chave pública do servidor criptografada
        server_public_str = str(server_public)
        encrypted_server_public = caesar_encrypt_bytes(server_public_str, public_key_shift)
        conn.sendall(encrypted_server_public.encode('utf-8'))
        print("Chave pública do servidor enviada (criptografada):", encrypted_server_public)
        
        # Recebe a chave pública do cliente criptografada
        encrypted_client_public = conn.recv(1024).decode('utf-8')
        if not encrypted_client_public:
            print("Nenhuma chave pública do cliente recebida.")
            exit(1)
        print("Chave pública do cliente recebida (criptografada):", encrypted_client_public)
        client_public_str = caesar_decrypt_bytes(encrypted_client_public, public_key_shift)
        client_public = int(client_public_str)
        print("Chave pública do cliente decifrada:", client_public)
        
        # Calcula o segredo compartilhado
        shared_secret = pow(client_public, server_secret, P)
        print("Chave compartilhada:", shared_secret)
        
        # Recebe uma mensagem criptografada do cliente usando o shared_secret como shift
        encrypted_message = conn.recv(1024).decode('utf-8')
        if encrypted_message:
            decrypted_message = caesar_decrypt_bytes(encrypted_message, shared_secret)
            print("Mensagem recebida do cliente decifrada:", decrypted_message)
        
        # Envia uma mensagem de resposta criptografada com o shared_secret como shift
        reply_message = "Olá, cliente! Mensagem recebida com sucesso."
        encrypted_reply = caesar_encrypt_bytes(reply_message, shared_secret)
        conn.sendall(encrypted_reply.encode('utf-8'))
        print("Mensagem de resposta enviada (criptografada):", encrypted_reply)
