import socket
import random
import base64
import time

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
    e converte de volta para uma string UTF-8.
    """
    encrypted_bytes = base64.b64decode(encoded_text)
    decrypted_bytes = bytearray()
    for byte in encrypted_bytes:
        decrypted_bytes.append((byte - shift) % 256)
    return decrypted_bytes.decode('utf-8')

def is_prime(n):
    """Valida se 'n' é primo utilizando um método de divisão (Primo Fast)."""
    if n < 2:
        return False
    i = 2
    while i < n:
        if n % i == 0:
            return False
        i += 1
    return True

def generate_random_prime(min_val, max_val):
    """Gera um número primo aleatório entre min_val e max_val."""
    while True:
        candidate = random.randint(min_val, max_val)
        if is_prime(candidate):
            return candidate

# --- Geração dos parâmetros Diffie–Hellman ---
# Gerar P (um primo grande) – para fins didáticos, escolhemos um intervalo pequeno
P = generate_random_prime(100, 300)
# Gerar G (primo também) em um intervalo de 2 até P-1
G = generate_random_prime(2, P - 1)
print("Valores gerados:")
print("P =", P)
print("G =", G)

# Shifts fixos para criptografia dos parâmetros e das chaves públicas
params_shift = 3
public_key_shift = 3

# Monta a string com os parâmetros no formato "G,P"
params_str = f"{G},{P}"
encrypted_params = caesar_encrypt_bytes(params_str, params_shift)
print("Parâmetros criptografados:", encrypted_params)

# Gera a chave privada e a chave pública do cliente usando Diffie–Hellman
client_secret = random.randint(1, P - 2)
client_public = pow(G, client_secret, P)
print("Cliente - Chave privada:", client_secret)
print("Cliente - Chave pública:", client_public)

HOST = '10.1.70.34'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Envia os parâmetros criptografados (G e P) para o servidor
    s.sendall(encrypted_params.encode('utf-8'))
    
    # Recebe a chave pública do servidor criptografada
    encrypted_server_public = s.recv(1024).decode('utf-8')
    if not encrypted_server_public:
        print("Nenhuma chave pública do servidor recebida.")
        exit(1)
    print("Chave pública do servidor recebida (criptografada):", encrypted_server_public)
    server_public_str = caesar_decrypt_bytes(encrypted_server_public, public_key_shift)
    server_public = int(server_public_str)
    print("Chave pública do servidor decifrada:", server_public)
    
    # Envia a chave pública do cliente criptografada
    client_public_str = str(client_public)
    encrypted_client_public = caesar_encrypt_bytes(client_public_str, public_key_shift)
    s.sendall(encrypted_client_public.encode('utf-8'))
    print("Chave pública do cliente enviada (criptografada):", encrypted_client_public)
    
    # Calcula o segredo compartilhado
    shared_secret = pow(server_public, client_secret, P)
    print("Chave compartilhada:", shared_secret)
    
    # Envia uma mensagem criptografada usando o shared_secret como shift
    message = "Olá, servidor! Esta é uma mensagem secreta com acentos: á, é, í, ó, ú, ç."
    encrypted_message = caesar_encrypt_bytes(message, shared_secret)
    s.sendall(encrypted_message.encode('utf-8'))
    print("Mensagem enviada para o servidor (criptografada):", encrypted_message)
    
    # Recebe a resposta do servidor
    encrypted_reply = s.recv(1024).decode('utf-8')
    if encrypted_reply:
        decrypted_reply = caesar_decrypt_bytes(encrypted_reply, shared_secret)
        print("Resposta do servidor decifrada:", decrypted_reply)
