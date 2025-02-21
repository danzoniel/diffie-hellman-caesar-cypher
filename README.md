Projeto: Troca de Chaves Diffie–Hellman com Criptografia de Parâmetros via Cifra de César e Base64
Este projeto demonstra a implementação de um protocolo de troca de chaves Diffie–Hellman, combinando uma cifra de César aplicada em nível de bytes com codificação Base64 para transmitir parâmetros e mensagens de forma segura entre um cliente e um servidor em Python.

Visão Geral
Diffie–Hellman: Permite que duas partes estabeleçam uma chave secreta compartilhada mesmo comunicando-se através de um canal inseguro.
Cifra de César em Bytes: Aplica um deslocamento (shift) aos bytes da mensagem (operando módulo 256) para cifrar e decifrar informações.
Base64: Converte os bytes cifrados em uma representação textual composta por caracteres seguros, garantindo compatibilidade na transmissão.
Geração de Parâmetros Aleatórios: O cliente gera aleatoriamente os números primos G e P (usando uma versão simplificada do método "Primo Fast") que serão utilizados para o algoritmo Diffie–Hellman.
Funcionalidades
Geração de Números Primos: O cliente gera números aleatórios para P e G e os valida com um método simples de teste de primalidade.
Criptografia dos Parâmetros: Os valores de G e P são criptografados utilizando a cifra de César em nível de bytes e codificados em Base64 antes de serem enviados ao servidor.
Troca de Chaves: Após a troca dos parâmetros, o servidor e o cliente realizam a troca de chaves públicas (também criptografadas) e calculam o segredo compartilhado.
Troca de Mensagens: Utilizando o segredo compartilhado, ambos os lados podem criptografar e decifrar mensagens trocadas.
Estrutura do Projeto
bash
Copiar
├── server.py    # Código do servidor: recebe parâmetros, gera chave pública e troca mensagens.
├── client.py    # Código do cliente: gera números primos, criptografa os parâmetros e realiza a troca de chaves.
└── README.md    # Este arquivo.
Pré-requisitos
Python 3.x
Módulos utilizados:
socket
random
base64
time (utilizado no teste de primalidade simples no cliente)
Observação: Os números primos usados neste exemplo são gerados em intervalos pequenos para fins didáticos. Em uma aplicação real, eles deveriam ser significativamente maiores para garantir a segurança do protocolo.

Instruções de Uso
Passo 1: Executar o Servidor
Abra um terminal.
Execute o script do servidor:
bash
Copiar
python server.py
O servidor ficará aguardando uma conexão na porta configurada (por padrão, 127.0.0.1:65432).
Passo 2: Executar o Cliente
Abra outro terminal.
Execute o script do cliente:
bash
Copiar
python client.py
O cliente irá:
Gerar e validar os números primos P e G.
Criptografar e enviar os parâmetros para o servidor.
Gerar sua chave privada e pública.
Realizar a troca de chaves com o servidor.
Enviar uma mensagem criptografada utilizando o segredo compartilhado.
Receber e decifrar a resposta do servidor.
Detalhes Técnicos
Módulo 256
Objetivo:
Operar com bytes, garantindo que, ao aplicar operações (como soma ou subtração para a cifra de César), os resultados se mantenham dentro do intervalo de 0 a 255.

Exemplo:
Um byte com valor 255, ao ter um shift de 3 aplicado, resultará em:

(
255
+
3
)
m
o
d
 
 
256
=
2
(255+3)mod256=2
Assim, o valor se "enrola" e permanece dentro dos limites de um byte.

Base64
Objetivo:
Converter os dados binários resultantes da cifra (que podem conter caracteres não imprimíveis ou de controle) em uma string composta por caracteres seguros e imprimíveis.

Benefícios:

Transmissão Segura: Garante que os dados cifrados possam ser enviados por protocolos que só aceitam dados textuais.
Compatibilidade: Os caracteres utilizados no Base64 são amplamente aceitos em diversos sistemas (e-mails, JSON, etc.).
Reversibilidade: O processo é reversível, permitindo que o receptor decodifique a mensagem exatamente como foi enviada.
Possíveis Melhorias e Considerações
Segurança Real:
A cifra de César é utilizada apenas para fins didáticos e não é segura para ambientes de produção. Em sistemas reais, recomenda-se o uso de algoritmos de criptografia modernos.

Geração de Números Primos:
O método de validação utilizado ("Primo Fast") é simples e adequado para intervalos pequenos. Para números grandes, algoritmos mais eficientes (como o teste de Miller-Rabin) devem ser considerados.

Parâmetros Diffie–Hellman:
Em aplicações reais, os parâmetros P e G devem ser escolhidos com base em padrões seguros e ser suficientemente grandes para evitar ataques de força bruta.

Conclusão
Este projeto demonstra de forma didática como é possível combinar a troca de chaves Diffie–Hellman com técnicas simples de criptografia (como a cifra de César e codificação Base64) para transmitir parâmetros e mensagens. Embora o exemplo seja educativo, ele ilustra os conceitos fundamentais que estão presentes em sistemas de criptografia mais robustos.
