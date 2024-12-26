# Blockchain Simulator / Lab

Um simulador educacional de blockchain implementado em C que demonstra os conceitos básicos de criptomoedas e mineração.

## Funcionalidades

- Criação e gerenciamento de carteiras usando criptografia de curva elíptica (secp256k1)
- Mineração de blocos com prova de trabalho (PoW)
- Sistema de transações entre carteiras
- Recompensas de mineração com mecanismo de halving
- Sistema de logging para monitoramento
- Persistência do estado da blockchain em arquivo
- Estatísticas da rede

## Requisitos

- GCC ou Clang
- OpenSSL >= 1.1.1
- Make

## Instalação

1. Clone o repositório:

```bash
git clone https://github.com/CiceroLino/blockchain-lab
cd blockchain-simulator
```

2. Compile o projeto:

```bash
make
```

## Uso

Execute o simulador:

```bash
./blockchain-simulator
```

O programa irá:

1. Inicializar ou carregar um blockchain existente
2. Criar carteiras de teste
3. Iniciar o processo de mineração
4. Realizar transações de teste periodicamente
5. Salvar o estado automaticamente

## Estrutura do Projeto

```
blockchain-simulator/
├── src/            # Código fonte
│   ├── core/       # Componentes principais
│   ├── utils/      # Utilitários
│   └── main.c      # Ponto de entrada
├── include/        # Headers públicos
└── Makefile
```

### Componentes Principais

- `blockchain.[ch]`: Gerenciamento da blockchain e estado global
- `block.[ch]`: Estrutura e operações de blocos
- `wallet.[ch]`: Gerenciamento de carteiras e chaves
- `transaction.[ch]`: Processamento de transações
- `logging.[ch]`: Sistema de logging
- `crypto.[ch]`: Operações criptográficas

## Detalhes Técnicos

### Carteiras

- Utiliza curva elíptica secp256k1 para geração de chaves
- Endereços simplificados baseados em hash SHA-256
- Armazenamento de histórico de transações

### Mineração

- Prova de trabalho (PoW) simplificada
- Dificuldade ajustável
- Recompensa inicial: 50 moedas
- Halving a cada 210.000 blocos

### Persistência

- Salvamento automático do estado após cada bloco
- Formato binário para eficiência
- Recuperação automática do último estado

## Limitações e Simplificações

Este é um projeto educacional com algumas simplificações:

- Sem rede P2P
- Sem validação completa de transações
- Sem scripts ou contratos inteligentes
- Dificuldade de mineração fixa
- Sistema de endereços simplificado

## Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o repositório
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a MIT License - veja o arquivo LICENSE para detalhes.
