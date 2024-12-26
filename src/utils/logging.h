#ifndef BLOCKCHAIN_LOGGING_H
#define BLOCKCHAIN_LOGGING_H

// Definições para logging
#define LOG_FILE "miner.log"
#define DEBUG 1
#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

// Função de logging
void log_message(int level, const char *format, ...);

#endif // BLOCKCHAIN_LOGGING_H