#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "logging.h"

void log_message(int level, const char *format, ...)
{
  static FILE *log_file = NULL;
  static const char *level_strings[] = {
      "ERROR",
      "WARNING",
      "INFO",
      "DEBUG"};

  if (log_file == NULL)
  {
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
      printf("Error opening log file!\n");
      return;
    }
  }

  time_t now;
  time(&now);
  char timestamp[26];
  ctime_r(&now, timestamp);
  timestamp[24] = '\0';

  va_list args;
  va_start(args, format);

  fprintf(log_file, "[%s][%s] ", timestamp, level_strings[level]);
  vfprintf(log_file, format, args);
  fprintf(log_file, "\n");
  fflush(log_file);

  if (DEBUG)
  {
    printf("[%s] ", level_strings[level]);
    vprintf(format, args);
    printf("\n");
  }

  va_end(args);
}