#include <stdio.h>

extern int sprintf(char *__restrict, char const *__restrict, ...);

extern int snprintf(char *__restrict, size_t, char const *__restrict, ...);

extern int vsprintf(char *__restrict, char const *__restrict, va_list);

extern int vsnprintf(char *__restrict, size_t, char const *__restrict, va_list);
