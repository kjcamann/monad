#include <string.h>

extern void *memcpy(void *__restrict, void const *__restrict, size_t);
extern void *memmove(void *, void const *, size_t);
extern void *memset(void *, int, size_t);
extern int memcmp(void const *, void const *, size_t);
extern void *memchr(void const *, int, size_t);

extern char *strcpy(char *__restrict, char const *__restrict);
extern char *strncpy(char *__restrict, char const *__restrict, size_t);

extern char *strchr(char const *, int);
extern char *strrchr(char const *, int);

extern size_t strlen(char const *);
extern char *strerror(int);

extern char *stpcpy(char *__restrict, char const *__restrict);
extern char *stpncpy(char *__restrict, char const *__restrict, size_t);

extern size_t strlcpy(char *, char const *, size_t);
extern void *mempcpy(void *__restrict, void const *__restrict, size_t);
