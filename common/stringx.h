
#ifndef __UTIL_H__
#define __UTIL_H__

void messagex(clamsmtp_context_t* ctx, int level, const char* msg, ...);
void message(clamsmtp_context_t* ctx, int level, const char* msg, ...);

void log_fd_data(clamsmtp_context_t* ctx, const char* data, int* fd, int read);
void log_data(clamsmtp_context_t* ctx, const char* data, const char* prefix);

int check_first_word(const char* line, const char* word, int len, char* delims);
int is_first_word(const char* line, const char* word, int len);
int is_last_word(const char* line, const char* word, int len);
int is_blank_line(const char* line);

void plock();
void punlock();

#endif /* __UTIL_H__ */
