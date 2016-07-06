#ifndef FCT_H
#define FCT_H
#include <openssl/ssl.h>

#define LOG_TYPE_STDOUT 1
#define LOG_TYPE_STDERR 2
#define LOG_TYPE_LOGFILE 3

#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARNING 3
#define LOG_LEVEL_ERROR 4
#define LOG_LEVEL_CRITICAL 5

void InitializeSSL();
void DestroySSL();
void ShutdownSSL(SSL *ssl);
void getSSLerr(int err);
int create_listenSock(int port);
int sendMsg(SSL *cSSL,char *msg);
int getMsg(SSL *cSSL,char *msg,char* compareTo);

int logType(int param);
int logLevel(int param);
int logError(int logValue, char *logMessage);
	
char from_hex(char ch);
char *url_decode(char *str);
char to_hex(char code);
char *url_encode(char *str);


#endif
