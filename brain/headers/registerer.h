#include <openssl/ssl.h>

#ifndef REGISTERER
	#define REGISTERER

int registerCommon(SSL *cSSL,int id, char *hostname, char **scripts);
int registerer_daemon(int port,int listenPipe[2],int speakPipe[2]);
int registerer_run(const char *tentacleIp,int tentaclePort, int id, char *hostname, char **scripts);


#endif
