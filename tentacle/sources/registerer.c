#include "../headers/registerer.h"
#include "../headers/fct.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <strings.h>

#define SUCCESS 0
#define ERR_DEFAULT -1
#define ERR_SCK_SCK -2
#define ERR_SCK_OPT -3
#define ERR_SCK_BND -4
#define ERR_SCK_LSN -5
#define ERR_SCK_ACT -6

int registerCommon(SSL *cSSL,int *key, int *id){
	int genKey;
	char bufIn[BUFSIZ],bufOut[BUFSIZ],*tmp,hostname[BUFSIZ], *listOfScripts;



	if(getMsg(cSSL,bufIn,NULL) != 0) return 0;
	if(strncmp(bufIn,"ID:",3) != 0){
		ShutdownSSL(cSSL);
		return 0;
	}
	tmp = bufIn+3;
	sscanf(tmp,"%d",id);



	gethostname(hostname,BUFSIZ);
	sprintf(bufOut,"OK:%d:HOSTNAME:%s\n",*id,hostname);
	if(sendMsg(cSSL,bufOut) == -1) return 0;

 
	sprintf(bufOut,"OK:%s",hostname);
	if(getMsg(cSSL,bufIn,bufOut) != 0) return 0;

	srand(time(NULL));
	genKey = rand();
	sprintf(bufOut,"KEY:%d\n",genKey);
	if(sendMsg(cSSL,bufOut) == -1) return 0;

	sprintf(bufOut,"OK:%d",genKey);
	if(getMsg(cSSL,bufIn,bufOut) != 0) return 0;
	*key = genKey;


	listOfScripts = list();
	sprintf(bufOut,"SCRIPTS:%s:EOL",listOfScripts);
	free(listOfScripts);
	if(sendMsg(cSSL,bufOut) == -1) return 0;

	sprintf(bufOut,"OKSCRIPTS");
	if(getMsg(cSSL,bufIn,bufOut) != 0) return 0;

	ShutdownSSL(cSSL);

	return *id;
}

int registerFromBrain(int sock, char **ipBrain,int *key, int *id){
	int service,len,ssl_err, ret;
	char buf[BUFSIZ],*tmp;
	SSL_CTX *sslctx;
	SSL *cSSL;
	struct sockaddr_in callerExtremity;
	len = sizeof(callerExtremity);

	service = accept(sock,(struct sockaddr *) &callerExtremity,(socklen_t *) &len);

	sslctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_use_certificate_file(sslctx, "/etc/octopus/tentacle/cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(sslctx, "/etc/octopus/tentacle/key.pem", SSL_FILETYPE_PEM);
	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, service);
	ssl_err = SSL_accept(cSSL);
	if (ssl_err != 1) {
		getSSLerr(SSL_get_error(cSSL,ssl_err));
		ShutdownSSL(cSSL);
	}

	if(getMsg(cSSL,buf,"LO_TENTACLE") != 0) return 0;
	if(sendMsg(cSSL,"LO_BRAIN\n") == -1) return 0;
	ret = registerCommon(cSSL,key,id);
	if(ret != 0){
		char *ip = inet_ntoa(callerExtremity.sin_addr);
		tmp = (char *)malloc(strlen(ip)+1);
		strcpy(tmp,ip);
		*ipBrain = tmp;
	}
	return ret;
}

int registerer_wait(int port, char **ipBrain, int *key, int *id){
	int sock,ret;
	InitializeSSL();
	sock = create_listenSock(port);
	do{
		ret = registerFromBrain(sock, ipBrain, key, id);
	}while(ret == 0);
	return ret;
}

int registerer_run(const char *brainIp,int brainPort, int *key, int *id){
	int sock, iSetOption = 1, ssl_err;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char buf[BUFSIZ];
	struct sockaddr_in brainExtremity;


	InitializeSSL();
	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &iSetOption, sizeof (iSetOption));
	brainExtremity.sin_family = AF_INET;
	brainExtremity.sin_addr.s_addr = inet_addr(brainIp);
	brainExtremity.sin_port = htons(brainPort);

	if (connect(sock, (struct sockaddr*) &brainExtremity, sizeof (brainExtremity)) != 0) {
		exit(0);
	}

	sslctx = SSL_CTX_new(SSLv3_client_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);


	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sock);
	ssl_err = SSL_connect(cSSL);

	if (ssl_err != 1) {
		getSSLerr(SSL_get_error(cSSL,ssl_err));
		ShutdownSSL(cSSL);
	}

	if(sendMsg(cSSL,"LO_BRAIN\n") == -1) return 0;
	if(getMsg(cSSL,buf,"LO_TENTACLE") != 0) return 0;
	if(sendMsg(cSSL,"PLS_REG\n") == -1) return 0;
	return registerCommon(cSSL,key,id);
}


