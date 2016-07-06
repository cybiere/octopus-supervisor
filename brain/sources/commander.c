#include "../headers/commander.h"
#include "../headers/fct.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int commanderRun(char *ip, int port, int key, int id, char *script){
	int sock, iSetOption = 1, ssl_err;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char buf[BUFSIZ],errBuf[BUFSIZ],cmpBuf[BUFSIZ];
	struct sockaddr_in tentacleExtremity;

	if(ip == NULL || script == NULL){
		logError(LOG_LEVEL_ERROR,"commander:commanderRun : ip or script NULL, abort.");
		return -1;
	}
	sprintf(errBuf,"commander:commanderRun : contacting %s:%d",ip,port);
	logError(LOG_LEVEL_DEBUG,errBuf);

	InitializeSSL();
	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &iSetOption, sizeof (iSetOption));
	tentacleExtremity.sin_family = AF_INET;
	tentacleExtremity.sin_addr.s_addr = inet_addr(ip);
	tentacleExtremity.sin_port = htons(port);


	if (connect(sock, (struct sockaddr*) &tentacleExtremity, sizeof (tentacleExtremity)) != 0) {
		snprintf(errBuf,BUFSIZ,"commander:commanderRun : unable to perform connect : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		return -1;
	}

	logError(LOG_LEVEL_DEBUG,"commander:commanderRun : Connected to remote");

	sslctx = SSL_CTX_new(SSLv3_client_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);


	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sock);
	ssl_err = SSL_connect(cSSL);

	if (ssl_err != 1) {
		getSSLerr(SSL_get_error(cSSL,ssl_err));
		ShutdownSSL(cSSL);
	}

	logError(LOG_LEVEL_DEBUG,"commander:commanderRun : SSL established");

	if(sendMsg(cSSL,"LO_TENTACLE\n") == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(getMsg(cSSL,buf,"LO_BRAIN") != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	if(sendMsg(cSSL,"GIVE_ID\n") == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"ID:%d",id);
	if(getMsg(cSSL,buf,cmpBuf) != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"KEY:%d\n",key);
	if(sendMsg(cSSL,cmpBuf) == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(getMsg(cSSL,buf,"KEY_OK") != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"RUN:%s\n",script);
	if(sendMsg(cSSL,cmpBuf) == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"RUNNING:%s",script);
	if(getMsg(cSSL,buf,cmpBuf) != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}

	return 0;
}
int commanderCpyScript(char *ip, int port, int key, int id, char *script, char *content){
	int sock, iSetOption = 1, ssl_err;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char buf[BUFSIZ],errBuf[BUFSIZ],cmpBuf[BUFSIZ];
	struct sockaddr_in tentacleExtremity;

	if(ip == NULL || script == NULL){
		logError(LOG_LEVEL_ERROR,"commander:commanderRun : ip or script NULL, abort.");
		return -1;
	}
	sprintf(errBuf,"commander:commanderRun : contacting %s:%d",ip,port);
	logError(LOG_LEVEL_DEBUG,errBuf);

	InitializeSSL();
	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &iSetOption, sizeof (iSetOption));
	tentacleExtremity.sin_family = AF_INET;
	tentacleExtremity.sin_addr.s_addr = inet_addr(ip);
	tentacleExtremity.sin_port = htons(port);


	if (connect(sock, (struct sockaddr*) &tentacleExtremity, sizeof (tentacleExtremity)) != 0) {
		snprintf(errBuf,BUFSIZ,"commander:commanderRun : unable to perform connect : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		return -1;
	}

	logError(LOG_LEVEL_DEBUG,"commander:commanderRun : Connected to remote");

	sslctx = SSL_CTX_new(SSLv3_client_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);


	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sock);
	ssl_err = SSL_connect(cSSL);

	if (ssl_err != 1) {
		getSSLerr(SSL_get_error(cSSL,ssl_err));
		ShutdownSSL(cSSL);
	}

	logError(LOG_LEVEL_DEBUG,"commander:commanderRun : SSL established");

	if(sendMsg(cSSL,"LO_TENTACLE\n") == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(getMsg(cSSL,buf,"LO_BRAIN") != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	if(sendMsg(cSSL,"GIVE_ID\n") == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"ID:%d",id);
	if(getMsg(cSSL,buf,cmpBuf) != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"KEY:%d\n",key);
	if(sendMsg(cSSL,cmpBuf) == -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(getMsg(cSSL,buf,"KEY_OK") != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"ADD:%s\n",script);
	if(sendMsg(cSSL,cmpBuf) ==  -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	snprintf(cmpBuf,BUFSIZ,"LISTENNING:%s",script);
	if(getMsg(cSSL,buf,cmpBuf) != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
 	}
	if(sendMsg(cSSL,content) ==  -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(sendMsg(cSSL,"EOF") ==  -1){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : couldn't send message.");
		return -1;
	}
	if(getMsg(cSSL,buf,"OK_EOF") != 0){
		logError(LOG_LEVEL_INFO,"commander:commanderRun : received unvalid message.");
		return -1;
 	}

	logError(LOG_LEVEL_INFO,"Script sent.\n");

	return 0;
}
