#include "../headers/registerer.h"
#include "../headers/fct.h"
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

int registerCommon(SSL *cSSL,int id, char *hostname,char **scripts){
	int gotKey;
	char bufIn[BUFSIZ],bufOut[BUFSIZ],*tmp;

	sprintf(bufOut,"ID:%d\n",id);
	if(sendMsg(cSSL,bufOut) == -1) return 0;

	sprintf(bufOut,"OK:%d:HOSTNAME:",id);
	if(getMsg(cSSL,bufIn,NULL) != 0) return 0;
	if(strncmp(bufIn,bufOut,strlen(bufOut)) != 0){
		logError(LOG_LEVEL_INFO,"registerer:registerCommon : received unvalid message.");
		ShutdownSSL(cSSL);
		return 0;
	}
	tmp = bufIn+strlen(bufOut);
	strcpy(hostname,tmp);

	sprintf(bufOut,"OK:%s\n",hostname);
	if(sendMsg(cSSL,bufOut) == -1){
		ShutdownSSL(cSSL);
		return 0;
	}

	if(getMsg(cSSL,bufIn,NULL) != 0) return 0;
	if(strncmp(bufIn,"KEY:",4) != 0){
		logError(LOG_LEVEL_INFO,"registerer:registerCommon : received unvalid message.");
		return 0;
	}
	tmp = bufIn+4;
	sscanf(tmp,"%d",&gotKey);

	sprintf(bufOut,"OK:%d\n",gotKey);
	if(sendMsg(cSSL,bufOut) == -1) return 0;

	if(getMsg(cSSL,bufIn,NULL) != 0) return 0;
	if(strncmp(bufIn,"SCRIPTS:",8) != 0){
		logError(LOG_LEVEL_INFO,"registerer:registerCommon : received unvalid message.");
		return 0;
	}
	tmp = bufIn+8;
	*scripts = (char *)malloc(strlen(tmp)+1);
	strcpy(*scripts,tmp);
	logError(LOG_LEVEL_DEBUG,"registerer:registerCommon : received scripts");

	sprintf(bufOut,"OKSCRIPTS\n");
	if(sendMsg(cSSL,bufOut) == -1) return 0;


	ShutdownSSL(cSSL);

	return gotKey;
}

int registerer_daemon(int port, int listenPipe[2],int speakPipe[2]){
	int sock,ret,key,id;
	int service,len,ssl_err;
	char buf[BUFSIZ],*ptr, errBuf[BUFSIZ];
	SSL_CTX *sslctx;
	SSL *cSSL;
	struct sockaddr_in callerExtremity;
	len = sizeof(callerExtremity);
	InitializeSSL();
	sock = create_listenSock(port);

	close(listenPipe[1]);
	close(speakPipe[0]);

	while(1){
		char *hostname;
		service = accept(sock,(struct sockaddr *) &callerExtremity,(socklen_t *) &len);
		sslctx = SSL_CTX_new(SSLv23_server_method());
		SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
		SSL_CTX_use_certificate_file(sslctx, "/etc/octopus/brain/cert.pem", SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(sslctx, "/etc/octopus/brain/key.pem", SSL_FILETYPE_PEM);
		cSSL = SSL_new(sslctx);
		SSL_set_fd(cSSL, service);
		ssl_err = SSL_accept(cSSL);
		if (ssl_err != 1) {
			getSSLerr(SSL_get_error(cSSL,ssl_err));
			ShutdownSSL(cSSL);
		}
		if(getMsg(cSSL,buf,"LO_BRAIN") != 0) return 0;
		if(sendMsg(cSSL,"LO_TENTACLE\n") == -1) return 0;
		if(getMsg(cSSL,buf,"PLS_REG") != 0) return 0;

		write(speakPipe[1],"GET_TENTACLE_ID",strlen("GET_TENTACLE_ID"));
		bzero(buf,BUFSIZ);
		logError(LOG_LEVEL_DEBUG,"registerer:registerDaemon : asking maestro for id");
		if(read(listenPipe[0],buf,BUFSIZ) <= 0){
			snprintf(errBuf,BUFSIZ,"registerer:registerDaemon : reading id : %s",strerror(errno));
			logError(LOG_LEVEL_ERROR,errBuf);
			return -1;
		}
		ptr = strstr(buf,":");
		ptr++;
		if(ptr == NULL){
			logError(LOG_LEVEL_ERROR,"registerer:registerDaemon : wrong message from maestro (NULL)");
		}else{
			if(sscanf(ptr,"%d",&id) == 0){
				logError(LOG_LEVEL_ERROR,"registerer:registerDaemon : wrong message from maestro (NO ID)");
			}else{
				char errBuf[BUFSIZ],*scripts;
				sprintf(errBuf,"registerer:registerDaemon : maestro gave id %d",id);
				logError(LOG_LEVEL_DEBUG,errBuf);
				hostname = (char *)malloc(BUFSIZ);
				key = registerCommon(cSSL,id,hostname,&scripts);
				sprintf(errBuf,"registerer:registerDaemon : registerCommon returned key %d",key);
				logError(LOG_LEVEL_DEBUG,errBuf);
				if(key != 0){
					sprintf(errBuf,"registerer:registerDaemon : Registerer New tentacle \"%s\" with id %d and key %d at ip %s",hostname,id,key,inet_ntoa(callerExtremity.sin_addr));
					logError(LOG_LEVEL_INFO,errBuf);
					bzero(buf,BUFSIZ);
					sprintf(buf,"REGISTERED:%s:%d:%d:%s:SCRIPTS:%s",inet_ntoa(callerExtremity.sin_addr),id,key,hostname,scripts);
					ret = write(speakPipe[1],buf,strlen(buf));
					logError(LOG_LEVEL_DEBUG,"registerer:registerDaemon : Registering message sent to maestro");



					free(scripts);
					if(ret < 0){
						snprintf(errBuf,BUFSIZ,"registerer:registerDaemon : writing maestro : %s",strerror(errno));
						logError(LOG_LEVEL_ERROR,errBuf);
						free(hostname);
						return -1;
					}
				}
			}
			free(hostname);
		}
	}
	return -1;
}

int registerer_run(const char *tentacleIp,int tentaclePort, int id, char *hostname,char **scripts){
	int sock, iSetOption = 0, ssl_err, key;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char buf[BUFSIZ],errBuf[BUFSIZ];
	struct sockaddr_in tentacleExtremity;

	sprintf(errBuf,"registerer:registerRun : contacting %s:%d",tentacleIp,tentaclePort);
	logError(LOG_LEVEL_DEBUG,errBuf);

	InitializeSSL();
	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &iSetOption, sizeof (iSetOption));
	tentacleExtremity.sin_family = AF_INET;
	tentacleExtremity.sin_addr.s_addr = inet_addr(tentacleIp);
	tentacleExtremity.sin_port = htons(tentaclePort);


	if (connect(sock, (struct sockaddr*) &tentacleExtremity, sizeof (tentacleExtremity)) != 0) {
		snprintf(errBuf,BUFSIZ,"registerer:registerRun : unable to perform connect : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		return -1;
	}

	logError(LOG_LEVEL_DEBUG,"registerer:registerRun : Connected to remote");

	sslctx = SSL_CTX_new(SSLv3_client_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);


	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sock);
	ssl_err = SSL_connect(cSSL);

	if (ssl_err != 1) {
		getSSLerr(SSL_get_error(cSSL,ssl_err));
		ShutdownSSL(cSSL);
	}

	logError(LOG_LEVEL_DEBUG,"registerer:registerRun : SSL established");

	if(sendMsg(cSSL,"LO_TENTACLE\n") == -1){
		logError(LOG_LEVEL_INFO,"registerer:registerRun : received unvalid message.");
		return 0;
	}
	if(getMsg(cSSL,buf,"LO_BRAIN") != 0){
		logError(LOG_LEVEL_INFO,"registerer:registerRun : received unvalid message.");
		return 0;
	}
	key = registerCommon(cSSL,id,hostname,scripts);
	
	sprintf(errBuf,"registerer:registerRun : registerCommon returned key %d",key);
	logError(LOG_LEVEL_DEBUG,errBuf);
	return key;
}


