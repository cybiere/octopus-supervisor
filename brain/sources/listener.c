#include "../headers/listener.h"
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
#include <dirent.h>
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

int saveWorker(int sock,int listen, int speak){
	struct sockaddr_in callerExtremity;
	int service, ssl_err, ret;
	int len = sizeof(callerExtremity);
	SSL_CTX *sslctx;
	SSL *cSSL;
	char bufIn[BUFSIZ],*idStr, bufOut[BUFSIZ],*keyStr, *date, *script, *tok, *content=NULL,*report;
	int contentSize=0,flag=0;

	InitializeSSL();

	service = accept(sock, (struct sockaddr *) &callerExtremity, (socklen_t *) &len);
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

	if(getMsg(cSSL,bufIn,"LO_BRAIN") != 0){ ShutdownSSL(cSSL); close(service); return 0; }
	if(sendMsg(cSSL,"LO_TENTACLE\n") == -1){ ShutdownSSL(cSSL); close(service); return 0; }
	if(getMsg(cSSL,bufIn,"PLS_SAVE_REPORT") != 0){ ShutdownSSL(cSSL); close(service); return 0; }
	if(sendMsg(cSSL,"GIVE_ID\n") == -1){ ShutdownSSL(cSSL); close(service); return 0; }
	if(getMsg(cSSL,bufIn,NULL) !=0){ ShutdownSSL(cSSL); close(service); return 0; }

	if(strncmp(bufIn,"ID:",3) !=0){ ShutdownSSL(cSSL); close(service); return 0; }
	idStr = bufIn+3;
	idStr = (char *)malloc(strlen(bufIn+3));
	strcpy(idStr,bufIn+3);
	snprintf(bufOut,BUFSIZ,"SEARCHKEY:%s",idStr);
	write(speak,bufOut,strlen(bufOut));
	bzero(bufIn,BUFSIZ);
	read(listen,bufIn,BUFSIZ);

	if(strcmp(bufIn,"ERROR") == 0){ ShutdownSSL(cSSL); close(service); return 0; }
	keyStr = (char *)malloc(strlen(bufIn));
	strcpy(keyStr,bufIn);

	snprintf(bufOut,BUFSIZ,"KEY:%s\n",keyStr);
	if(sendMsg(cSSL,bufOut) == -1){ ShutdownSSL(cSSL); close(service); return 0; }
	if(getMsg(cSSL,bufIn,"OK") != 0){ ShutdownSSL(cSSL); close(service); return 0; }
	if(sendMsg(cSSL,"OK\n") == -1){ ShutdownSSL(cSSL); close(service); return 0; }

	if(getMsg(cSSL,bufIn,NULL) !=0){ ShutdownSSL(cSSL); close(service); return 0; }
	if(strncmp(bufIn,"RET:",4) !=0){ ShutdownSSL(cSSL); close(service); return 0; }
	strtok(bufIn+4,"/");
	tok = strtok(NULL,"-");
	if(tok == NULL){ ShutdownSSL(cSSL); close(service); return 0; }
	date = (char *)malloc(strlen(tok));
	strcpy(date,tok);
	tok = strtok(NULL,"-");
	if(tok == NULL){ ShutdownSSL(cSSL); close(service); return 0; }
	script = (char *)malloc(strlen(tok));
	strcpy(script,tok);
	if(sendMsg(cSSL,"OK\n") == -1){ ShutdownSSL(cSSL); close(service); return 0; }


	do{
		contentSize++;
		content = (char *)realloc(content,contentSize*BUFSIZ);
		if(!flag){content[0] = '\0'; flag=1;}
		bzero(bufIn,BUFSIZ);
		ret = SSL_read(cSSL,bufIn,BUFSIZ);
		if(ret <= 0){
			getSSLerr(SSL_get_error(cSSL,ret));
			close(service);
			ShutdownSSL(cSSL);
			return 0;
		}
		flag = strcmp(bufIn,"EOF");
		if(flag) strcat(content,bufIn);
	}while(flag);

	sendMsg(cSSL, "OK_EOF\n");

	contentSize = BUFSIZ+strlen(content);
	report = (char *)malloc(contentSize);
	snprintf(report,contentSize,"WRITE:%s:%s:%s:%s",idStr,date,script,content);
	write(speak, report,strlen(report));

	free(idStr);
	free(keyStr);
	free(date);
	free(script);
	free(content);
	free(report);
	ShutdownSSL(cSSL);
	
	return 0;
}

int saveRapports(int port, int listenPipe[2], int speakPipe[2]){
	int sock;
	sock=create_listenSock(port);

	close(listenPipe[1]);
	close(speakPipe[0]);

	while (1){
		saveWorker(sock,listenPipe[0],speakPipe[1]);
	}
}
