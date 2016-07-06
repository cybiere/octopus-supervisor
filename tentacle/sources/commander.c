#include "../headers/commander.h"
#include "../headers/fct.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
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
#include <dirent.h>
#include <strings.h>

#define SUCCESS 0
#define ERR_DEFAULT -1
#define ERR_SCK_SCK -2
#define ERR_SCK_OPT -3
#define ERR_SCK_BND -4
#define ERR_SCK_LSN -5
#define ERR_SCK_ACT -6
#define ERR_THR_ATT -7
#define ERR_THR_DTC -8
#define ERR_THR_CRT -9



#define WORKER_CONTINUE 1
#define WORKER_ABORT 0

typedef struct{
	int id;
	int key;
	int retPort;
	int socket;
	struct sockaddr *brain;
}threadParam;


void listScripts(char *outFile){
	FILE *out;
	char *scripts;
	out = fopen(outFile,"w");
	scripts = list();
	fprintf(out,"%s",scripts);		
	free(scripts);
	fclose(out);
}

void addScript(char *name,char *content){
	int fd;
	char path[BUFSIZ];
	strcpy(path,"/usr/share/octopus/tentacle/scripts/");
	strcat(path,name);
	strcat(path,".sh");
	fd = open(path,O_WRONLY|O_CREAT|O_TRUNC,S_IRWXU|S_IRGRP);
	if(fd == -1){
		logError(LOG_LEVEL_ERROR,"commander:addScript : error openning file");
		return;
	}
	for(;*content!='#';content++);
	write(fd,content,strlen(content));
	write(fd,"\n",1);
	close(fd);
}

char *getCmd(SSL* cSSL,int id,int key){
	char bufIn[BUFSIZ], bufOut[BUFSIZ], *tmp, *cmd;

	if(getMsg(cSSL,bufIn,"LO_TENTACLE") != 0) return NULL;
	if(sendMsg(cSSL,"LO_BRAIN\n") == -1) return NULL;
	if(getMsg(cSSL,bufIn,"GIVE_ID") != 0) return NULL;

	sprintf(bufOut,"ID:%d\n",id);
	if(sendMsg(cSSL,bufOut) == -1) return NULL;

	sprintf(bufOut,"KEY:%d",key);
	if(getMsg(cSSL,bufIn,bufOut) != 0) return NULL;

	sprintf(bufOut,"KEY_OK\n");
	if(sendMsg(cSSL,bufOut) == -1) return NULL;

	if(getMsg(cSSL,bufIn,NULL) != 0) return NULL;
	tmp = bufIn + 4;
	if(strncmp(bufIn,"ADD",3) == 0){
		char *content=NULL, *name=NULL;
		int contentSize=0,flag = 1,ret;

		name = (char *)malloc(strlen(tmp)+1);
		strcpy(name,tmp);

		sprintf(bufOut,"LISTENNING:%s\n",name);
		if(sendMsg(cSSL,bufOut) == -1) return NULL;
		do{
			contentSize++;
			content = (char *)realloc(content,contentSize*BUFSIZ);
			bzero(bufIn,BUFSIZ);
			ret = SSL_read(cSSL,bufIn,BUFSIZ);
			if(ret <= 0){
				getSSLerr(SSL_get_error(cSSL,ret));
				ShutdownSSL(cSSL);
				return NULL;
			}
			flag = strcmp(bufIn,"EOF");
			if(flag) strcat(content,bufIn);
		}while(flag);


		if(sendMsg(cSSL,"OK_EOF") == -1) return NULL;

		addScript(name,content);

		free(content);
		free(name);
		return NULL;
	}
	cmd = (char *)malloc(strlen(tmp)+1);
	strcpy(cmd,tmp);


	return cmd;
}

void sendResult(int id, int key, int retPort, char *outFile, struct sockaddr *brain){
	int sock, iSetOption = 1, ssl_err;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char bufIn[BUFSIZ],bufOut[BUFSIZ],*needle;
	struct sockaddr_in brainExtremity;
	FILE *file;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &iSetOption, sizeof (iSetOption));
	((struct sockaddr_in *)brain)->sin_port = htons(retPort);

	if (connect(sock, brain, sizeof (brainExtremity)) != 0) {
		logError(LOG_LEVEL_ERROR,"commander:sendResult : couldn't connect to brain");
		return;
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

	if(sendMsg(cSSL,"LO_BRAIN\n") == -1) return;
	if(getMsg(cSSL,bufIn,"LO_TENTACLE") != 0) return;
	if(sendMsg(cSSL, "PLS_SAVE_REPORT\n") == -1) return;
	if(getMsg(cSSL, bufIn, "GIVE_ID") != 0) return;

	sprintf(bufOut,"ID:%d\n",id);
	if(sendMsg(cSSL,bufOut) == -1) return;

	sprintf(bufOut,"KEY:%d",key);
	if(getMsg(cSSL,bufIn,bufOut) != 0) return;
	if(sendMsg(cSSL, "OK") == -1) return;
	if(getMsg(cSSL, bufIn, "OK") != 0) return;
	
	needle = strstr(outFile,"results");
	sprintf(bufOut,"RET:%s\n",needle);
	if(sendMsg(cSSL,bufOut) == -1) return;

	if(getMsg(cSSL,bufIn,"OK") != 0) return;

	file = fopen(outFile,"r");
	if(file == NULL){
		return;
	}

	bzero(bufOut,BUFSIZ);
	while(fgets(bufOut,BUFSIZ-1,file)){
		if(sendMsg(cSSL,bufOut) == -1) return;
	}

	if(sendMsg(cSSL, "EOF") == -1) return;
	if(getMsg(cSSL,bufIn,"OK_EOF") != 0) return;
	ShutdownSSL(cSSL);
	close(sock);
}

void *commandWorker(void *param){
	int sockService, ssl_err,id,retPort,key, found,ret,fd;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char *cmd, outFile[BUFSIZ], *script, bufOut[BUFSIZ], *scripts,errBuf[BUFSIZ];
	threadParam *data;
	struct tm *now;
	time_t tps;
	struct sockaddr *brain;
	pid_t pid;

	logError(LOG_LEVEL_DEBUG,"commander:commandWorker : In thread");

	data = (threadParam *)param;
	sockService = data->socket;
	id = data->id;
	retPort = data->retPort;
	brain = data->brain;
	key = data->key;

	snprintf(errBuf,BUFSIZ,"Connection on fd %d",sockService);
	logError(LOG_LEVEL_DEBUG,errBuf);

	sslctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_use_certificate_file(sslctx, "/etc/octopus/tentacle/cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(sslctx, "/etc/octopus/tentacle/key.pem", SSL_FILETYPE_PEM);
	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sockService);
	ssl_err = SSL_accept(cSSL);
	if (ssl_err != 1) {
		SSL_get_error(cSSL, ssl_err);
		ShutdownSSL(cSSL);
	}

	cmd = getCmd(cSSL,id,key);
	if(cmd == NULL){
		pthread_exit(NULL);
	}
	tps = time(NULL);
	now = localtime(&tps);
	sprintf(outFile,"/usr/share/octopus/tentacle/results/%04d%02d%02d%02d%02d%02d-%s",now->tm_year+1900,now->tm_mon+1,now->tm_mday,now->tm_hour,now->tm_min,now->tm_sec,cmd);
	
	if(strcmp("listscripts",cmd) == 0){
		listScripts(outFile);
		sprintf(bufOut,"RUNNING:%s\n",cmd);
		if(sendMsg(cSSL,bufOut) == -1) return NULL;
		ShutdownSSL(cSSL);
		close(sockService);
	}
	else{
		found = 0;
		scripts = list();
		script = strtok(scripts,":");
		while(found == 0 && script != NULL){
			if(strcmp(script,cmd) == 0){
				found = 1;
			}
			script = strtok(NULL,":");
		}
		free(scripts);
		if(found == 0){
			sprintf(bufOut,"NOTFOUND:%s\n",cmd);
			if(sendMsg(cSSL,bufOut) == -1) return NULL;
			ShutdownSSL(cSSL);
			close(sockService);
			snprintf(errBuf,BUFSIZ,"commander:commandWorker : script %s not found",cmd);
			logError(LOG_LEVEL_WARNING,errBuf);
			return NULL;
		}else{
			sprintf(bufOut,"RUNNING:%s\n",cmd);
			if(sendMsg(cSSL,bufOut) == -1) return NULL;

			ShutdownSSL(cSSL);
			close(sockService);
			

			snprintf(errBuf,BUFSIZ,"commander:commandWorker : script %s lauched\n",cmd);
			logError(LOG_LEVEL_INFO,errBuf);
			pid = fork();
			switch(pid){
				case -1:
					logError(LOG_LEVEL_CRITICAL,"commander : Fork failure");
					return NULL;
					break;
				case 0:
					fd = open(outFile,O_CREAT | O_WRONLY | O_TRUNC,0644);
					if(fd == -1){
						return NULL;
					}
					strcpy(bufOut,"/usr/share/octopus/tentacle/scripts/");
					strcat(bufOut,cmd);
					strcat(bufOut,".sh");
					ret = dup2(fd,STDOUT_FILENO);
					if(ret == -1){
						return NULL;
					}
					ret = dup2(fd,STDERR_FILENO);
					if(ret == -1){
						return NULL;
					}
					
					ret = execl(bufOut,cmd,(char*)NULL);
					if(ret == -1){
						return NULL;
					}
					break;
				default:
					waitpid(pid,NULL,0);
					break;
			}
		}
	}
	sendResult(id,key,retPort,outFile,brain);
	free(cmd);
	pthread_exit(NULL);
}


int connectionWorker(int listenSocket,int tentacleId, char *brainIp, int brainKey, int returnPort){
	struct sockaddr *callerExtremity;
	int service,len;
	threadParam *data;
	pthread_t tid;
	pthread_attr_t attr;
	char *ip;
	logError(LOG_LEVEL_DEBUG,"commander:connectionWorker : I'm in !");
	if(pthread_attr_init(&attr) != 0){
		close(listenSocket);
		return WORKER_ABORT;
	}

	if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0){
		close(listenSocket);
		return WORKER_ABORT;
	}
	callerExtremity = (struct sockaddr *)malloc(sizeof(struct sockaddr));
	len = sizeof (struct sockaddr);
	logError(LOG_LEVEL_DEBUG,"commander:connectionWorker : just before accept");
	service = accept(listenSocket,callerExtremity, (socklen_t *) & len);
	logError(LOG_LEVEL_DEBUG,"commander:connectionWorker : just after accept !");
	if(service < 0){
		close(listenSocket);
		return WORKER_ABORT;
	}

	ip = inet_ntoa(((struct sockaddr_in *)callerExtremity)->sin_addr);
	if(strncmp(brainIp,ip,strlen(brainIp)) != 0){
		logError(LOG_LEVEL_WARNING,"commander:threadWorker : connection from unknown IP");
		close(service);
		return WORKER_CONTINUE;
	}
	data = (threadParam *)malloc(sizeof(threadParam));
	data->socket = service;
	data->id = tentacleId;
	data->key = brainKey;
	data->retPort = returnPort;
	data->brain = callerExtremity;
	logError(LOG_LEVEL_DEBUG,"commander:connectionWorker : before thread!");
	if(pthread_create(&tid,&attr,commandWorker,(void *)data)){
		close(listenSocket);
		close(service);
		return WORKER_ABORT;
	}
	return WORKER_CONTINUE;
}

int commander_sendAllResults(int tentacleId, int brainKey, char *brainIp, int returnPort){ 
	DIR *dir;
	struct dirent *entry;
	char buffer[BUFSIZ];
	struct sockaddr_in brain;


	brain.sin_family = AF_INET;
	brain.sin_addr.s_addr = inet_addr(brainIp);
	brain.sin_port = htons(returnPort);

	dir = opendir("/usr/share/octopus/tentacle/results");
	entry = readdir(dir);
	while(entry != NULL){
		if(entry->d_name[0] != '.'){
			bzero(buffer,BUFSIZ);
			snprintf(buffer,BUFSIZ,"/usr/share/octopus/tentacle/results/%s",entry->d_name);
			sendResult(tentacleId, brainKey, returnPort, buffer,(struct sockaddr *)&brain);
 		}
		entry = readdir(dir);
 	}


	return 0;
}
int commander_run(int tentacleId, int brainKey, char *brainIp, int cmdPort, int returnPort){ 
	int sock;
	sock = create_listenSock(cmdPort);
	while(connectionWorker(sock,tentacleId,brainIp,brainKey,returnPort) != WORKER_ABORT);
	return EXIT_FAILURE;
}


