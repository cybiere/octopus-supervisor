#include "../headers/webServ.h"
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
#include <ctype.h>

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


int read_get(SSL* cSSL, char* url, int size){
	char buf[4096];
	int i,j,ret;
	ret = SSL_read(cSSL,buf,4096);
	if(ret <= 0){
		return ERR_DEFAULT;
	}
	for(i=0;i<4096 && buf[i] != '\r';i++); buf[i] = '\0';
	if (strncmp(buf, "GET", 3)){
		logError(LOG_LEVEL_ERROR,"webserver:readget : request type is not GET");
		return ERR_DEFAULT;
	}
	for (i=3; buf[i]==' '; i++);
	if (!strncmp(buf+i, "https://", 8)) i+=8;
	for (; buf[i] && buf[i]!='/'; i++);
	if (buf[i]=='/') i++;
	for (j=0; buf[i] && buf[i]!=' ' && j<size-1; j++, i++) url[j] = buf[i];
	url[j] = 0;
	for (; buf[i]==' '; i++);
	if (strncmp(buf+i, "HTTP/1.1", 8)){
		logError(LOG_LEVEL_ERROR,"webserver:readget : protocol is not HTTP/1.1");
		return ERR_DEFAULT;
	}
	return SUCCESS;
}
char* fileType(char* url){
	int len = strlen(url);
	if (!strcasecmp(url+len-5, ".html") ||
			!strcasecmp(url+len-4, ".htm")) return "text/html";
	if (!strcasecmp(url+len-4, ".css")) return "text/css";
	if (!strcasecmp(url+len-3, ".js")) return "text/javascript";
	if (!strcasecmp(url+len-4, ".png")) return "image/png";
	if (!strcasecmp(url+len-4, ".gif")) return "image/gif";
	if (!strcasecmp(url+len-5, ".jpeg") ||
			!strcasecmp(url+len-4, ".jpg")) return "image/jpeg";
	return "text/ascii";
}
int response404(char** response){
	*response = (char *)calloc(1024,sizeof(char));
	strcat(*response, "HTTP/1.1 404 Not found\r\n");
	strcat(*response, "Connection: close\r\n");
	strcat(*response, "Content-type: text/html\r\n");
	strcat(*response, "\r\n");
	strcat(*response, 
			"<html><head><title>Not Found</title></head>"
			"<body><p>Sorry, the object you requested was not found</p> "
			"</body></html>\r\n");
	return strlen(*response);
}
int sendFile(char **response, char* url){
	char modiftime[30], *tmp, curtime[30], errBuf[BUFSIZ];
	struct timeval  tv;
	char buf[4096];
	char extPath[4096];
	int freeSpace;
	struct stat s;
	int fd,len,ret,i;
	if (strstr(url,"..")) { return response404(response); }
	strcpy(extPath,"/usr/share/octopus/brain/web/");
	strcat(extPath,url);
	fd = open(extPath, O_RDONLY);
	if (fd==-1) { return response404(response); }
	if (fstat(fd, &s)==-1 || !S_ISREG(s.st_mode) || !(s.st_mode & S_IROTH))
	{
		logError(LOG_LEVEL_WARNING,"Can't read requested file (404 or 403).");
		close(fd);
		return response404(response);
	}

	if (gettimeofday(&tv, NULL) ||
			!ctime_r(&s.st_mtime, modiftime) ||
			!ctime_r(&tv.tv_sec, curtime))
	{
		logError(LOG_LEVEL_WARNING,"Error with gettimeofday.");
		close(fd);
		return response404(response);
	}  
	*response = (char *)calloc(512,sizeof(char));
	freeSpace = 512;
	modiftime[strlen(modiftime)-1] = 0; 
	curtime[strlen(curtime)-1] = 0;     
	strcat(*response, "HTTP/1.1 200 OK\r\n");
	strcat(*response, "Connection: close\r\n");
	sprintf(buf, "Content-length: %li\r\n", (long)s.st_size);
	strcat(*response,buf);
	sprintf(buf, "Content-type: %s\r\n", fileType(url));
	strcat(*response,buf);
	sprintf(buf, "Date: %s\r\n", curtime);
	strcat(*response,buf);
	sprintf(buf, "Last-modified: %s\r\n", modiftime);
	strcat(*response,buf);
	strcat(*response, "\r\n");
	len = strlen(*response);
	freeSpace -=len;

	ret = read(fd, buf, sizeof(buf));
	while (ret > 0) {
		for(i=0;i<ret;i++){
			if(freeSpace == 1){
				tmp = (char *)realloc(*response,len+i+512);
				if(tmp == NULL){
					free(*response);
					logError(LOG_LEVEL_CRITICAL,"webserver:sendFile : realloc failure");
					exit(EXIT_FAILURE);
				}
				*response = tmp;
				freeSpace +=512;
			}
			(*response)[len+i] = buf[i];
			freeSpace--;
		}
		(*response)[len+i+1] = 0;
		len+=i;
		ret = read(fd, buf, sizeof(buf));
	}
	(*response)[len] = 0;
	if (ret<0) {
		snprintf(errBuf,BUFSIZ,"webserver:sendFile : error in read : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		close(fd);
	}
	snprintf(errBuf,BUFSIZ,"webserver:sendFile : sent file %s",url);
	logError(LOG_LEVEL_DEBUG,errBuf);
	return len;
}
int responsePage(char** response, char* url){
	return sendFile(response,url);
}

int responseAjaxFail(char **response){
	*response = (char *)calloc(1024,sizeof(char));
	strcat(*response, "HTTP/1.1 200 OK\r\n");
	strcat(*response, "Connection: close\r\n");
	strcat(*response, "Content-type: application/json\r\n");
	strcat(*response, "\r\n");
	strcat(*response, 
			"{\"success\":false}");
	return strlen(*response);
}
int responseAjaxLogout(char **response){
	*response = (char *)calloc(1024,sizeof(char));
	strcat(*response, "HTTP/1.1 200 OK\r\n");
	strcat(*response, "Connection: close\r\n");
	strcat(*response, "Content-type: application/json\r\n");
	strcat(*response, "\r\n");
	strcat(*response, 
			"{\"success\":\"logout\"}");
	return strlen(*response);
}
char ***parseArgs(char *paramStr, int *nbParam){
	char *p=paramStr,*r;
	char *key=NULL,*val=NULL,**param=NULL;
	char ***args = NULL;
	int s=0,i;
	*nbParam = 0;
	while(*p != '\0'){
		p++;
		r=p;
		s=0;
		for(;*p!='=' && *p != '\0';p++){
			s++;
		}
		key = (char *)calloc(s+1,sizeof(char));
		for(i=0;i<s;i++)
			key[i] = r[i];
		key[s] = '\0';
		if(*p == '\0') return args;
		p++;
		r=p;
		s=0;
		for(;*p!='&' && *p!='\0' ;p++){
			s++;
		}
		if(s!=0){
			val = (char *)calloc(s+1,sizeof(char));
			for(i=0;i<s;i++) val[i] = r[i];
			val[s] = '\0';
			param = (char **)malloc(sizeof(char *)*2);
			param[0] = key;
			param[1] = val;
			(*nbParam)++;
			args = (char ***)realloc(args,(*nbParam)*sizeof(char **));
			args[(*nbParam)-1] = param;
		}
	}
	return args;

}
void freeArgs(char ***args, int nbParam){
	int i;
	for(i=0;i<nbParam;i++){
		free(args[i][0]);
		free(args[i][1]);
		free(args[i]);
	}
	free(args);
}
char *getArgValue(char ***args,char *key,int nbParam){
	int i;
	for(i=0;i<nbParam;i++){
		if(strcmp(args[i][0],key)==0)
			return args[i][1];
	}
	return NULL;
}

int responseService(char** response, char* url,int listenpipe, int speakpipe){
	char *paramStr,***args,*action;
	char buffer[BUFSIZ], bufIn[BUFSIZ], errBuf[BUFSIZ];
	int paramStrLen,nbParam;


	bzero(buffer,BUFSIZ);
	bzero(bufIn,BUFSIZ);

	paramStr = strstr(url,"?");
	if(paramStr == NULL) return responseAjaxFail(response);
	paramStrLen = strlen(paramStr);
	if(paramStrLen <= 1) return responseAjaxFail(response);
	args=parseArgs(paramStr,&nbParam);
	sprintf(errBuf,"webserver:responseService : %d parameters read",nbParam);
	logError(LOG_LEVEL_DEBUG,errBuf);
	if(nbParam == 0){ freeArgs(args,nbParam); return responseAjaxFail(response); }
	action = getArgValue(args,"action",nbParam);
	if(action == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
	snprintf(errBuf,BUFSIZ,"webserver:responseService : action %s read",action);
	logError(LOG_LEVEL_DEBUG,errBuf);

	if(strcmp(action,"addtentacle")==0){
		char *key, *uid, *ip;

		ip =  getArgValue(args,"ip",nbParam);
		if(ip == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }


		sprintf(buffer,"REGISTER:%s:%s:%s",ip,key,uid);
		write(speakpipe,buffer,strlen(buffer));
		read(listenpipe,bufIn,BUFSIZ);
		if(strcmp(buffer,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(buffer,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)calloc(1024,sizeof(char));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		strcat(*response, "{\"success\":true}");
		freeArgs(args,nbParam);
		return strlen(*response);

	}
	else if(strcmp(action,"addscript") == 0){
		char *name, *content, *clearContent, *uid, *key;
		name = getArgValue(args,"name",nbParam);
		if(name == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		content = getArgValue(args,"content",nbParam);
		if(content == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		clearContent = url_decode(content);
		content = url_encode(clearContent);
		snprintf(buffer,BUFSIZ,"ADDSCRIPT:%s:%s:%s:%s",uid,key,name,content);
		write(speakpipe,buffer,strlen(buffer));
		free(clearContent);
		free(content);
		freeArgs(args,nbParam); 

		read(listenpipe,buffer,BUFSIZ);
		if(strcmp(buffer,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(buffer,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		*response = (char *)malloc(BUFSIZ);
		bzero(*response,BUFSIZ);
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true}");
		strcat(*response, buffer);
		return strlen(*response);
	}
	else if(strcmp(action,"login") == 0){
		char *login, *pw, *id, *key;
		login = getArgValue(args,"login",nbParam);
		if(login == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		pw = getArgValue(args,"pw",nbParam);
		if(pw == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		sprintf(buffer,"CONNECT:%s:%s",login,pw);
		write(speakpipe,buffer,strlen(buffer));
		read(listenpipe,bufIn,BUFSIZ);
		if(strcmp(bufIn,"CONNECTION_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		id = strstr(bufIn,":");
		if(id == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		id++;
		key = strstr(id,":");
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		*key = 0;
		key++;

		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)calloc(1024,sizeof(char));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true,\"id\":%s,\"login\":\"%s\",\"key\":%s}",id,login,key);
		strcat(*response, buffer);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"gettentacles") == 0){
		char *tentacles, *key, *uid;
		int tentaclesSize = 1,readBytes;	
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		tentacles = (char *)malloc(BUFSIZ);
		bzero(tentacles,BUFSIZ);
		sprintf(buffer,"GETTENTACLES:%s:%s",key,uid);
		write(speakpipe,buffer,strlen(buffer));
		readBytes = read(listenpipe,tentacles,BUFSIZ);
		while(readBytes == BUFSIZ){
			tentaclesSize++;
			tentacles = (char*)realloc(tentacles,tentaclesSize*BUFSIZ);
			readBytes = read(listenpipe,tentacles+((tentaclesSize-1)*BUFSIZ),BUFSIZ);
		}
		if(strcmp(tentacles,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(tentacles,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }


		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ+strlen(tentacles));
		bzero(*response,BUFSIZ+strlen(tentacles));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true,\"tentacles\":[");
		strcat(*response, buffer);

		strcat(*response, tentacles);

		sprintf(buffer,"]}");
		strcat(*response, buffer);
		free(tentacles);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"getscripts") == 0){
		char *scripts, *key, *uid;
		int scriptsSize = 1,readBytes;	
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		scripts = (char *)malloc(BUFSIZ);
		bzero(scripts,BUFSIZ);
		sprintf(buffer,"GETSCRIPTS:%s:%s",key,uid);
		write(speakpipe,buffer,strlen(buffer));
		readBytes = read(listenpipe,scripts,BUFSIZ);
		while(readBytes == BUFSIZ){
			scriptsSize++;
			scripts = (char*)realloc(scripts,scriptsSize*BUFSIZ);
			readBytes = read(listenpipe,scripts+((scriptsSize-1)*BUFSIZ),BUFSIZ);
		}
		if(strcmp(scripts,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(scripts,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }


		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ+strlen(scripts));
		bzero(*response,BUFSIZ+strlen(scripts));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true,\"scripts\":[");
		strcat(*response, buffer);

		strcat(*response, scripts);

		sprintf(buffer,"]}");
		strcat(*response, buffer);
		free(scripts);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"gettentaclescripts") == 0){
		char *scripts, *key, *uid;
		int scriptsSize = 1,readBytes;	
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		scripts = (char *)malloc(BUFSIZ);
		bzero(scripts,BUFSIZ);
		sprintf(buffer,"GETTENTACLESCRIPTS:%s:%s",key,uid);
		write(speakpipe,buffer,strlen(buffer));
		readBytes = read(listenpipe,scripts,BUFSIZ);
		while(readBytes == BUFSIZ){
			scriptsSize++;
			scripts = (char*)realloc(scripts,scriptsSize*BUFSIZ);
			readBytes = read(listenpipe,scripts+((scriptsSize-1)*BUFSIZ),BUFSIZ);
		}
		if(strcmp(scripts,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(scripts,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ+strlen(scripts));
		bzero(*response,BUFSIZ+strlen(scripts));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true,\"scripts\":[");
		strcat(*response, buffer);

		strcat(*response, scripts);

		sprintf(buffer,"]}");
		strcat(*response, buffer);
		free(scripts);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"runscript") == 0){
		char *script, *key, *uid, *tentacle;
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		tentacle =  getArgValue(args,"tentacle",nbParam);
		if(tentacle == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		script =  getArgValue(args,"script",nbParam);
		if(script == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		sprintf(buffer,"RUNSCRIPT:%s:%s:%s:%s",tentacle,script,key,uid);
		write(speakpipe,buffer,strlen(buffer));
		read(listenpipe,buffer,BUFSIZ);
		if(strcmp(buffer,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(buffer,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ);
		bzero(*response,BUFSIZ);
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true}");
		strcat(*response, buffer);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"cpyscript") == 0){
		char *script, *key, *uid, *tentacle;
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		tentacle =  getArgValue(args,"tentacle",nbParam);
		if(tentacle == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		script =  getArgValue(args,"script",nbParam);
		if(script == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		sprintf(buffer,"CPYSCRIPT:%s:%s:%s:%s",tentacle,script,key,uid);
		write(speakpipe,buffer,strlen(buffer));
		read(listenpipe,buffer,BUFSIZ);
		if(strcmp(buffer,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(buffer,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ);
		bzero(*response,BUFSIZ);
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true}");
		strcat(*response, buffer);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	else if(strcmp(action,"getscriptsresults") == 0){
		char *key, *uid, *results;
		int resultsSize = 1,readBytes;	
		key =  getArgValue(args,"key",nbParam);
		if(key == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }
		uid =  getArgValue(args,"id",nbParam);
		if(uid == NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		results = (char *)malloc(BUFSIZ);
		bzero(results,BUFSIZ);
		sprintf(buffer,"GETSCRIPTSRESULTS:%s:%s",key,uid);
		write(speakpipe,buffer,strlen(buffer));
		readBytes = read(listenpipe,results,BUFSIZ);
		while(readBytes == BUFSIZ){
			resultsSize++;
			results = (char*)realloc(results,resultsSize*BUFSIZ);
			readBytes = read(listenpipe,results+((resultsSize-1)*BUFSIZ),BUFSIZ);
		}
		if(strcmp(results,"LOGIN_FAILURE")==0){ freeArgs(args,nbParam); return responseAjaxLogout(response); }
		else if(strstr(results,"FAILURE")!=NULL){ freeArgs(args,nbParam); return responseAjaxFail(response); }

		logError(LOG_LEVEL_DEBUG,"webserver:responseService : preparing response.");
		*response = (char *)malloc(BUFSIZ+strlen(results));
		bzero(*response,BUFSIZ+strlen(results));
		strcat(*response, "HTTP/1.1 200 OK\r\n");
		strcat(*response, "Connection: close\r\n");
		strcat(*response, "Content-type: application/json\r\n");
		strcat(*response, "\r\n");
		sprintf(buffer,"{\"success\":true,\"results\":[");
		strcat(*response, buffer);

		strcat(*response, results);

		sprintf(buffer,"]}");
		strcat(*response, buffer);
		free(results);
		freeArgs(args,nbParam); 
		return strlen(*response);
	}
	freeArgs(args,nbParam); 
	return responseAjaxFail(response);
}

void *threadWorker(void *service){
	int sockService, ssl_err,i,len,listenpipe,speakpipe;
	SSL_CTX *sslctx;
	SSL *cSSL;
	char buf[BUFSIZ],*response=NULL, errBuf[BUFSIZ];
	InitializeSSL();
	sockService = ((int *)service)[0];
	listenpipe = ((int *)service)[1];
	speakpipe = ((int *)service)[2];
	free(service);

	sslctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_use_certificate_file(sslctx, "/etc/octopus/brain/cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(sslctx, "/etc/octopus/brain/key.pem", SSL_FILETYPE_PEM);
	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, sockService);
	ssl_err = SSL_accept(cSSL);
	if (ssl_err != 1) {
		SSL_get_error(cSSL, ssl_err);
		ShutdownSSL(cSSL);
	}

	for(i=0;i<BUFSIZ;i++) buf[i] = 0;
	if(read_get(cSSL,buf,BUFSIZ) == SUCCESS){
		if(buf[0] == 0) strcpy(buf,"index.html");
		snprintf(errBuf,BUFSIZ,"webserver:threadWorker : socket %d requested %s",sockService,buf);
		logError(LOG_LEVEL_DEBUG,errBuf);
		if(strncmp("service",buf,7) == 0){
			len = responseService(&response,buf,listenpipe,speakpipe);
		}else{
			len = responsePage(&response,buf);
		}
		SSL_write(cSSL,response,len);
	}
	free(response);
	ShutdownSSL(cSSL);
	close(sockService);
	return NULL;
}
int loop(int listenSocket,int listenpipe,int speakpipe){
	struct sockaddr_in callerExtremity;
	int *service,len;
	char errBuf[BUFSIZ];
	/*
	pthread_t tid;
	pthread_attr_t attr;
	if(pthread_attr_init(&attr) != 0){
		snprintf(errBuf,BUFSIZ,"webserver:loop pthread attr init : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		close(listenSocket);
		return ERR_THR_ATT;
	}

	if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0){
		snprintf(errBuf,BUFSIZ,"webserver:loop Pthread_attr_detachestate : %s",strerror(errno));
		logError(LOG_LEVEL_ERROR,errBuf);
		close(listenSocket);
		return ERR_THR_DTC;
	}*/
	while(1){
		service = (int *)malloc(sizeof(int)*3);
		service[1] = listenpipe;
		service[2] = speakpipe;
		len = sizeof (callerExtremity);
		service[0] = accept(listenSocket, (struct sockaddr *) &callerExtremity, (socklen_t *) & len);
		if(*service < 0){
			snprintf(errBuf,BUFSIZ,"webserver:loop accept : %s",strerror(errno));
			logError(LOG_LEVEL_ERROR,errBuf);
			close(listenSocket);
			return ERR_SCK_ACT;
		}
		threadWorker((void *)service);
		/*
		if(pthread_create(&tid,&attr,threadWorker,(void *)service)){
			snprintf(errBuf,BUFSIZ,"webserver:loop thread create : %s",strerror(errno));
			logError(LOG_LEVEL_ERROR,errBuf);
			close(listenSocket);
			close(*service);
			return ERR_THR_CRT;
		}*/
	}
	return ERR_DEFAULT;
}
int webServ_run(int port,int listenpipe[2],int speakpipe[2]){
	int sock,err;
	sock = create_listenSock(port);
	close(listenpipe[1]);
	close(speakpipe[0]);
	if(sock >= 0)
		err=loop(sock,listenpipe[0],speakpipe[1]);
	else
		err=sock;
	return err;
}
