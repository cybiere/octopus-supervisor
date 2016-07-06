#include "../headers/maestro.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../headers/fct.h"
#include "../headers/webServ.h"
#include "../headers/dbManager.h"
#include "../headers/registerer.h"
#include "../headers/commander.h"
#include "../headers/listener.h"


#define BRAIN_REGISTER_PORT 6000
#define TENTACLE_REGISTER_PORT 7000
#define WEBSERV_PORT 8080
#define TENTACLE_COMMAND_PORT 7001
#define BRAIN_LISTENER_PORT 6001

int interpret_msg(char *msg,int answer){
	char *tok;
	char buffer[BUFSIZ];
	tok = strtok(msg,":");
	if(tok == NULL) return -1;
	if(strcmp(tok,"REGISTER") == 0){
		char *ip, *keyStr, *uidStr, *hostname,*scripts,*scriptTok,errBuf[BUFSIZ];
		int id,webKey, webUid, key;
		ip = strtok(NULL,":");
		if(ip == NULL){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); return 0; }
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }
		id = db_getTentacleId();
		hostname = (char *)malloc(BUFSIZ);
		key = registerer_run(ip,TENTACLE_REGISTER_PORT,id,hostname,&scripts);
		if(key < 0){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); free(hostname); return 0; }
		if(createClients(ip,hostname,id,key) != 0){ write(answer,"REGISTER_FAILURE",strlen("REGISTER_FAILURE")); free(scripts); free(hostname); return 0;}
		logError(LOG_LEVEL_DEBUG,"maestro:interpretMsg:register : Tentacle registered, will now show scripts");

		scriptTok = strtok(scripts,":");
		while(scriptTok != NULL && strcmp(scriptTok,"EOL") != 0){
			snprintf(errBuf,BUFSIZ,"maestro:interpretMsg:register : added script %s",scriptTok);
			logError(LOG_LEVEL_DEBUG,errBuf);
			createLinkScript(scriptTok,id);
			scriptTok = strtok(NULL,":");
		}
		free(scripts);

		write(answer,"REGISTER_SUCCESS",strlen("REGISTER_SUCCESS"));
		sprintf(buffer,"maestro:interpretMsg:register : Registerer New tentacle \"%s\" with id %d and key %d at ip %s",hostname,id,key,ip);
		logError(LOG_LEVEL_INFO,buffer);
		free(hostname);

	}
	else if(strcmp(tok,"GET_TENTACLE_ID") == 0){
		int id;
		id = db_getTentacleId();
		sprintf(buffer,"ID:%d\n",id);
		write(answer,buffer,strlen(buffer));
	}
	else if(strcmp(tok,"REGISTERED") == 0){
		char *ip, *keyStr, *idStr, *hostname, *scriptTok;
		int key, id;
		ip = strtok(NULL,":");
		if(ip == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (TOK NULL IP)");
			return -1; 
		}
		idStr = strtok(NULL,":");
		if(idStr == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (TOK NULL ID)");
			return -1;
		}
		if(sscanf(idStr,"%d",&id) != 1){ 
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (SSCANF ID)");
			return -1;
		}
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (TOK NULL KEY)");
			return -1;
		}
		if(sscanf(keyStr,"%d",&key) != 1){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (SSCANF KEY)");
			return -1;
		}
		hostname = strtok(NULL,":");
		if(hostname == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (TOK NULL HOSTNAME)");
			return -1;
		}
		if(createClients(ip,hostname,id,key) != 0){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:registered : wrong message from registerer (createClients)");
			return -1;
		}
		logError(LOG_LEVEL_INFO,"maestro:interpretMsg:registered : Registered successfully from daemon, now scripts");
		scriptTok = strtok(NULL,":");
		if(scriptTok == NULL || strcmp(scriptTok,"SCRIPTS") != 0){
			logError(LOG_LEVEL_WARNING,"maestro:interpretMsg:registered : failed to register scripts (wrong message)");
			return -1;
		}
		scriptTok = strtok(NULL,":");
		while(scriptTok != NULL && strcmp(scriptTok,"EOL") != 0){
			snprintf(buffer,BUFSIZ,"maestro:interpretMsg:register : added script %s",scriptTok);
			logError(LOG_LEVEL_DEBUG,buffer);
			createLinkScript(scriptTok,id);
			scriptTok = strtok(NULL,":");
		}

		return 0;
	}
	else if(strcmp(tok,"CONNECT") == 0){
		char *login;
		char *pw;
		int idUser,key;
		tok = strtok(NULL,":");
		if(tok == NULL){ write(answer,"CONNECTION_FAILURE",strlen("CONNECTION_FAILURE")); return 0; }
		login = (char *)malloc(strlen(tok)+1);
		strcpy(login,tok);
		tok = strtok(NULL,":");
		if(tok == NULL){ write(answer,"CONNECTION_FAILURE",strlen("CONNECTION_FAILURE")); free(login); return 0; }
		pw = (char *)malloc(strlen(tok)+1);
		strcpy(pw,tok);
		idUser = db_connectUser(login,pw);
		if(idUser == 0){ write(answer,"CONNECTION_FAILURE",strlen("CONNECTION_FAILURE"));
		}else{
			key = db_getKey(idUser);
			sprintf(buffer,"CONNECTED:%d:%d",idUser,key);
			write(answer,buffer,strlen(buffer));
		}
		free(login); free(pw);
	}
	else if(strcmp(tok,"GETTENTACLES") == 0){
		char *list, *keyStr, *uidStr;
		int webKey, webUid;
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"GETTENTACLES_FAILURE",strlen("GETTENTACLES_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"GETTENTACLES_FAILURE",strlen("GETTENTACLES_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"GETTENTACLES_FAILURE",strlen("GETTENTACLES_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"GETTENTACLES_FAILURE",strlen("GETTENTACLES_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }


		list = db_getTentacles();
		if(list == NULL){ write(answer,"GETTENTACLES_FAILURE",strlen("GETTENTACLES_FAILURE")); return 0; }
		if(list == 0){ write(answer,"\0",1); return 0; }
		write(answer,list,strlen(list));
		free(list);
	}
	else if(strcmp(tok,"GETSCRIPTS") == 0){
		char *list, *keyStr, *uidStr;
		int webKey, webUid;
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"GETSCRIPTS_FAILURE",strlen("GETSCRIPTS_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"GETSCRIPTS_FAILURE",strlen("GETSCRIPTS_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"GETSCRIPTS_FAILURE",strlen("GETSCRIPTS_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"GETSCRIPTS_FAILURE",strlen("GETSCRIPTS_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }


		list = dbGetScripts();
		if(list == NULL){ write(answer,"GETSCRIPTS_FAILURE",strlen("GETSCRIPTS_FAILURE")); return 0; }
		if(list == 0){ write(answer,"\0",1); return 0; }
		write(answer,list,strlen(list));
		free(list);
	}
	else if(strcmp(tok,"GETTENTACLESCRIPTS") == 0){
		char *list, *keyStr, *uidStr;
		int webKey, webUid;


		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"GETTENTACLESSCRIPTS_FAILURE",strlen("GETTENTACLESSCRIPTS_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"GETTENTACLESSCRIPTS_FAILURE",strlen("GETTENTACLESSCRIPTS_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"GETTENTACLESSCRIPTS_FAILURE",strlen("GETTENTACLESSCRIPTS_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"GETTENTACLESSCRIPTS_FAILURE",strlen("GETTENTACLESSCRIPTS_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }

		list = dbGetTentacleScripts();
		if(list == NULL){ write(answer,"GETTENTACLESSCRIPTS_FAILURE",strlen("GETTENTACLESSCRIPTS_FAILURE")); return 0; }
		if(list == 0){ write(answer,"\0",1); return 0; }
		write(answer,list,strlen(list));
		free(list);
	}
	else if(strcmp(tok,"RUNSCRIPT") == 0){
		char *script, *keyStr, *uidStr, *tentacle, *ip, *scriptName;
		int webKey, webUid, tentacleId, tentacleKey, scriptId;


		tentacle = strtok(NULL,":");
		if(tentacle == NULL){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		if(sscanf(tentacle,"%d",&tentacleId) != 1){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		script = strtok(NULL,":");
		if(script == NULL){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		if(sscanf(script,"%d",&scriptId) != 1){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }

		tentacleKey = dbGetTentacleKey(tentacleId);
		if(tentacleKey == 0){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }


		if(!dbTentacleHasScript(tentacle,script)){ write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		ip = dbGetTentacleIp(tentacleId);
		if(ip == NULL){
			write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE"));
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:runscript : unable to retrieve tentacle ip");
			return 0;
		}
		scriptName = dbGetScriptName(scriptId);
		if(scriptName== NULL){
			write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE"));
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:runscript : unable to retrieve script name");
			return 0; 
		}
		if(commanderRun(ip,TENTACLE_COMMAND_PORT,tentacleKey,tentacleId,scriptName) != 0){  write(answer,"RUNSCRIPT_FAILURE",strlen("RUNSCRIPT_FAILURE")); return 0; }
		write(answer,"RUNSCRIPT_SUCCESS",strlen("RUNSCRIPT_SUCCESS"));
		free(ip);
		free(scriptName);
	}
	else if(strcmp(tok,"CPYSCRIPT") == 0){
		char *script, *keyStr, *uidStr, *tentacle, *ip, *scriptName, *scriptContent;
		int webKey, webUid, tentacleId, tentacleKey, scriptId;


		tentacle = strtok(NULL,":");
		if(tentacle == NULL){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		if(sscanf(tentacle,"%d",&tentacleId) != 1){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		script = strtok(NULL,":");
		if(script == NULL){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		if(sscanf(script,"%d",&scriptId) != 1){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }

		tentacleKey = dbGetTentacleKey(tentacleId);
		if(tentacleKey == 0){ write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }


		if(dbTentacleHasScript(tentacle,script)){ write(answer,"CPYSCRIPT_SUCCESS",strlen("CPYSCRIPT_SUCCESS")); return 0; }
		ip = dbGetTentacleIp(tentacleId);
		if(ip == NULL){
			write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE"));
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:cpyscript : unable to retrieve tentacle ip");
			return 0;
		}
		scriptName = dbGetScriptName(scriptId);
		if(scriptName== NULL){
			write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE"));
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:cpyscript : unable to retrieve script name");
			return 0; 
		}
		scriptContent = dbGetScriptContent(scriptId);
		if(scriptContent== NULL){
			write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE"));
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:cpyscript : unable to retrieve script name");
			return 0; 
		}
		if(commanderCpyScript(ip,TENTACLE_COMMAND_PORT,tentacleKey,tentacleId,scriptName,scriptContent) != 0){  write(answer,"CPYSCRIPT_FAILURE",strlen("CPYSCRIPT_FAILURE")); return 0; }
		createLinkScript(scriptName,tentacleId);
		write(answer,"CPYSCRIPT_SUCCESS",strlen("CPYSCRIPT_SUCCESS"));
	}
	else if (strcmp(tok, "SEARCHKEY") ==0){
		char *id;
		int idTentacle, key;
		id=strtok(NULL, ":");
		if(id==NULL) { write(answer, "NO_ID_FOUND", strlen("NO_ID_FOUND")); return 0; }
		sscanf(id, "%d", &idTentacle);
		key = dbGetTentacleKey(idTentacle);
		sprintf(buffer, "%d", key);
		write(answer, buffer, strlen(buffer));
	}
	else if (strcmp(tok, "ADDSCRIPT") ==0){
		char *name, *keyStr, *idStr, *content, *clearContent;
		int key, id;
		idStr = strtok(NULL,":");
		if(idStr == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (TOK NULL ID)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1;
		}
		if(sscanf(idStr,"%d",&id) != 1){ 
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (SSCANF ID)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1;
		}
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (TOK NULL KEY)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1;
		}
		if(sscanf(keyStr,"%d",&key) != 1){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (SSCANF KEY)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1;
		}
		if(db_isKeyValid(id,key) != 1){
			logError(LOG_LEVEL_WARNING,"maestro:interpretMsg:addscript : invalid web credentials");
			write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE"));
			return 0; 
		}
		name = strtok(NULL,":");
		if(name == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (TOK NULL NAME)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1;
		}
		content = strtok(NULL,":");
		if(content == NULL){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : wrong message from registerer (TOK NULL CONTENT)");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
			return -1; 
		}


		clearContent = url_decode(content);

		if(createScript(name,clearContent) != 0){
			logError(LOG_LEVEL_ERROR,"maestro:interpretMsg:addscript : createScript returned non-null");
			write(answer,"ADDSCRIPT_FAILURE",strlen("ADDSCRIPT_FAILURE"));
		}else{
			write(answer,"ADDSCRIPT_SUCCESS",strlen("ADDSCRIPT_SUCCESS"));
		}

		free(clearContent);
	}
	else if (strcmp(tok, "WRITE") ==0){
		char *tentacle, *cmd, *date, *report;
		tentacle=strtok(NULL, ":");
		if(tentacle==NULL) { write(answer, "NO_ID_FOUND", strlen("NO_ID_FOUND")); return 0; }
		date=strtok(NULL, ":");
		if(date==NULL) { write(answer, "NO_DATE_FOUND", strlen("NO_DATE_FOUND")); return 0; }
		cmd=strtok(NULL, ":");
		if(cmd==NULL) { write(answer, "NO_FILENAME_FOUND", strlen("NO_FILENAME_FOUND")); return 0; }
		report=strtok(NULL, "\r");
		dbCreateReport(tentacle, cmd, date, report);
	}
	else if(strcmp(tok,"GETSCRIPTSRESULTS") == 0){
		char *list, *keyStr, *uidStr;
		int webKey, webUid;
		keyStr = strtok(NULL,":");
		if(keyStr == NULL){ write(answer,"GETSCRIPTSRESULTS_FAILURE",strlen("GETSCRIPTSRESULTS_FAILURE")); return 0; }
		if(sscanf(keyStr,"%d",&webKey) != 1){ write(answer,"GETSCRIPTSRESULT_FAILURE",strlen("GETSCRIPTSRESULTS_FAILURE")); return 0; }
		uidStr = strtok(NULL,":");
		if(uidStr == NULL){ write(answer,"GETSCRIPTSRESULTS_FAILURE",strlen("GETSCRIPTSRESULTS_FAILURE")); return 0; }
		if(sscanf(uidStr,"%d",&webUid) != 1){ write(answer,"GETSCRIPTSRESULTS_FAILURE",strlen("GETSCRIPTSRESULTS_FAILURE")); return 0; }
		if(db_isKeyValid(webUid,webKey) != 1){ write(answer,"LOGIN_FAILURE",strlen("LOGIN_FAILURE")); return 0; }


		list = db_getResults();
		if(list == NULL){ write(answer,"GETSCRIPTSRESULTS_FAILURE",strlen("GETSCRIPTSRESULTS_FAILURE")); return 0; }
		if(list == 0){ write(answer,"\0",1); return 0; }
		write(answer,list,strlen(list));
		free(list);
	}
	return 0;
}

void maestro_start(){
	int webServ_listen_pipe[2], webServ_speak_pipe[2], registerer_listen_pipe[2], registerer_speak_pipe[2], cmd_speak_pipe[2], cmd_listen_pipe[2], readLen,maxfd;
	pid_t webServ_PID, registerer_listen_PID, cmd_listen_PID;
	fd_set rfds;
	char bufIn[BUFSIZ],errBuf[BUFSIZ];

	if(pipe(webServ_listen_pipe)	!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return;
	}
	if(pipe(webServ_speak_pipe)		!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return;
	}
	if(pipe(registerer_listen_pipe)	!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return;
	}
	if(pipe(registerer_speak_pipe)	!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return; 
	}
	if(pipe(cmd_listen_pipe)		!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return; 
	}
	if(pipe(cmd_speak_pipe)			!= 0){ 
		snprintf(errBuf,BUFSIZ,"maestroStart : pipe : %s",strerror(errno));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return; 
	}


	if((webServ_PID = fork()) == 0){
		webServ_run(WEBSERV_PORT,webServ_listen_pipe,webServ_speak_pipe);
		return;
	}
	if((registerer_listen_PID = fork()) == 0){
		registerer_daemon(BRAIN_REGISTER_PORT,registerer_listen_pipe,registerer_speak_pipe);
		return;
	}
	if((cmd_listen_PID = fork()) == 0){
		saveRapports(BRAIN_LISTENER_PORT, cmd_listen_pipe, cmd_speak_pipe);
		return;
	}

	close(webServ_listen_pipe[0]);
	close(webServ_speak_pipe[1]);
	close(registerer_listen_pipe[0]);
	close(registerer_speak_pipe[1]);
	close(cmd_listen_pipe[0]);
	close(cmd_speak_pipe[1]);

	maxfd = webServ_listen_pipe[1];
	if(webServ_speak_pipe[0] > maxfd) maxfd = webServ_speak_pipe[0];
	if(registerer_listen_pipe[1] > maxfd) maxfd = registerer_listen_pipe[1];
	if(registerer_speak_pipe[0] > maxfd) maxfd = registerer_speak_pipe[0];
	if(cmd_listen_pipe[1] > maxfd) maxfd = cmd_listen_pipe[1];
	if(cmd_speak_pipe[0] > maxfd) maxfd = cmd_speak_pipe[0];

	FD_ZERO(&rfds);
	FD_SET(registerer_speak_pipe[0], &rfds);
	FD_SET(webServ_speak_pipe[0], &rfds);
	FD_SET(cmd_speak_pipe[0], &rfds);
	while(select(maxfd+1, &rfds, NULL, NULL, NULL) != -1){
		logError(LOG_LEVEL_DEBUG,"maestro:maestro_start : select got data.");
		if(FD_ISSET(webServ_speak_pipe[0],&rfds)){
			bzero(bufIn,BUFSIZ);
			readLen = read(webServ_speak_pipe[0],bufIn,BUFSIZ);
			if(readLen < 0){
				perror("Maestro Read :");
				snprintf(errBuf,BUFSIZ,"maestroStart:webserv : read : %s",strerror(errno));
				logError(LOG_LEVEL_CRITICAL,errBuf);
				/*here we should close everything and kill children... Should.*/
				return;
			}
			snprintf(errBuf,BUFSIZ,"maestro:maestro_start:webserver : %s",bufIn);
			logError(LOG_LEVEL_DEBUG,errBuf);
			interpret_msg(bufIn,webServ_listen_pipe[1]);
		}
		if(FD_ISSET(registerer_speak_pipe[0],&rfds)){
			bzero(bufIn,BUFSIZ);
			readLen = read(registerer_speak_pipe[0],bufIn,BUFSIZ);
			if(readLen < 0){
				perror("Maestro Read :");
				snprintf(errBuf,BUFSIZ,"maestroStart:registerer : read : %s",strerror(errno));
				logError(LOG_LEVEL_CRITICAL,errBuf);
				/*here we should close everything and kill children... Should.*/
				return;
			}
			snprintf(errBuf,BUFSIZ,"maestro:maestro_start:registerer : %s",bufIn);
			logError(LOG_LEVEL_DEBUG,errBuf);
			interpret_msg(bufIn,registerer_listen_pipe[1]);
		}
		if(FD_ISSET(cmd_speak_pipe[0], &rfds)){
			char *buffer=NULL; int size=0, first=1;
			bzero(bufIn, BUFSIZ);
			do{	
				readLen = read(cmd_speak_pipe[0], bufIn, BUFSIZ);
				if(readLen < 0){
					perror("Maestro Read :");
					snprintf(errBuf,BUFSIZ,"maestroStart:listener : read : %s",strerror(errno));
					logError(LOG_LEVEL_CRITICAL,errBuf);
					/*here we should close everything and kill children... Should.*/
					return;
				}
				size++;
				buffer = (char *)realloc(buffer,BUFSIZ*size+1);
				if(first){buffer[0] = '\0'; first=0;}
				strcat(buffer, bufIn);
				bzero(bufIn, BUFSIZ);
			}while(readLen == BUFSIZ);
			if(readLen < 0){
				perror("Maestro Read :");
				snprintf(errBuf,BUFSIZ,"maestroStart:listener : read : %s",strerror(errno));
				logError(LOG_LEVEL_CRITICAL,errBuf);
				/*here we should close everything and kill children... Should.*/
				return;
			}
			snprintf(errBuf,100,"maestro:maestro_start:listener : %s",buffer);
			logError(LOG_LEVEL_DEBUG,errBuf);
			interpret_msg(buffer, cmd_listen_pipe[1]);
		}

		FD_ZERO(&rfds);
		FD_SET(registerer_speak_pipe[0], &rfds);
		FD_SET(webServ_speak_pipe[0], &rfds);
		FD_SET(cmd_speak_pipe[0], &rfds);
	}
	snprintf(errBuf,BUFSIZ,"maestroStart : select : %s",strerror(errno));
	logError(LOG_LEVEL_CRITICAL,errBuf);
}
