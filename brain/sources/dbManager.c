#include "../headers/dbManager.h"
#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include "../headers/webServ.h"
#include "../headers/fct.h"
#include "../headers/maestro.h"
#include "../headers/registerer.h"

int callback(void __attribute__((unused))*data, int __attribute__((unused))argc,  char __attribute__((unused))**argv, char __attribute__((unused))**azColName){
	return 0;
}
void db_prepareTable(){
	sqlite3 *db;
	char *zErrMsg = 0;
	char errBuf[BUFSIZ];
	int rc;

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		return;
	}
	logError(LOG_LEVEL_DEBUG,"dbManager:dbPrepare : database openned.");
	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY NOT NULL, key INTEGER NOT NULL, ip VARCHAR(255) NOT NULL, hostname VARCHAR(255) NOT NULL, last_alive BIGINT, registration_date BIGINT NOT NULL);", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table clients: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }

	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS rapports(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, tentacle INTEGER NOT NULL, cmd INTEGER NOT NULL, result TEXT, date BIGINT NOT NULL, seenbyuser BOOLEAN, FOREIGN KEY(tentacle) REFERENCES clients(id), FOREIGN KEY(cmd) REFERENCES commands(id));", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table rapports: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }

	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, login VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL);", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table users: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }

	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS keys(key INTEGER PRIMARY KEY NOT NULL, user INTEGER NOT NULL, lastAlive INTEGER NOT NULL, FOREIGN KEY(user) REFERENCES users(id));", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table keys: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }


	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS scripts(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name VARCHAR(255) UNIQUE NOT NULL, content TEXT NOT NULL);", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table scripts: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }

	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS link_scripts(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, script INTEGER NOT NULL, tentacle INTEGER NOT NULL, FOREIGN KEY(script) REFERENCES scripts(id), FOREIGN KEY(tentacle) REFERENCES clients(id));", callback, NULL, &zErrMsg);
	if(rc != 0)	{ snprintf(errBuf,BUFSIZ, "dbManager:dbPrepare : can't create table link_scripts: %s", zErrMsg); logError(LOG_LEVEL_CRITICAL,errBuf); }

	sqlite3_close(db);

	truncateClients();
	truncateKeys();
	truncateRapports();
	truncateLinkScripts();
	if(!existsUser("admin")) createUser("admin","admin");
}
int flagCallback(void *flag, int __attribute__((unused))argc, char __attribute__((unused))**argv, char __attribute__((unused))**azColName){
	*((int *)flag) = (*((int *)flag)+1)%2;
	return 0;
}	
int intValCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int *ret = (int *)param;
	sscanf(argv[0],"%d",ret);
	return 0;
}

/* Keys */
int db_getKey(int uid){
	int genKey, flag=1, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,buffer[BUFSIZ];
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetKey : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	do {
		genKey = rand();
		/* Test is based on the fact that if no result is found, callback won't be called, hence flag won't be set */
		sprintf(buffer,"SELECT *FROM keys WHERE key=%d",genKey);
		rc = sqlite3_exec(db, buffer, flagCallback,&flag, &zErrMsg);
		if(rc != 0){
			genKey=-1;
			flag=0;
		}
	}while(flag==0);

	sprintf(buffer,"INSERT INTO keys (key,user,lastAlive) VALUES (%d,%d,%u);",genKey,uid,(unsigned)time(NULL));
	rc = sqlite3_exec(db, buffer, callback, NULL, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetKey : error saving new key: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		genKey=-1;
	}

	sqlite3_close(db);
	return genKey;
}
int db_isKeyValid(int uid, int key){
	int flag=0, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,buffer[BUFSIZ];
	char errBuf[BUFSIZ];

	purgeKeys(0);

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbIsKeyValid : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	sprintf(buffer,"SELECT *FROM keys WHERE key=%d AND user=%d AND lastAlive>%u;",key,uid,(unsigned)(time(NULL)-KEY_TIMEOUT));
	rc = sqlite3_exec(db, buffer, flagCallback,&flag, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbIsKeyValid : error getting key: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		flag=0;
	}

	sprintf(buffer,"UPDATE keys SET lastAlive=%u WHERE key=%d AND user=%d;",(unsigned)time(NULL),key,uid);
	rc = sqlite3_exec(db, buffer, flagCallback,&flag, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbIsKeyValid : error updating key lastalive: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		flag=0;
	}
	sqlite3_close(db);


	return flag;
}
void purgeKeys(int key){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,buffer[BUFSIZ];
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:purgeKeys : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
	}

	sprintf(buffer,"DELETE FROM keys WHERE lastAlive<%u;",(unsigned)time(NULL)-KEY_TIMEOUT);
	rc = sqlite3_exec(db, buffer, callback,NULL, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbPurgeKeys : error deleting keys: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
	}

	if(key > 0){
		sprintf(buffer,"DELETE FROM keys WHERE key=%d",key);
		rc = sqlite3_exec(db, buffer, callback,NULL, &zErrMsg);
		if(rc != 0){
			snprintf(errBuf,BUFSIZ, "dbManager:dbPurgeKeys : error deleting one key: %s", zErrMsg);
			logError(LOG_LEVEL_ERROR,errBuf);
		}
	}	
	sqlite3_close(db);
}
void truncateKeys(void){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:truncateKeys : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return;
	}

	retval = sqlite3_exec(db,"DELETE FROM keys;", callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:truncateKeys : error truncate: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return;
	}
	sqlite3_close(db);
	return ;
}

/* Clients */
int db_getTentacleId(void){
	int genId, flag=1, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,buffer[BUFSIZ];
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleId : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	do {
		genId = rand();
		/* Test is based on the fact that if no result is found, callback won't be called, hence flag won't be set */
		sprintf(buffer,"SELECT *FROM clients WHERE id=%d",genId);
		rc = sqlite3_exec(db, buffer, flagCallback,&flag, &zErrMsg);
		if(rc != 0){
			snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleId : error test id exists: %s",zErrMsg);
			logError(LOG_LEVEL_ERROR,errBuf);
			genId=-1;
			flag=0;
		}
	}while(flag==0);

	sqlite3_close(db);
	return genId;
}	
int dbGetTentacleByIPName(char *ip, char *hostname){
	int id=0, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	sql = sqlite3_mprintf("SELECT id FROM clients WHERE ip='%q' and hostname='%q';",ip,hostname);
	rc = sqlite3_exec(db, sql, intValCallback,&id, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : error getting id: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		id = 0;
	}
	sqlite3_free(sql);
	sqlite3_close(db);
	return id;
}	
int dbGetTentacleKey(int id){
	int key=0, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	sql = sqlite3_mprintf("SELECT key FROM clients WHERE id='%d';",id);
	rc = sqlite3_exec(db, sql, intValCallback,&key, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : error getting id: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		key = 0;
	}
	sqlite3_free(sql);
	sqlite3_close(db);
	return key;
}	
int createClients(char *ip, char *hostname, int id, int key){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char sql[BUFSIZ];
	time_t tps;
	struct tm instant;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:createClients : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}
	tps=time(NULL);
	instant=*localtime(&tps);
	sprintf(sql, "INSERT INTO clients(id, key, ip, hostname, last_alive, registration_date) VALUES ('%d','%d','%s', '%s', %u, '%d%d%d%d%d%d');", id, key, ip, hostname, (unsigned)time(NULL),instant.tm_year+1900, instant.tm_mon+1, instant.tm_mday, instant.tm_hour, instant.tm_min, instant.tm_sec);
	retval = sqlite3_exec(db, sql, callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbCreateClient : error insert: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	return 0;
}
void truncateClients(void){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:truncateClients: can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return;
	}

	retval = sqlite3_exec(db,"DELETE FROM clients;", callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbTruncateClients : error delete: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return;
	}
	sqlite3_close(db);
	return;
}
int getTentaclesCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int first;
	char **ret = (char **)param;
	char buffer[BUFSIZ],tentStr[BUFSIZ];
	first = (*ret==NULL);
	bzero(buffer,BUFSIZ);
	bzero(tentStr,BUFSIZ);
	if(!first) strcat(buffer,",");
	sprintf(tentStr,"{\"id\":%s,\"hostname\":\"%s\",\"ip\":\"%s\",\"lastalive\":%s}",argv[0],argv[3],argv[2],argv[4]);
	strcat(buffer,tentStr);
	if(first) *ret = (char *)calloc(strlen(buffer)+1,sizeof(char));
	else *ret = (char *)realloc(*ret,strlen(*ret)+strlen(buffer)+1);
	strcat(*ret,buffer);
	return 0;
}
char *db_getTentacles(void){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*ret=NULL;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacles : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_exec(db, "SELECT *FROM clients", getTentaclesCallback,&ret, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacles : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_close(db);
	return ret;
}	
int getTentacleIpCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	char **ret = (char **)param;
	*ret = (char *)calloc(strlen(argv[0])+1,sizeof(char));
	strcpy(*ret,argv[0]);
	return 0;
}
char *dbGetTentacleIp(int id){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql, *ret;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:existsUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		fprintf(stderr, "octobrain > Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}

	sql = sqlite3_mprintf("SELECT ip FROM clients WHERE id='%d'", id);
	rc = sqlite3_exec(db, sql, getTentacleIpCallback,&ret, &zErrMsg);
	if(rc != 0){
		printf("Error test key exist : %s",zErrMsg);
		sqlite3_free(sql);
		sqlite3_close(db);
		return NULL;
	}

	sqlite3_free(sql);
	sqlite3_close(db);
	return ret;
}

/* Rapports */
int dbCreateReport( char *id_tentacle, char *id_cmd, char *date, char* result){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char *sql;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:createRapports : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}
	sql=sqlite3_mprintf("INSERT INTO rapports(tentacle, cmd, result, date, seenbyuser) VALUES ('%q', '%q', '%q', '%q', 0);", id_tentacle, id_cmd, result, date);
	retval = sqlite3_exec(db, sql, callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbCreateRapports : error insert: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);
	return 0;
}
int truncateRapports(void) {
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:truncateRapports : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	retval = sqlite3_exec(db,"DELETE FROM rapports;", callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbTruncateRapports : error delete: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		return -1;
	}
	sqlite3_close(db);
	return 0;
}
int getResultsCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int first;
	char **ret = (char **)param;
	char buffer[BUFSIZ],tentStr[BUFSIZ], *encodedResult;
	first = (*ret==NULL);
	bzero(buffer,BUFSIZ);
	bzero(tentStr,BUFSIZ);
	if(!first) strcat(buffer,",");
	encodedResult = url_encode(argv[3]);
	sprintf(tentStr,"{\"tentacle\":%s,\"script\":\"%s\",\"result\":\"%s\",\"date\":%s}",argv[1],argv[2],encodedResult,argv[4]);
	free(encodedResult);
	strcat(buffer,tentStr);
	if(first) *ret = (char *)calloc(strlen(buffer)+1,sizeof(char));
	else *ret = (char *)realloc(*ret,strlen(*ret)+strlen(buffer)+1);
	strcat(*ret,buffer);
	return 0;
}
char *db_getResults(void){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*ret=NULL;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetResults : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_exec(db, "SELECT *FROM rapports ORDER BY date DESC", getResultsCallback,&ret, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetResults : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_close(db);
	return ret;
}	

/* Users */
int createUser(char* login, char* password){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char sql[BUFSIZ];
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:createUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}
	sprintf(sql, "INSERT INTO users(login, password) VALUES ('%s', '%s');", login, crypt(password, "$6$LU04BNcas1$"));
	retval = sqlite3_exec(db, sql, callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbCreateUser : error insert: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	return 0;
}
int connectCallback(void *user, int argc, char **argv, char **azColName){
	int i;
	UserStruct *usr;
	usr = (UserStruct *)user;
	for(i=0; i<argc; i++){
		if(strcmp(azColName[i],"id") == 0){
			int readId;
			if(sscanf(argv[i],"%d",&readId) != 1) return -1;
			usr->id = readId;
		}else if(strcmp(azColName[i],"login") == 0){
			usr->login = (char *)malloc(strlen(argv[i])+1);
			strcpy(usr->login,argv[i]);
		}else if(strcmp(azColName[i],"password") == 0){
			usr->pw = (char *)malloc(strlen(argv[i])+1);
			strcpy(usr->pw,argv[i]);
		}
	}
	return 0;
}
int db_connectUser(char *login, char *password){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char sql[BUFSIZ];
	UserStruct user;
	char errBuf[BUFSIZ];

	user.id = -1;

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbConnectUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}
	sprintf(sql, "SELECT * FROM users WHERE login='%s';", login); 
	retval = sqlite3_exec(db, sql, connectCallback, (void*)&user, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbConnectUser : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	if(user.id == -1) return 0;
	if(strcmp(user.pw,crypt(password, "$6$LU04BNcas1$"))== 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbConnectUser : user connected: %s",login);
		logError(LOG_LEVEL_INFO,errBuf);
		return user.id;
	}
	snprintf(errBuf,BUFSIZ, "dbManager:dbConnectUser : connexion failure: %s",login);
	logError(LOG_LEVEL_WARNING,errBuf);
	return 0;
}
int existsUser(char *login){
	int flag=0, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,buffer[BUFSIZ];
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:existsUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		fprintf(stderr, "octobrain > Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	sprintf(buffer,"SELECT *FROM users WHERE login='%s'",login);
	rc = sqlite3_exec(db, buffer, flagCallback,&flag, &zErrMsg);
	if(rc != 0){
		printf("Error test key exist : %s",zErrMsg);
		flag=0;
	}

	return flag;
}

/* Scripts */
int createScript(char *name, char *content){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char *sql;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:createScript : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}
	sql = sqlite3_mprintf("INSERT INTO scripts(name, content) VALUES ('%q', '%q');", name,content);
	retval = sqlite3_exec(db, sql, callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbCreateScript : error insert: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);
	return 0;
}
int getScriptsCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int first;
	char **ret = (char **)param;
	char buffer[BUFSIZ],tentStr[BUFSIZ];
	first = (*ret==NULL);
	bzero(buffer,BUFSIZ);
	bzero(tentStr,BUFSIZ);
	if(!first) strcat(buffer,",");
	sprintf(tentStr,"{\"id\":%s,\"name\":\"%s\"}",argv[0],argv[1]);
	strcat(buffer,tentStr);
	if(first) *ret = (char *)calloc(strlen(buffer)+1,sizeof(char));
	else *ret = (char *)realloc(*ret,strlen(*ret)+strlen(buffer)+1);
	strcat(*ret,buffer);
	return 0;
}
char *dbGetScripts(void){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*ret=NULL;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbScripts : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_exec(db,"SELECT *FROM scripts", getScriptsCallback,&ret, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetScripts : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_close(db);
	return ret;
}	
int dbGetScriptIdByName(char *name){
	int id=0, rc;
	sqlite3 *db;
	char *zErrMsg = 0,*sql;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	sql = sqlite3_mprintf("SELECT id FROM scripts WHERE name='%q'",name);
	rc = sqlite3_exec(db, sql, intValCallback,&id, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleByIPName : error getting id: %s", zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		id = 0;
	}
	sqlite3_free(sql);
	sqlite3_close(db);
	return id;
}	
int createLinkScript(char* name, int tentacleId){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval,scriptId;
	char *sql;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:createLinkScript : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return -1;
	}

	scriptId = dbGetScriptIdByName(name);
	if(scriptId == 0){
		snprintf(errBuf,BUFSIZ,"dbManager:createLinkScript : Unknown script %s ignored",name);
		logError(LOG_LEVEL_WARNING,errBuf);
		return -1;
	}
	sql = sqlite3_mprintf("INSERT INTO link_scripts(script, tentacle) VALUES ('%d', '%d');", scriptId,tentacleId);
	retval = sqlite3_exec(db, sql, callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbCreateLinkScript : error insert: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return -1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);
	snprintf(errBuf,BUFSIZ,"dbManager:createLinkScript : Added script %s",name);
	logError(LOG_LEVEL_INFO,errBuf);
	return 0;
}
void truncateLinkScripts(void){
	sqlite3 *db;
	char *zErrMsg = 0;
	int retval;
	char errBuf[BUFSIZ];

	retval=sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (retval) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbtruncateScript : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return;
	}

	retval = sqlite3_exec(db,"DELETE FROM link_scripts;", callback, NULL, &zErrMsg);
	if( retval != SQLITE_OK ){
		snprintf(errBuf,BUFSIZ, "dbManager:dbTruncateScript : error delete: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return;
	}
	sqlite3_close(db);
	return;
}
int getAllScriptsCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int first;
	char **ret = (char **)param;
	char buffer[BUFSIZ],tentStr[BUFSIZ];
	first = (*ret==NULL);
	bzero(buffer,BUFSIZ);
	bzero(tentStr,BUFSIZ);
	if(!first) strcat(buffer,":");
	sprintf(tentStr,"%s:%s",argv[0],argv[1]);
	strcat(buffer,tentStr);
	if(first) *ret = (char *)calloc(strlen(buffer)+1,sizeof(char));
	else *ret = (char *)realloc(*ret,strlen(*ret)+strlen(buffer)+1);
	strcat(*ret,buffer);
	return 0;
}
int getAllTentaclesCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	int first;
	char **ret = (char **)param;
	char buffer[BUFSIZ],tentStr[BUFSIZ];
	first = (*ret==NULL);
	bzero(buffer,BUFSIZ);
	bzero(tentStr,BUFSIZ);
	if(!first) strcat(buffer,":");
	sprintf(tentStr,"%s",argv[0]);
	strcat(buffer,tentStr);
	if(first) *ret = (char *)calloc(strlen(buffer)+1,sizeof(char));
	else *ret = (char *)realloc(*ret,strlen(*ret)+strlen(buffer)+1);
	strcat(*ret,buffer);
	return 0;
}
char *dbGetTentacleScripts(void){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*ret=NULL, *allscripts=NULL, *tok, **scriptNames=NULL, **scriptIds=NULL, *alltentacles=NULL, **tentacleIds=NULL;
	char errBuf[BUFSIZ];
	int i,j, nbScripts=0, nbTentacles=0;

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleScripts : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_exec(db,"SELECT id,name FROM scripts", getAllScriptsCallback,&allscripts, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleScripts : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	tok = strtok(allscripts,":");
	while(tok != NULL){
		nbScripts++;
		scriptNames = (char **)realloc(scriptNames,sizeof(char *)*nbScripts);
		scriptIds = (char **)realloc(scriptIds,sizeof(char *)*nbScripts);
		scriptIds[nbScripts-1] = (char *)malloc(strlen(tok));
		strcpy(scriptIds[nbScripts-1],tok);
		tok = strtok(NULL,":");
		if(tok == NULL){
			logError(LOG_LEVEL_ERROR,"dbManager:dbGetTentacleScripts : unpaired script");
			return NULL;
		}
		scriptNames[nbScripts-1] = (char *)malloc(strlen(tok));
		strcpy(scriptNames[nbScripts-1],tok);
		tok = strtok(NULL,":");
	}

	rc = sqlite3_exec(db,"SELECT id FROM clients", getAllTentaclesCallback,&alltentacles, &zErrMsg);
	if(rc != 0){
		snprintf(errBuf,BUFSIZ, "dbManager:dbGetTentacleScripts : error select: %s",zErrMsg);
		logError(LOG_LEVEL_ERROR,errBuf);
		sqlite3_close(db);
		return NULL;
	}

	tok = strtok(alltentacles,":");
	while(tok != NULL){
		nbTentacles++;
		tentacleIds = (char **)realloc(tentacleIds,sizeof(char *)*nbTentacles);
		tentacleIds[nbTentacles-1] = (char *)malloc(strlen(tok));
		strcpy(tentacleIds[nbTentacles-1],tok);
		tok = strtok(NULL,":");
	}

	ret = (char *)calloc(sizeof(char),255*nbScripts+255*nbTentacles);
	for(i=0;i<nbScripts;i++){
		if(i!=0) strcat(ret,",");
		strcat(ret,"{\"id\":");
		strcat(ret,scriptIds[i]);
		strcat(ret,",\"name\":\"");
		strcat(ret,scriptNames[i]);
		strcat(ret,"\",\"tentacles\":[");
		for(j=0;j<nbTentacles;j++){
			if(j!=0) strcat(ret,",");
			strcat(ret,"{\"id\":");
			strcat(ret,tentacleIds[j]);
			strcat(ret,",\"has\":");
			strcat(ret,dbTentacleHasScript(tentacleIds[j],scriptIds[i])?"true":"false");
			strcat(ret,"}");
		}
		strcat(ret,"]}");
	}

	free(allscripts);
	free(alltentacles);
	for(i=0;i<nbScripts;i++){
		free(scriptIds[i]);
		free(scriptNames[i]);
	}
	free(scriptIds);
	for(j=0;j<nbTentacles;j++){
		free(tentacleIds[j]);
	}
	free(tentacleIds);

	sqlite3_close(db);
	return ret;
}	
int dbTentacleHasScript(char *id, char *script){
	int flag=0, rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:existsUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		fprintf(stderr, "octobrain > Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	sql = sqlite3_mprintf("SELECT *FROM link_scripts WHERE tentacle='%q' AND script='%q';", id, script);
	rc = sqlite3_exec(db, sql, flagCallback,&flag, &zErrMsg);
	if(rc != 0){
		printf("Error test key exist : %s",zErrMsg);
		flag=0;
	}

	sqlite3_free(sql);
	sqlite3_close(db);
	return flag;
}
int getScriptNameCallback(void *param, int __attribute__((unused))argc,  char **argv, char __attribute__((unused))**azColName){
	char **ret = (char **)param;
	*ret = (char *)calloc(strlen(argv[0])+1,sizeof(char));
	strcpy(*ret,argv[0]);
	return 0;
}
char *dbGetScriptName(int id){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql, *ret;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:existsUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		fprintf(stderr, "octobrain > Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}

	sql = sqlite3_mprintf("SELECT name FROM scripts WHERE id='%d'", id);
	rc = sqlite3_exec(db, sql, getScriptNameCallback,&ret, &zErrMsg);
	if(rc != 0){
		printf("Error test key exist : %s",zErrMsg);
		sqlite3_free(sql);
		sqlite3_close(db);
		return NULL;
	}

	sqlite3_free(sql);
	sqlite3_close(db);
	return ret;
}
char *dbGetScriptContent(int id){
	int rc;	
	sqlite3 *db;
	char *zErrMsg = 0,*sql, *ret;
	char errBuf[BUFSIZ];

	rc = sqlite3_open("/usr/share/octopus/brain/brain.db", &db);
	if (rc) {
		snprintf(errBuf,BUFSIZ, "dbManager:existsUser : can't open database: %s", sqlite3_errmsg(db));
		logError(LOG_LEVEL_CRITICAL,errBuf);
		fprintf(stderr, "octobrain > Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}

	sql = sqlite3_mprintf("SELECT content FROM scripts WHERE id='%d'", id);
	rc = sqlite3_exec(db, sql, getScriptNameCallback,&ret, &zErrMsg);
	if(rc != 0){
		printf("Error test key exist : %s",zErrMsg);
		sqlite3_free(sql);
		sqlite3_close(db);
		return NULL;
	}

	sqlite3_free(sql);
	sqlite3_close(db);
	return ret;
}
