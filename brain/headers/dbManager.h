#define KEY_TIMEOUT 300 /* user keys timeout in seconds */

int callback(void *data, int argc,  char **argv,char **azColName);
int flagCallback(void *flag, int argc, char **argv, char **azColName);
void db_prepareTable();

typedef struct{
	int id;
	char *login;
	char *pw;
}UserStruct;

/*Keys management */
int db_getKey(int uid);
int db_isKeyValid(int uid, int key);
void purgeKeys(int key);
void truncateKeys(void);


/* Clients Table */
int db_getTentacleId(void);
int dbGetTentacleKey(int id);
int dbGetTentacleByIPName(char *ip,char *hostname);
char *dbGetTentacleIp(int id);
char *db_getTentacles(void);
int createClients(char *ip, char *hostname, int id, int key);
void truncateClients(void);

/* Rapports Table */
int truncateRapports(void);
int dbCreateReport(char* id_tentacle, char* id_cmd, char* date, char* result);
char *db_getResults(void);

/* Users Table */
int createUser(char* login, char* password);
int existsUser(char *login);
int connectCallback(void *user, int argc, char **argv, char **azColName);
int db_connectUser(char *login, char *password);

/* Scripts Table */
int createScript(char* name, char *content);
char *dbGetScripts(void);
char *dbGetScriptName(int id);
char *dbGetScriptContent(int id);
int createLinkScript(char* name, int tentacleId);
void truncateLinkScripts(void);
char *dbGetTentacleScripts(void);
int dbTentacleHasScript(char *id, char *script);
