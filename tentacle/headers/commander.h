#ifndef COMMANDER
	#define COMMANDER

int commander_run(int tentacleId, int brainKey, char *brainIp, int cmdPort, int returnPort);
int commander_sendAllResults(int tentacleId, int brainKey, char *brainIp, int returnPort);



#endif
