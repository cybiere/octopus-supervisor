#ifndef REGISTERER
	#define REGISTERER

int registerer_wait(int port, char **ipBrain, int *key,int *id);
int registerer_run(const char *brainIp,int brainPort, int *key, int *id);



#endif
