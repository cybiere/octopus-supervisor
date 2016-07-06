#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include "headers/fct.h"

#include "headers/registerer.h"
#include "headers/commander.h"

#define BRAIN_REGISTER_PORT 6000
#define TENTACLE_REGISTER_PORT 7000
#define TENTACLE_CMD_PORT 7001
#define BRAIN_RETURN_PORT 6001

#define DAEMON_NAME "octoTentacle"


static void finish(){
	/* Finish up */
	logError(LOG_LEVEL_INFO, "Octobrain is closing" );
	closelog();
}

static void child_handler(int signum){

	switch(signum) {
		case SIGALRM: exit(EXIT_FAILURE); break;
		case SIGUSR1: exit(EXIT_SUCCESS); break;
		case SIGCHLD: exit(EXIT_FAILURE); break;
		case SIGTERM: finish(); exit(EXIT_SUCCESS); break;
	}
}

static void daemonize( const char *lockfile, const char *pidfile){
	pid_t pid, sid, parent;
	int lfp = -1;

	/* already a daemon */
	if ( getppid() == 1 ) return;

	/* Create the lock file as the current user */
	if ( lockfile && lockfile[0] ) {
		lfp = open(lockfile,O_RDWR|O_CREAT,0640);
		if ( lfp < 0 ) {
			syslog( LOG_ERR, "unable to create lock file %s, code=%d (%s)",
					lockfile, errno, strerror(errno) );
			exit(EXIT_FAILURE);
		}
	}

	/* Trap signals that we expect to recieve */
	signal(SIGCHLD,child_handler);
	signal(SIGUSR1,child_handler);
	signal(SIGALRM,child_handler);
	signal(SIGTERM,child_handler);

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		syslog( LOG_ERR, "unable to fork daemon, code=%d (%s)",
				errno, strerror(errno) );
		exit(EXIT_FAILURE);
	}
	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {

		/* Wait for confirmation from the child via SIGTERM or SIGCHLD, or
		   for two seconds to elapse (SIGALRM).  pause() should not return. */
		alarm(2);
		pause();

		exit(EXIT_FAILURE);
	}

	/* Create pid file */
	if ( pidfile && pidfile[0] ) {
		char buf[20];
		lfp = open(pidfile,O_RDWR|O_CREAT,0640);
		if ( lfp < 0 ) {
			syslog( LOG_ERR, "unable to create pid file %s, code=%d (%s)",
					lockfile, errno, strerror(errno) );
			exit(EXIT_FAILURE);
		}
		sprintf(buf,"%d",getpid());
		write(lfp,buf,strlen(buf));

	}

	/* At this point we are executing as the child process */
	parent = getppid();

	/* Cancel certain signals */
	signal(SIGCHLD,SIG_DFL); /* A child process dies */
	signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGHUP, SIG_IGN); /* Ignore hangup signal */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		syslog( LOG_ERR, "unable to create a new session, code %d (%s)",
				errno, strerror(errno) );
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory.  This prevents the current
	   directory from being locked; hence not being able to remove it. */
	if ((chdir("/")) < 0) {
		syslog( LOG_ERR, "unable to change directory to %s, code %d (%s)",
				"/", errno, strerror(errno) );
		exit(EXIT_FAILURE);
	}

	/* Redirect standard files to /dev/null */
	freopen( "/dev/null", "r", stdin);
	freopen( "/dev/null", "w", stdout);
	freopen( "/dev/null", "w", stderr);

	/* Tell the parent process that we are A-okay */
	kill( parent, SIGUSR1 );
}


int main(int argc, const char *argv[]){	
	int ret,key,id;
	char *ipBrain;

	if(getuid() != 0 || geteuid() != 0){
		printf("octoTentacle must be started as root\n");
		return 0;
	}


	if(argc == 2){
	 	if(!strcmp(argv[1],"help")){
			printf("Octopus Supervisor :\nTentacle Help : \n\t-b ip\tconnect brain at ip at startup\n");
			return 0;
		}else if(!strcmp(argv[1],"--no-daemon")){
			logType(LOG_TYPE_STDOUT);
			logLevel(LOG_LEVEL_DEBUG);
		}else{
			logType(LOG_TYPE_LOGFILE);
			logLevel(LOG_LEVEL_INFO);
			daemonize( "/var/lock/subsys/" DAEMON_NAME , "/var/run/" DAEMON_NAME ".pid");
		}
	}else{
		logType(LOG_TYPE_LOGFILE);
		logLevel(LOG_LEVEL_INFO);
		daemonize( "/var/lock/subsys/" DAEMON_NAME , "/var/run/" DAEMON_NAME ".pid");
	}

	logError(LOG_LEVEL_INFO,"Octopus Supervisor tentacle started.");
	if(argc == 3){
		if (!strcmp(argv[1],"-b")) {
			ret= registerer_run(argv[2],BRAIN_REGISTER_PORT,&key,&id);
			ipBrain = (char *)malloc(strlen(argv[2])+1);
			strcpy(ipBrain,argv[2]);
		}
	}else{
		ret = registerer_wait(TENTACLE_REGISTER_PORT,&ipBrain,&key,&id);
	}
	if(ret == 0){
		return EXIT_FAILURE;
	}
	logError(LOG_LEVEL_INFO,"Tentacle is registered.");
	ret = commander_sendAllResults(id,key,ipBrain,BRAIN_RETURN_PORT);
	ret = commander_run(id,key, ipBrain, TENTACLE_CMD_PORT,BRAIN_RETURN_PORT);
	return EXIT_SUCCESS;
}
