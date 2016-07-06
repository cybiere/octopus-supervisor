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
#include "headers/maestro.h"
#include "headers/dbManager.h"


#define DAEMON_NAME "octoBrain"


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


	srand(time(NULL)-1);
	if(getuid() != 0 || geteuid() != 0){
		printf("octoBrain must be started as root user\n");
		return 0;
	}
	if(argc == 2){
		if(!strcmp(argv[1],"help")){
			printf("Octopus Supervisor :\nBrain Help : \n\t--no-daemon\tLaunch without daemon mode.\n");
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


	db_prepareTable();

	/* test data
	   if(1){
	   createClients("127.0.0.1","Salmar",db_getTentacleId(),456);
	   createClients("192.168.0.1","Osse",db_getTentacleId(),456);
	   createClients("192.168.1.2","Tillion",db_getTentacleId(),456);
	   createClients("192.168.1.3","Eonwe",db_getTentacleId(),456);
	   createClients("192.168.1.4","Ilmare",db_getTentacleId(),456);
	   }*/
	/* log testing 
	   logError(LOG_LEVEL_DEBUG,"This is a debug message");
	   logError(LOG_LEVEL_INFO,"This is an info message");
	   logError(LOG_LEVEL_WARNING,"This is a warning message");
	   logError(LOG_LEVEL_ERROR,"This is an error message");
	   logError(LOG_LEVEL_CRITICAL,"This is a critical message");
	   */


	logError(LOG_LEVEL_INFO,"Octopus Supervisor brain started");
	maestro_start();

	return 0;
}
