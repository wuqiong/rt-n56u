#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#define TIMEOUT 10
#define PORT 9999

#define AC_MODE 1
#define AP_MODE 3

int dev_mode = 0;
int timerfd = -1;
unsigned long long missed;

static int running = 0;
static char *pid_file_name = "/tmp/ac2ap.pid";
static int pid_fd = -1;
static int start_daemonized = 0;

#pragma pack(1)


typedef enum MsgType{AP_Request=0,AC_Broadcast}MsgType;

typedef struct WiFiConfigInfo
{
    char ssid[32];
    char wpa_psk[64];
    char auth_mode[16];
    char crypto[8];
    char country_code[4];
    char wifi_on;
}WiFiConfigInfo;


typedef struct SyncMessage
{
    MsgType         msgtype;
    WiFiConfigInfo  config;
    WiFiConfigInfo  config5;    
}SyncMessage;


#pragma pack()










char *rtrim(char *str);

int broadcastACLocalConfig(int sock);

int check_mode(int argc, char* argv[]);

int nvram_get(char *buffer, int buf_len, char *name);
int nvram_set(char *name, char *value);
int nvram_commit();

int get_wifi_config(WiFiConfigInfo *config);
int set_wifi_config(WiFiConfigInfo *config);
int check_same_config(WiFiConfigInfo *aConf, WiFiConfigInfo *bConf);

int timerfd_setup(int *timerfd, int sec);

int ac_main();
int ap_main();
int main(int argc, char *argv[]);



void handle_signal(int sig);
static void daemonize();
int read_pid(char *pidfile);
int check_process_exist(int pid);




char *rtrim(char *str)
{
	if (str == NULL || *str == '\0')
	{
		return str;
	}

	int len = strlen(str);
	char *p = str + len - 1;
	while (p >= str  && isspace(*p))
	{
		*p = '\0';
		--p;
	}

	return str;
}



int timerfd_setup(int *timerfd, int sec)
{
    if(!timerfd) return 1;

    struct itimerspec timeout;
    /* create new timer */
    *timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (*timerfd <= 0) {
        printf("Failed to create timer\n");
        return 1;
    }

    /* set to non-blocking */
    int ret = fcntl(*timerfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        printf("Failed to set to non blocking mode\n");
        return 1;
    }

    /* set timeout */
    timeout.it_value.tv_sec = sec;
    timeout.it_value.tv_nsec = 0;
    timeout.it_interval.tv_sec = sec; /* recurring */
    timeout.it_interval.tv_nsec = 0;
    ret = timerfd_settime(*timerfd, 0, &timeout, NULL);
    if (ret) {
        printf("Failed to set timer duration\n");
        return 1;
    }   
    return 0; 
}

int nvram_get(char *buffer, int buflen, char *name)
{
    char cmd[64];
    memset(cmd,0x00,sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "nvram get %s",name);
    FILE *fp;
    if ((fp = popen(cmd, "r")) == NULL)
    {
        return -1;
    }
    fread(buffer,buflen,1,fp);
    if (pclose(fp) == -1)
    {
        return -1;
    }
    return 0;
}
int nvram_set(char *name, char *value)
{
    if(strlen(name) == 0 || strlen(value) == 0) return -1;

    char cmd[64];
    memset(cmd,0x00,sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "nvram set %s=%s",name,value);
    FILE *fp;
    if ((fp = popen(cmd, "r")) == NULL)
    {
        return -1;
    }
    if (pclose(fp) == -1)
    {
        return -1;
    }
    return 0;
}
int nvram_commit()
{
    return system("nvram commit");
}


int check_same_config(WiFiConfigInfo *aConf, WiFiConfigInfo *bConf)
{
    if(0==strcmp(aConf->auth_mode,bConf->auth_mode) &&
        0==strcmp(aConf->crypto,bConf->crypto) &&
        0==strcmp(aConf->ssid,bConf->ssid) &&
        0==strcmp(aConf->wpa_psk,bConf->wpa_psk) &&
        0==strcmp(aConf->country_code,bConf->country_code) &&
        aConf->wifi_on == bConf->wifi_on
        )
    {
        return 1;
    }else
    {
        return 0;
    }
}



int check_mode(int argc, char* argv[])
{
    extern char *optarg;
    extern int optind, opterr, optopt;
    int ret;
    int mode=-1;
    while((ret = getopt(argc, argv, "dp")) != -1)
    {
            switch (ret) {
            case 'd':
                    start_daemonized = 1;
                    break;
            case 'p':
                    mode=AP_MODE;
                    break;
            default:
                    break;
            }
    }
    if(mode==AP_MODE)
    {
        return AP_MODE;
    }


    char buf[256];
    if (nvram_get(buf,sizeof(buf), "sw_mode") != 0)
    {
        return AC_MODE;
    }

    mode=atoi(buf);
    return mode;
}

int get_wifi_config(WiFiConfigInfo *config)
{
    if(!config) return -1;
    memset(config,0x00,sizeof(WiFiConfigInfo));

    nvram_get(config->ssid,sizeof(config->ssid),"rt_ssid");
    rtrim(config->ssid);
    nvram_get(config->wpa_psk,sizeof(config->wpa_psk),"rt_wpa_psk");
    rtrim(config->wpa_psk);
    nvram_get(config->auth_mode,sizeof(config->auth_mode),"rt_auth_mode");
    rtrim(config->auth_mode);
    nvram_get(config->crypto,sizeof(config->crypto),"rt_crypto");
    rtrim(config->crypto);
    nvram_get(config->country_code,sizeof(config->country_code),"rt_country_code");
    rtrim(config->country_code);

    char rt_radio_x[4];
    nvram_get(rt_radio_x,sizeof(rt_radio_x),"rt_radio_x");
    rtrim(rt_radio_x);
    if(atoi(rt_radio_x) == 0)
    {
        config->wifi_on = 0;
    }else
    {
        config->wifi_on = 1;
    }
    return 0;
}

int set_wifi_config(WiFiConfigInfo *config)
{
    if(!config)
    {
        return -1;
    }
    nvram_set("rt_ssid", config->ssid);
    nvram_set("rt_wpa_psk", config->wpa_psk);
    nvram_set("rt_auth_mode", config->auth_mode);
    nvram_set("rt_crypto", config->crypto);
    nvram_set("country_code", config->country_code);

    if(config->wifi_on==1)
    {
        nvram_set("rt_radio_x", "1");
    }else
    {
        nvram_set("rt_radio_x", "0");
    }
    return 0;
}


int broadcastACLocalConfig(int sock)
{
    SyncMessage acLocalMsg;

    int addr_len;
    struct sockaddr_in broadcast_addr;
    addr_len = sizeof(struct sockaddr_in);

    memset((void*)&broadcast_addr, 0, addr_len);
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    broadcast_addr.sin_port = htons(PORT);


    memset(&acLocalMsg,0x00,sizeof(SyncMessage));
    acLocalMsg.msgtype=AC_Broadcast;
    get_wifi_config(&(acLocalMsg.config));

    int ret = sendto(sock, &acLocalMsg, sizeof(SyncMessage), 0, 
                    (struct sockaddr*) &broadcast_addr, addr_len);

    if(ret < 0)
    {
        printf("AC cann't broadcast config data.ret:%d\n",ret);
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    timerfd_setup(&timerfd, TIMEOUT);
    dev_mode = check_mode(argc, argv);

    int pid = read_pid(pid_file_name);
    if(pid>0 && check_process_exist(pid))
    {
        //已经有一个daemon进程在运行．
        unlink (pid_file_name);
        kill(pid,SIGINT);
    }


    if(start_daemonized)
    {
        daemonize();
        /* Daemon will handle  signals */
	    signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);
	    signal(SIGHUP, handle_signal);
    }

    switch(dev_mode)
    {
        case AP_MODE:
            return ap_main();
        default:
            return ac_main();
    }

    return 0;
}

int ap_main() {
  int sock;
  struct sockaddr_in ap_client_addr;
  struct sockaddr_in ac_server_addr;
  unsigned int addr_len;
  int count;
  int ret;
  fd_set readfd;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("create socket error\n");
    return -1;
  }

  addr_len = sizeof(struct sockaddr_in);

  memset((void*)&ap_client_addr, 0, addr_len);
  ap_client_addr.sin_family = AF_INET;
  ap_client_addr.sin_addr.s_addr = htons(INADDR_ANY);
  ap_client_addr.sin_port = htons(PORT);

  ret = bind(sock, (struct sockaddr*)&ap_client_addr, addr_len);
  if (ret < 0) {
    perror("bind error\n");
    return -1;
  }
 
  running = 1;
  while (running) {
    FD_ZERO(&readfd);
    FD_SET(sock, &readfd);

    ret = select(sock+1, &readfd, NULL, NULL, 0);
    if (ret > 0) {
        if (FD_ISSET(sock, &readfd))
        {
            char buffer[1024];
            SyncMessage *recvACMsg = (SyncMessage *)buffer;
            count = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                (struct sockaddr*)&ac_server_addr, &addr_len);
            if(count<sizeof(SyncMessage)) continue;
            if(recvACMsg->msgtype != AC_Broadcast) continue;

            WiFiConfigInfo apLocalConfig;
            get_wifi_config(&apLocalConfig);
            if(check_same_config(&apLocalConfig, &(recvACMsg->config)))
            {
                continue;
            }else
            {
                printf("recv broadcast config=> ssid:%s  psk:%s\n",
                        recvACMsg->config.ssid,
                        recvACMsg->config.wpa_psk);

                set_wifi_config(&recvACMsg->config);
                nvram_commit();
                system("radio2_restart");
            }
        }
    }

  }

  return 0;
}




int ac_main() {
  int sock;
  int yes = 1;
  struct sockaddr_in ap_client_addr;
  unsigned int addr_len;
  int count;
  int ret;
  fd_set readfd;


  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("sock error");
    return -1;
  }
  ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&yes, sizeof(yes));
  if (ret == -1) {
    perror("setsockopt error");
    return -1;
  }
    /* set to non-blocking */
    ret = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (ret) {
        printf("Failed to set to non blocking mode\n");
        return 1;
    }

 /* bind the socket to one network device */
  const char device[] = "br0";
  ret=setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, sizeof(device));
  if (ret != 0)
  {
     printf("%s: could not set SO_BINDTODEVICE (%s)\n",
            device, strerror(errno));
  }



  //AC启动的时候广播一下配置
  broadcastACLocalConfig(sock);



  running = 1;
  while(running)
  {


    FD_ZERO(&readfd);
    FD_SET(sock, &readfd);
    FD_SET(timerfd, &readfd);

    ret = select(sock + 1, &readfd, NULL, NULL, NULL);

    if (ret > 0)
    {
      if (FD_ISSET(sock, &readfd))
      {
        char buffer[1024];
        SyncMessage *requestMsg = (SyncMessage *)buffer;
        memset(buffer,0x00,sizeof(buffer));
        count = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&ap_client_addr, &addr_len);
        if(count<sizeof(SyncMessage)) continue;
        if(requestMsg->msgtype != AP_Request) continue;

        SyncMessage acLocalMsg;
        memset(&acLocalMsg,0x00,sizeof(acLocalMsg));
        acLocalMsg.msgtype=AC_Broadcast;
        get_wifi_config(&(acLocalMsg.config));

        if ( check_same_config(&(acLocalMsg.config),&(requestMsg->config)) )
        {
            continue;
        }else
        {

                SyncMessage acLocalMsg;
                memset(&acLocalMsg,0x00,sizeof(acLocalMsg));
                acLocalMsg.msgtype=AC_Broadcast;
                get_wifi_config(&(acLocalMsg.config));

                ret = sendto(sock, &acLocalMsg, sizeof(acLocalMsg), 0, 
                                (struct sockaddr*) &ap_client_addr, addr_len);

                if(ret < 0)
                {
                    printf("AC cann't response config data.ret:%d\n",ret);
                }

        }

      }

      //timer
      if(read(timerfd, &missed, sizeof(missed)) > 0)
      {//定时器时间到
        printf("Time out missed:%lld broadcast AC config...\n", missed);
        broadcastACLocalConfig(sock);
      }

    }

  }

  return 0;
}



/**
 * \brief Callback function for handling signals.
 * \param	sig	identifier of signal
 */
void handle_signal(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {

		/* Unlock and close lockfile */
		if (pid_fd != -1) {
			lockf(pid_fd, F_ULOCK, 0);
			close(pid_fd);
		}
		/* Try to delete lockfile */
		if (pid_file_name != NULL) {
			unlink(pid_file_name);
		}
		running = 0;
		/* Reset signal handling to default behavior */
		signal(sig, SIG_DFL);
	} else if (sig == SIGHUP) {


	} else if (sig == SIGCHLD) {

	}
}


/**
 * \brief This function will daemonize this app
 */
void daemonize()
{
	pid_t pid = 0;
	int fd;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* On success: The child process becomes session leader */
	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	/* Ignore signal sent from child to parent process */
	signal(SIGCHLD, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");

	/* Close all open file descriptors */
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
		close(fd);
	}

	/* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	stdin = fopen("/dev/null", "r");
	stdout = fopen("/dev/null", "w+");
	stderr = fopen("/dev/null", "w+");

	/* Try to write PID of daemon to lockfile */
	if (pid_file_name != NULL)
	{
		char str[256];
		pid_fd = open(pid_file_name, O_RDWR|O_CREAT, 0640);
		if (pid_fd < 0) {
			/* Can't open lockfile */
			exit(EXIT_FAILURE);
		}
		if (lockf(pid_fd, F_TLOCK, 0) < 0) {
			/* Can't lock file */
			exit(EXIT_FAILURE);
		}
		/* Get current PID */
		sprintf(str, "%d\n", getpid());
		/* Write PID to lockfile */
		write(pid_fd, str, strlen(str));
	}
}



int read_pid(char *pidfile)
{
    FILE *f;
    int pid;

    if (!(f=fopen(pidfile,"r")))
        return -1;
    fscanf(f,"%d", &pid);
    fclose(f);
    return pid;
}

int check_process_exist(int pid)
{
    char proc_path[256]="";
    snprintf(proc_path, sizeof(proc_path),"/proc/%d", pid);

    struct stat sts;
    if (stat(proc_path, &sts) == -1 && errno == ENOENT)
    {
        return 0;
    }else
    {
        return 1;
    }
}