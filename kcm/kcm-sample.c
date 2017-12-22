/*
 * A sample program of KCM.
 *
 * $ gcc -lbcc kcm-sample.c
 * $ ./a.out 10000
 */
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>

/* libbcc */
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>

#include <linux/bpf.h>

/* From linux/kcm.h */
struct kcm_clone {
	int fd;
};

struct kcm_attach {
	int fd;
	int bpf_fd;
};

#ifndef AF_KCM
/* From linux/socket.h */
#define AF_KCM		41	/* Kernel Connection Multiplexor*/
#endif

#ifndef KCMPROTO_CONNECTED
/* From linux/kcm.h */
#define KCMPROTO_CONNECTED	0
#endif

#ifndef SIOCKCMCLONE
/* From linux/sockios.h */
#define SIOCPROTOPRIVATE	0x89E0 /* to 89EF */
/* From linux/kcm.h */
#define SIOCKCMATTACH		(SIOCPROTOPRIVATE + 0)
#define SIOCKCMCLONE		(SIOCPROTOPRIVATE + 2)
#endif

struct my_proto {
	struct _hdr {
		uint32_t len;
	} hdr;
	char data[32];
};

const char *bpf_prog_string = "			\
ssize_t bpf_prog1(struct __sk_buff *skb)	\
{						\
	return load_half(skb, 0) + 4;		\
}						\
";

int servsock_init(int port)
{
	int s, error;
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_STREAM, 0);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	error = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	if (error == -1)
		err(EXIT_FAILURE, "bind");

	error = listen(s, 10);
	if (error == -1)
		err(EXIT_FAILURE, "listen");

	return s;
}

int bpf_init(void)
{
	int fd, map_fd;
	void *mod;
	int key;
	long long value = 0;

	mod = bpf_module_create_c_from_string(bpf_prog_string, 0, NULL, 0);
	fd = bpf_prog_load(
		BPF_PROG_TYPE_SOCKET_FILTER,
		bpf_function_start(mod, "bpf_prog1"),
		bpf_function_size(mod, "bpf_prog1"),
		bpf_module_license(mod),
		bpf_module_kern_version(mod),
		NULL, 0);

	if (fd == -1)
		exit(1);
	return fd;	
}

void client(int port)
{
	int s, error;
	struct sockaddr_in addr;
	struct hostent *host;
	struct my_proto my_msg;
	int len;

	printf("client is starting\n");

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	host = gethostbyname("localhost");
	if (host == NULL)
		err(EXIT_FAILURE, "gethostbyname");
	memcpy(&addr.sin_addr, host->h_addr, host->h_length);

	error = connect(s, (struct sockaddr *)&addr, sizeof(addr));
	if (error == -1)
		err(EXIT_FAILURE, "connect");

	len = sprintf(my_msg.data, "hello");
	my_msg.data[len] = '\0';
	my_msg.hdr.len = htons(len + 1);

	len = write(s, &my_msg, sizeof(my_msg.hdr) + len + 1);
	if (error == -1)
		err(EXIT_FAILURE, "write");
	printf("client sent data\n");

	printf("client is waiting a reply\n");
	len = read(s, &my_msg, sizeof(my_msg));
	if (error == -1)
		err(EXIT_FAILURE, "read");

	printf("\"%s\" from server\n", my_msg.data);
	printf("client received data\n");

	close(s);
}

int kcm_init(void)
{
	int kcmfd;

	kcmfd = socket(AF_KCM, SOCK_DGRAM, KCMPROTO_CONNECTED);
	if (kcmfd == -1)
		err(EXIT_FAILURE, "socket(AF_KCM)");

	return kcmfd;
}

int kcm_clone(int kcmfd)
{
	int error;
	struct kcm_clone clone_info;

	memset(&clone_info, 0, sizeof(clone_info));
	error = ioctl(kcmfd, SIOCKCMCLONE, &clone_info);
	if (error == -1)
		err(EXIT_FAILURE, "ioctl(SIOCKCMCLONE)");

	return clone_info.fd;
}

int kcm_attach(int kcmfd, int csock, int bpf_prog_fd)
{
	int error;
	struct kcm_attach attach_info;

	memset(&attach_info, 0, sizeof(attach_info));
	attach_info.fd = csock;
	attach_info.bpf_fd = bpf_prog_fd;

	error = ioctl(kcmfd, SIOCKCMATTACH, &attach_info);
	if (error == -1)
		err(EXIT_FAILURE, "ioctl(SIOCKCMATTACH)");
}

void process(int kcmfd0, int kcmfd1)
{
	struct my_proto my_msg;
	int error, len;
	struct pollfd fds[2];
	struct msghdr msg;
	struct iovec iov;
	int fd;

	fds[0].fd = kcmfd0;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	fds[1].fd = kcmfd1;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	printf("server is waiting data\n");
	error = poll(fds, 1, -1);
	if (error == -1)
		err(EXIT_FAILURE, "poll");

	if (fds[0].revents & POLLIN)
		fd = fds[0].fd;
	else if (fds[1].revents & POLLIN)
		fd = fds[1].fd;
	iov.iov_base = &my_msg;
	iov.iov_len = sizeof(my_msg);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("server is receiving data\n");
	len = recvmsg(fd, &msg, 0);
	if (len == -1)
		err(EXIT_FAILURE, "recvmsg");
	printf("\"%s\" from client\n", my_msg.data);
	printf("server received data\n");

	len = sprintf(my_msg.data, "goodbye");
	my_msg.data[len] = '\0';
	my_msg.hdr.len = htons(len + 1);

	len = sendmsg(fd, &msg, 0);
	if (len == -1)
		err(EXIT_FAILURE, "sendmsg");
}

void server(int tcpfd, int bpf_prog_fd)
{
	int kcmfd0, error, kcmfd1;
	struct sockaddr_in client;
	int len, csock;

	printf("server is starting\n");

	kcmfd0 = kcm_init();
	kcmfd1 = kcm_clone(kcmfd0);

	len = sizeof(client);
	csock = accept(tcpfd, (struct sockaddr *)&client, &len);
	if (csock == -1)
		err(EXIT_FAILURE, "accept");

	kcm_attach(kcmfd0, csock, bpf_prog_fd);
	kcm_attach(kcmfd1, csock, bpf_prog_fd);

	process(kcmfd0, kcmfd1);

	close(kcmfd0);
	close(kcmfd1);
}

int main(int argc, char **argv)
{
	int error, tcpfd, bpf_prog_fd;
	pid_t pid;
	int pipefd[2];
	int dummy;

	error = pipe(pipefd);
	if (error == -1)
		err(EXIT_FAILURE, "pipe");

	pid = fork();
	if (pid == -1)
		err(EXIT_FAILURE, "fork");

	if (pid == 0) {
		/* wait for server's ready */
		read(pipefd[0], &dummy, sizeof(dummy));

		client(atoi(argv[1]));

		exit(0);
	}

	tcpfd = servsock_init(atoi(argv[1]));
	bpf_prog_fd = bpf_init();

	/* tell ready */
	write(pipefd[1], &dummy, sizeof(dummy));

	server(tcpfd, bpf_prog_fd);

	waitpid(pid, NULL, 0);

	close(bpf_prog_fd);
	close(tcpfd);

	return 0;
}
