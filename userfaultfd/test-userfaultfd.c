#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>
#include <string.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <linux/userfaultfd.h>

/*
 * FD passing utility functions based on https://stackoverflow.com/questions/28003921/
 */
void sendfd(int s, int fd)
{
	struct msghdr msg = {0};
	char buf[CMSG_SPACE(sizeof(fd))];
	struct iovec io = { .iov_base = "send", .iov_len = 4 };

	memset(buf, '\0', sizeof(buf));

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	*((int *) CMSG_DATA(cmsg)) = fd;

	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(s, &msg, 0) == -1)
		perror("sendmsg");
}

int recvfd(int s)
{
	struct msghdr msg = {0};
	char mbuf[256];
	struct iovec io = { .iov_base = mbuf, .iov_len = sizeof(mbuf) };
	char cbuf[256];

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	if (recvmsg(s, &msg, 0) == -1)
		perror("recvmsg");

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);

	return *((int *)CMSG_DATA(cmsg));
}

int setup_userfaultfd(int sock, char *page, int pagesize)
{
	int uffd, ret;
	struct uffdio_api api;
        struct uffdio_register reg;

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC);
	if (uffd == -1)
		perror("userfaultfd");

	api.api = UFFD_API;
	api.features = 0;

	/*
	 * Even if we don't use the result, we have to call UFFDIO_API
	 * prior to UFFDIO_REGISTER.
	 */
	ret = ioctl(uffd, UFFDIO_API, &api);
	if (ret == -1)
		perror("ioctl(UFFDIO_API)");

	reg.range.start = (uintptr_t)page;
	reg.range.len = pagesize;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;

	ret = ioctl(uffd, UFFDIO_REGISTER, &reg);
	if (ret == -1)
		perror("ioctl(UFFDIO_REGISTER)");

	__u64 features = UFFD_API_RANGE_IOCTLS;
	if ((reg.ioctls & features) != features)
		perror("ioctl(UFFDIO_REGISTER)");

	return uffd;
}

void target(int sock, char *page, int pagesize)
{
	int uffd;

	printf("target: starting\n");

	/*
	 * The target needs to set up userfaultfd and pass it to
	 * the management process.
	 */
	uffd = setup_userfaultfd(sock, page, pagesize);

	printf("target: set up a userfaultfd\n");

	sendfd(sock, uffd);

	/* This causes a page fault. */
	printf("target: got \"%s\"\n", page);
}

void die(const char *errstr, int errnum, pid_t pid)
{
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	errno = errnum;
	perror(errstr);
}

void manager(int sock, char *page, int pagesize, int targetpid,
	     const char *str)
{
	int uffd, ret;
        struct uffdio_copy copy;
	struct uffd_msg msg;
	char *buf;

	uffd = recvfd(sock);

	printf("manager: waiting for a page fault\n");

	ret = read(uffd, &msg, sizeof(msg));
	if (ret != sizeof(msg))
		die("read(sizeof(msg))", EINVAL, targetpid);
	if (msg.event != UFFD_EVENT_PAGEFAULT)
		die("read(UFFD_EVENT_PAGEFAULT)", EINVAL, targetpid);

	printf("manager: notified a page fault\n");

	buf = malloc(pagesize);
	if (buf == NULL)
		die("malloc", ENOMEM, targetpid);

	memset(buf, 0, pagesize);
	strncpy(buf, str, strlen(str) + 1);

	copy.dst = (uint64_t)(uintptr_t)page;
	copy.src = (uint64_t)(uintptr_t)buf;
	copy.len = pagesize;
	copy.mode = 0;

	ret = ioctl(uffd, UFFDIO_COPY, &copy);
	if (ret == -1)
		die("ioctl(UFFDIO_COPY)", errno, targetpid);

	printf("manager: resolved a page fault\n");
}

int main(int argc, char **argv)
{
	const char *str = argc == 2 ? argv[1] : "test";
	const int pagesize = getpagesize();
	pid_t pid;
	char *page;
	int ret, socks[2];

	page = mmap(NULL, pagesize, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (page == MAP_FAILED)
		perror("mmap");

	ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);
	if (ret == -1)
		perror("socketpair");

	/* We need to fork first, then userfaultfd */
	pid = fork();
	switch (pid) {
	case 0:
		target(socks[0], page, pagesize);
		return EXIT_SUCCESS;
	case -1:
		perror("fork");
	default:
		manager(socks[1], page, pagesize, pid, str);
		return EXIT_SUCCESS;
	}
}
