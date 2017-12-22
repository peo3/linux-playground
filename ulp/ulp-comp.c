#include <linux/module.h>
#include <linux/zlib.h>

#include <net/tcp.h>
#include <net/inet_common.h>

MODULE_AUTHOR("peo3");
MODULE_DESCRIPTION("compression ULP");
MODULE_LICENSE("GPL");

struct comp_context {
	int	(*sendmsg)(struct sock *sk, struct msghdr *msg,
			   size_t len);
	int	(*recvmsg)(struct sock *sk, struct msghdr *msg,
			   size_t len, int noblock, int flags,
			   int *addr_len);
	int	(*setsockopt)(struct sock *sk, int level,
			      int optname, char __user *optval,
			      unsigned int optlen);
	int	(*getsockopt)(struct sock *sk, int level,
			      int optname, char __user *optval,
			      int __user *optlen);
};

struct comp_hdr {
	uint32_t olen;		/* original length */
	uint32_t clen;		/* compressed length */
	char payload[1];	/* payload */
} __packed;

#define COMP_HDRSIZE		(sizeof(uint32_t) * 2)
#define COMP_MINIMUM_SIZE	64

static struct proto com_prot;
static struct z_stream_s stream;

/* Derived from nvram_compress() */
static int comp_compress(const void *in, void *out, size_t inlen,
			 size_t outlen)
{
	int err, ret;

	ret = -EIO;
	err = zlib_deflateInit2(&stream,
				Z_DEFAULT_COMPRESSION,
				Z_DEFLATED,
				-DEF_WBITS,
				MAX_MEM_LEVEL,
				Z_DEFAULT_STRATEGY);
	if (err != Z_OK)
		goto error;

	stream.next_in = in;
	stream.avail_in = inlen;
	stream.total_in = 0;
	stream.next_out = out;
	stream.avail_out = outlen;
	stream.total_out = 0;

	err = zlib_deflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
		goto error;

	err = zlib_deflateEnd(&stream);
	if (err != Z_OK)
		goto error;

	if (stream.total_out >= stream.total_in)
		goto error;

	ret = stream.total_out;
error:
	return ret;
}

static int comp_decompress(const void *in, void *out, size_t inlen,
			   size_t outlen)
{
	return zlib_inflate_blob(out, outlen, in, inlen);
}

static inline struct comp_context *comp_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return icsk->icsk_ulp_data;
}

int comp_setsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
	struct comp_context *ctx = comp_get_ctx(sk);

	return ctx->setsockopt(sk, level, optname, optval, optlen);
}

int comp_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct comp_context *ctx = comp_get_ctx(sk);

	return ctx->getsockopt(sk, level, optname, optval, optlen);
}

struct kvec *comp_clone_iov(struct iov_iter *iter, int *nvecs)
{
	struct kvec *kvec;
	struct iov_iter _iter;
	struct iovec iov;
	int i;

	kvec = kcalloc(iter->count, sizeof(*kvec), GFP_KERNEL);

	i = 0;
	iov_for_each(iov, _iter, *iter) {
		unsigned long len = iov.iov_len + COMP_HDRSIZE;

		kvec[i].iov_base = kmalloc(len, GFP_KERNEL);
		kvec[i].iov_len = len;
		i++;
	}
	*nvecs = i;

	return kvec;
}

void comp_free_kvec(struct kvec *kvec, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (kvec[i].iov_base)
			kfree(kvec[i].iov_base);
		i++;
	}
	kfree(kvec);
}

int comp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct comp_context *ctx = comp_get_ctx(sk);
	struct iov_iter iter;
	struct iovec iov;
	struct kvec *kvec;
	int i, ret, nvecs;
	size_t total = 0;

	/* Clone iov for compressed data */
	kvec = comp_clone_iov(&msg->msg_iter, &nvecs);

	i = 0;
	iov_for_each(iov, iter, msg->msg_iter) {
		unsigned long len = iov.iov_len;
		struct comp_hdr *hdr;

		hdr = (struct comp_hdr *) kvec[i].iov_base;
		hdr->olen = htonl(len);

		/* Compress the payload only if it's big enough */
		if (len >= COMP_MINIMUM_SIZE) {
			int clen;
			clen = comp_compress(iov.iov_base, hdr->payload, len, len);
			if (clen < 0) {
				ret = clen;
				goto error;
			}
			hdr->clen = htonl(clen);
			kvec[i].iov_len = clen + COMP_HDRSIZE;
		} else {
			hdr->clen = htonl(len);
			if (copy_from_user(hdr->payload, iov.iov_base, len)) {
				ret = -EFAULT;
				goto error;
			}
			kvec[i].iov_len = len + COMP_HDRSIZE;
		}
		total += kvec[i].iov_len;

		i++;
	}
	/* Use kvec */
	msg->msg_iter.kvec = kvec;
	msg->msg_iter.type = ITER_KVEC;
	msg->msg_iter.count = total;

	/* tcp_sendmsg */
	ret = ctx->sendmsg(sk, msg, total);
	/* XXX should we restore iov? */
error:
	comp_free_kvec(kvec, nvecs);

	return ret;
}

int comp_recvmsg(struct sock *sk, struct msghdr *msg, size_t size,
		 int noblock, int flags, int *addr_len)
{
	struct comp_context *ctx = comp_get_ctx(sk);
	struct iov_iter iter;
	struct iovec iov;
	struct kvec *kvec;
	int i, ret, nvecs;
	const struct iovec *iovec;
	size_t count, total = 0;

	kvec = comp_clone_iov(&msg->msg_iter, &nvecs);
	iovec = msg->msg_iter.iov;
	count = msg->msg_iter.count;

	/* Receive data with kvec */
	msg->msg_iter.kvec = kvec;
	msg->msg_iter.type = ITER_KVEC;

	/* tcp_recvmsg */
	ret = ctx->recvmsg(sk, msg, size, noblock, flags, addr_len);
	if (ret <= 0)
		goto error;

	/* Restore iov for iov_for_each */
	msg->msg_iter.iov = iovec;
	msg->msg_iter.type = ITER_IOVEC;
	/* Adjust for iov_for_each */
	msg->msg_iter.iov_offset = 0;
	msg->msg_iter.count = count;

	i = 0;
	iov_for_each(iov, iter, msg->msg_iter) {
		unsigned long len = iov.iov_len;
		struct comp_hdr *hdr;
		uint32_t olen, clen;

		hdr = (struct comp_hdr *) kvec[i].iov_base;
		if (hdr == NULL)
			break; // XXX
		olen = ntohl(hdr->olen);
		clen = ntohl(hdr->clen);

		if (olen >= COMP_MINIMUM_SIZE) {
			int dlen;
			dlen = comp_decompress(hdr->payload, iov.iov_base,
					       clen, len);
			if (dlen < 0) {
				printk(KERN_ERR "comp_decompress failed: %d\n",
				       dlen);
				ret = dlen;
				goto error;
			}
		} else {
			if (copy_to_user(iov.iov_base, hdr->payload, olen)) {
				ret = -EFAULT;
				goto error;
			}
		}

		/* FIXME support multiple data blocks */

		iov.iov_len = olen;
		total += olen;
		i++;
	}
	msg->msg_iter.iov_offset = total;
	msg->msg_iter.count = count - total;
	ret = total;
error:
	comp_free_kvec(kvec, nvecs);

	return ret;
}

static int comp_init(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct comp_context *ctx;
	int rc = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		rc = -ENOMEM;
		goto out;
	}
	icsk->icsk_ulp_data = ctx;

	/* Save original handlers */
	ctx->setsockopt	= sk->sk_prot->setsockopt;
	ctx->getsockopt	= sk->sk_prot->getsockopt;
	ctx->sendmsg	= sk->sk_prot->sendmsg;
	ctx->recvmsg	= sk->sk_prot->recvmsg;

	sk->sk_prot = &com_prot;
out:
	return rc;
}

static struct tcp_ulp_ops tcp_comp_ulp_ops __read_mostly = {
	.name	= "comp",
	.owner	= THIS_MODULE,
	.init	= comp_init,
};

static int __init comp_register(void)
{
	/* For comp_compress */
	stream.workspace = kmalloc(zlib_deflate_workspacesize(
				   MAX_WBITS, MAX_MEM_LEVEL), GFP_KERNEL);

	com_prot		= tcp_prot;
	com_prot.setsockopt	= comp_setsockopt;
	com_prot.getsockopt	= comp_getsockopt;
	com_prot.sendmsg	= comp_sendmsg;
	com_prot.recvmsg	= comp_recvmsg;

	tcp_register_ulp(&tcp_comp_ulp_ops);

	return 0;
}

static void __exit comp_unregister(void)
{
	tcp_unregister_ulp(&tcp_comp_ulp_ops);
	kfree(stream.workspace);
}

module_init(comp_register);
module_exit(comp_unregister);
