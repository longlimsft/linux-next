#ifndef _RIMBAUD_H
#define _RIMBAUD_H

/* user-mode sync request sent through ioctl */
struct xs_fastpath_request_sync_response {
	__u32 status;
	__u32 response_len;
};

struct xs_fastpath_request_sync {
	guid_t guid;
	__u32 timeout;
	__u32 request_len;
	__u32 response_len;
	__u32 data_len;
	__u32 data_valid;
	__aligned_u64 request_buffer;
	__aligned_u64 response_buffer;
	__aligned_u64 data_buffer;
	struct xs_fastpath_request_sync_response response;
};

#define RIMBAUD_MAGIC_NUMBER	'R'
#define IOCTL_XS_FASTPATH_DRIVER_USER_REQUEST _IOWR(RIMBAUD_MAGIC_NUMBER, 10, struct xs_fastpath_request_sync)

#endif /* define _RIMBAUD_H */
