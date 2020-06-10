#ifndef _RIMBAUD_H
#define _RIMBAUD_H

#include <linux/hyperv.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/uio.h>

struct rimbaud_device {
	struct hv_device *device;
//	struct cdev cdev;
//	dev_t devno;

	bool removing;
	atomic_t vsp_pending;
	wait_queue_head_t wait_remove;

//	struct class *class;
//	struct device *chardev;

	// hash table for opened blob handles, 1024 hash entries
	DECLARE_HASHTABLE(read_blob_hash, 10);
	spinlock_t read_blob_hash_lock;
};

/*
 * Interfaces for VSC - VSP
 */
enum rimbaud_request_type {
	OPEN_BLOB			= 1,
	CLOSE_BLOB			= 2,
	METADATA_CACHE_HINT		= 3,
	GET_BLOB			= 4,
	UPDATE_SESSION			= 5,
	VERSION_NEGOTIATE		= 6,
};

// Header for all rimbaud request packets
struct rimbaud_packet_request {
	u32	length;
	u32	blob_handle;

	u32	type;	// enum rimbaud_request_type

	// Request timeout in milliseconds
	u32	timeout;
	guid_t	transaction_id;

	// Offset into the packet buffer for the sessin token
	u32	session_token_offset;
	u32	session_token_length;
} __packed;

struct rimbaud_version_negotiate_request {
	struct rimbaud_packet_request header;

	// Offset into the packet buffer for supported version list
	// each version has major/minor -> 4 bytes total
	u32	version_list_offset;
	u32	version_list_length;
} __packed;

#define RIMBAUD_VERSION_MAJOR	1
#define RIMBAUD_VERSION_MINOR	0

struct rimbaud_open_blob_request {
	struct rimbaud_packet_request header;

	// Offset into the packet buffer for the blob name
	u32	blob_name_offset;
	u32	blob_name_length;
} __packed;

// for rimbaud_close_blob the packet is just a rimbaud_packet_request

struct rimbaud_metadata_hint_request {
	struct rimbaud_packet_request header;

	// Offset into the blob where cached metadata should start
	u64	offset;

	// Length of the blob section to cache metadata
	u64	length;
} __packed;

struct rimbaud_get_blob_request {
	struct rimbaud_packet_request header;

	// Request flags
	union {
		u32	all_flags;
		struct {
			u32	guest_compress : 1;
			u32	guest_encrypt : 1;
			u32	reserved : 30;
		};
	};

	// Offset into the blob to read
	u64 offset;

	// Length of the blob section to read
	u32 length;
} __packed;

// Header for rimbaud response packets
struct rimbaud_packet_response {
	u32	length;
	u32	status;
} __packed;

struct rimbaud_version_negotiate_response {
	struct rimbaud_packet_response header;
	u16 selected_major_version;
	u16 selected_minor_version;
} __packed;

struct rimbaud_open_blob_response {
	struct rimbaud_packet_response header;
	u32 blob_handle;
} __packed;

struct rimbaud_get_blob_response {
	struct rimbaud_packet_response header;

	// Bytes written to data buffer
	u32	bytes_written;

	// Starting offset into the blob for returned data
	u64	blob_offset;
} __packed;

// used by device for tracking requests/responses
struct rimbaud_request{
	u32 type;
	u32 handle;
	guid_t transaction_id;
	void *vsp_response_packet;
	struct completion wait_event;
	struct page **pagevec;
	int num_pages;
	struct list_head list;
};

struct blob_handle_hash_list {
	u32 blob_handle;
	struct hlist_node node;
	struct list_head head;	 // link list to VSP responses for this handle

	bool closing;		// this blob handle is being closed
	u32 query_pending;		// pending get_blob_query
	u32 vsp_request_pending;	// pending get_blob
	wait_queue_head_t wait_close;

	wait_queue_head_t wait_response;
};

/*
 * Interfaces for VSC - user-mode client library
 */
struct rimbaud_client_openblob_request {
	__aligned_u64 response_addr;
	__u32 timeout;
	guid_t transaction_id;
	
	__u32 blob_name_offset; 
	__u32 blob_name_length;

	__u32 session_token_offset;
	__u32 session_token_length;
};

struct rimbaud_client_openblob_response {
	__u32 status;
	__u32 blob_handle;
};

struct rimbaud_client_closeblob_request {
	__aligned_u64 response_addr;
	__u32 blob_handle;
	__u32 timeout;
	guid_t transaction_id;
};

struct rimbaud_client_closeblob_response {
	__u32 status;
};

struct rimbaud_client_metadata_cache_hint_request {
	__aligned_u64 response_addr;
	__u32 blob_handle;
	__u32 timeout;
	guid_t transaction_id;
	__aligned_u64 offset;
	__aligned_u64 length;

	__u32 session_token_offset;
	__u32 session_token_length;
};

struct rimbaud_client_metadata_cache_hint_response {
	__u32 status;
};

struct rimbaud_client_getblob_request {
	__u32 blob_handle;
	__u32 timeout;
	guid_t transaction_id;
	__aligned_u64 offset;
	__u32 length;

	union {
		__u32 flag;
		struct {
			__u32 guest_compress : 1;
			__u32 guest_encrypt : 1;
			__u32 reserved : 30;
		};
	};

	__aligned_u64 user_buffer;
	__u32 user_buffer_len;

	__u32 session_token_offset;
	__u32 session_token_length;
}; 

struct rimbaud_client_getblob_response {
	__u32 status;
	guid_t transaction_id;
	__u32 bytes_written;

	/* Starting offset into the blob for returned data.
	 * When reading compressed append blocks, the response's BlobOffset
	 * may differ from the request's Offset, depending on the append block
	 * boundary.
	 */
	__aligned_u64 blob_offset;
};

struct rimbaud_client_getblob_responses {
	__u32 returned_responses;
	struct rimbaud_client_getblob_response responses[];
};

struct rimbaud_client_getblob_query {
	__aligned_u64 response_addr;
	__u32 blob_handle;
	__u32 num_responses; // the size of responses that response_addr can hold
};

struct rimbaud_client_update_session_request {
	__aligned_u64 response_addr;
	__u32 blob_handle;
	__u32 timeout;
	guid_t transaction_id;
	__u32 session_token_offset;
	__u32 session_token_length;
};

struct rimbaud_client_update_session_response {
	__u32 status;
};

enum rimbaud_client_command {
	CLIENT_OPEN_BLOB	= 0,
	CLIENT_CLOSE_BLOB	= 1,
	CLIENT_METADATA_HINT	= 2,
	CLIENT_GET_BLOB		= 3,
	CLIENT_UPDATE_SESSION	= 4,
	CLIENT_GET_BLOB_QUERY	= 5,
};

struct rimbaud_client_request_hdr {
	__u32 command;		// enum rimbaud_client_command
	__u16 in_bytes;		// total bytes of this request, not including this hdr
	__u16 out_bytes;	// total bytes of response in response_addr
	__aligned_u64 response_addr;	// the response address for VSC to return data
};

struct rimbaud_client_request {
	struct rimbaud_client_request_hdr hdr;
	union {
		struct rimbaud_client_openblob_request openblob;
		struct rimbaud_client_closeblob_request closeblob;
		struct rimbaud_client_metadata_cache_hint_request metadata_hint;
		struct rimbaud_client_getblob_request getblob;
		struct rimbaud_client_update_session_request update_session;
		struct rimbaud_client_getblob_query getblob_query;
	};
};

#endif /* define _RIMBAUD_H */
