#include <linux/hyperv.h>
#include <linux/cdev.h>
#include <linux/hashtable.h>
#include <linux/uio.h>

struct rimbaud_device {
	struct hv_device device;
	struct cdev cdev;
	dev_t devno;

	bool removing;
	atomic_t vsp_pending;
	wait_queue_head_t wait_remove;

	struct class *class;
	struct device *chardev;

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
			u8	guest_compress : 1;
			u8	guest_encrypt : 1;
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

	u32 wait_pending;
	wait_queue_head_t wait_close;
	wait_queue_head_t wait_response;

	bool closing;	// this blob handle is being closed
};

/*
 * Interfaces for VSC - user-mode client library
 */
struct rimbaud_client_openblob_request {
	u64 response_addr;
	u32 timeout;
	guid_t transaction_id;
	
	u32 blob_name_offset; 
	u32 blob_name_length;

	u32 session_token_offset;
	u32 session_token_length;
};

struct rimbaud_client_openblob_response {
	u32 status;
	u32 blob_handle;
};

struct rimbaud_client_closeblob_request {
	u64 response_addr;
	u32 blob_handle;
	u32 timeout;
	guid_t transaction_id;
};

struct rimbaud_client_closeblob_response {
	u32 status;
};

struct rimbaud_client_metadata_cache_hint_request {
	u64 response_addr;
	u32 blob_handle;
	u32 timeout;
	guid_t transaction_id;
	u64 offset;
	u64 length;

	u32 session_token_offset;
	u32 session_token_length;
};

struct rimbaud_client_metadata_cache_hint_response {
	u32 status;
};

struct rimbaud_client_getblob_request {
	u32 blob_handle;
	u32 timeout;
	guid_t transaction_id;
	u64 offset;
	u32 length;

	union {
		u32 flag;
		struct {
			bool guest_compress : 1;
			bool guest_encrypt : 1;
		};
	};

	void* user_buffer; 
	u32 user_buffer_len;

	u32 session_token_offset;
	u32 session_token_length;
}; 

struct rimbaud_client_getblob_response {
	u32 status;
	guid_t transaction_id;
	u32 bytes_written;

	/* Starting offset into the blob for returned data.
	 * When reading compressed append blocks, the response's BlobOffset
	 * may differ from the request's Offset, depending on the append block
	 * boundary.
	 */
	u64 blob_offset;
};

struct rimbaud_client_getblob_responses {
	u32 returned_responses;
	struct rimbaud_client_getblob_response responses[];
};

struct rimbaud_client_getblob_query {
	u64 response_addr;
	u32 blob_handle;
	u32 num_responses; // the size of responses that response_addr can hold
};

struct rimbaud_client_update_session_request {
	u64 response_addr;
	u32 blob_handle;
	u32 timeout;
	guid_t transaction_id;
	u32 session_token_offset;
	u32 session_token_length;
};

struct rimbaud_client_update_session_response {
	u32 status;
};

enum rimbaud_client_command {
	CLIENT_OPEN_BLOB	= 0,
	CLIENT_CLOSE_BLOB	= 1,
	CLIENT_METADATA_HINT	= 2,
	CLIENT_GET_BLOB		= 3,
	CLIENT_UPDATE_SESSION	= 4,
	CLIENT_GET_BLOB_QUERY	= 5,
};

struct rimbaud_client_request {

	u32 command;	// enum rimbaud_client_command
	union {
		struct rimbaud_client_openblob_request openblob;
		struct rimbaud_client_closeblob_request closeblob;
		struct rimbaud_client_metadata_cache_hint_request metadata_hint;
		struct rimbaud_client_getblob_request getblob;
		struct rimbaud_client_update_session_request update_session;
		struct rimbaud_client_getblob_query getblob_query;
	};
};

int rimbaud_client_init(struct rimbaud_device *dev);
