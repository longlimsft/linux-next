struct rimbaud_client_openblob_request {
	u32 timeout;
	guid_t transaction_id;
	
	u32 blob_name_offset; 
	u32 blob_name_length;

	u32 session_token_offset;
	u32 sessino_token_length;

	// response
	u32 status;
	u32 blob_handle;
};

struct rimbaud_client_closeblob_request {
	u32 blob_handle;
	u32 timeout;

	// response
	u32 status;
};

struct rimbaud_client_metadata_cache_hint_request {
	u32 blob_handle;
	u32 timeout;
	guit_t transaction_id;
	u64 offset;
	u64 length;

	u32 session_token_offset;
	u32 session_token_length;

	//response
	u32 status;
}

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
	u32 bytes_written;
	u32 status;
	// Starting offset into the blob for returned data.
	// When reading compressed append blocks, the response's BlobOffset may differ from
	// the request's Offset, depending on the append block boundary.
	u64 blob_offset;
};

struct rimbaud_client_update_session_request {
	u32 blob_handle;
	u32 timeout;
	guid_t transaction_id;
	u32 session_token_offset;
	u32 session_token_length;

	//response
	u32 status;
};

enum rimbaud_client_command {
	rimbaud_client_open_blob = 0,
	rimbaud_client_close_blob,
	rimbaud_client_metadata_hint,
	rimbaud_client_get_blob,
	rimbaud_client_update_session
};

struct rimbaud_client_request {

	u32 command;
	union {
		struct rimbaud_client_openblob_request openblob;
		struct rimbaud_client_closeblob_request closeblob;
		struct rimbaud_client_metadata_cache_hint_request metadata_hint;
		struct rimbaud_client_getblob_request getblob;
		struct rimbaud_client_update_session_request update_session;
	};
};

int rimbaud_client_init()
{
	return 0;
}
