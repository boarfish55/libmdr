#ifndef COUNTER_NAMES_H
#define COUNTER_NAMES_H

__BEGIN_DECLS

const char *counter_names[] = {
	"restarts",             /* COUNTER_RESTARTS */
	"messages_in",          /* COUNTER_MESSAGES_IN */
	"messages_in_denied",   /* COUNTER_MESSAGES_IN_DENIED */
	"messages_out",         /* COUNTER_MESSAGES_OUT */
	"raw_bytes_in",         /* COUNTER_RAW_BYTES_IN */
	"raw_bytes_out",        /* COUNTER_RAW_BYTES_OUT */
	"ssl_bytes_in",         /* COUNTER_SSL_BYTES_IN */
	"ssl_bytes_out",        /* COUNTER_SSL_BYTES_OUT */
	"total_clients",        /* COUNTER_TOTAL_CLIENTS */
	"total_active_clients", /* COUNTER_TOTAL_ACTIVE_CLIENTS */
	"read_pauses",          /* COUNTER_READ_PAUSES */
	"wake_for_accept"       /* COUNTER_WAKE_FOR_ACCEPT */
};

__END_DECLS

#endif
