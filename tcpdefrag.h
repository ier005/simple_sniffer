#ifndef TCPDEFRAG_H
#define TCPDEFRAG_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>


# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6


struct skbuff {
    struct skbuff *next;
    struct skbuff *prev;

    void *data;
    u_int len;
    u_int truesize;
    u_int urg_ptr;

    char fin;
    char urg;
    u_int seq;
    u_int ack;
};

struct tuple4 {
    u_short source;
    u_short dest;
    u_int saddr;
    u_int daddr;
};

struct half_stream {
    char state;
    char collect;
    char collect_urg;

    char *data;
    int offset;
    int count;
    int count_new;
    int bufsize;
    int rmem_alloc;

    int urg_count;
    u_int acked;
    u_int seq;
    u_int ack_seq;
    u_int first_data_seq;
    u_char urgdata;
    u_char count_new_urg;
    u_char urg_seen;
    u_int urg_ptr;
    u_short window;
    u_char ts_on;
    u_char wscale_on;
    u_int curr_ts;
    u_int wscale;

    struct skbuff *list;
    struct skbuff *listtail;
};

struct tcp_stream {
    struct tuple4 addr;
    char nids_state;
    struct half_stream client;
    struct half_stream server;
    struct tcp_stream *next_node;
    struct tcp_stream *prev_node;
    int hash_index;
    struct tcp_stream *next_time;
    struct tcp_stream *prev_time;
    int read;
    struct tcp_stream *next_free;
    void *user;
};


int process_tcp(u_char *, int, struct tcp_stream **);
int tcp_init(int);
void tcp_exit(void);

#endif // TCPDEFRAG_H
