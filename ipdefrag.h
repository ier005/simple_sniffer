#ifndef IPDEFRAG_H
#define IPDEFRAG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/time.h>

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

#define IP_FRAG_TIME (30 * 1000)
#define IPF_NOTF 0
#define IPF_NEW 1
#define IPF_ISF 2

struct sk_buff {
    char *data;
    int truesize;
};

struct timer_list {
    struct timer_list *prev;
    struct timer_list *next;
    int expires;
    void (*function)(struct ipq*);
    struct ipq *data;
};


struct hostfrags {
    struct ipq *ipqueue;
    int ip_frag_mem;
    unsigned int ip;
    int hash_index;
    struct hostfrags *prev;
    struct hostfrags *next;
};

struct ipq {
    unsigned char *mac;
    struct ip *iph;
    int len;
    short ihlen;
    short maclen;
    struct timer_list timer;
    struct ipfrag *fragments;
    struct hostfrags *hf;
    struct ipq *next;
    struct ipq *prev;
};

struct ipfrag {
    int offset;
    int end;
    int len;
    struct sk_buff *skb;
    unsigned char *ptr;
    struct ipfrag *next;
    struct ipfrag *prev;
};


//extern struct hostfrags **fragtable;

void ip_frag_init(int);
int ip_defrag_stub(struct ip *, u_char **);

#endif // IPDEFRAG_H
