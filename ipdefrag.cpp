#include "ipdefrag.h"
#include <QDebug>

static struct hostfrags **fragtable;
static struct hostfrags *this_host;
static int hash_size;
static int timenow;
static unsigned int time0;
static struct timer_list *timer_head = 0, *timer_tail = 0;


static int jiffies()
{
    struct timeval tv;
    if (timenow)
        return timenow;
    gettimeofday(&tv, 0);
    timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;
    return timenow;
}

static void panic(char *str)
{
    qDebug() << str << endl;
    exit(1);
}

static void add_timer(struct timer_list *x)
{
    if (timer_tail) {
        timer_tail->next =x;
        x->prev = timer_tail;
        x->next = 0;
        timer_tail = x;
    }
    else {
        x->prev = 0;
        x->next = 0;
        timer_tail = timer_head = x;
    }
}

static void del_timer(struct timer_list *x)
{
    if (x->prev)
        x->prev->next = x->next;
    else
        timer_head = x->next;

    if (x->next)
        x->next->prev = x->prev;
    else
        timer_tail = x->prev;
}



static void rmthis_host()
{
    int hash_index = this_host->hash_index;

    if (this_host->prev) {
        this_host->prev->next = this_host->next;
        if (this_host->next)
            this_host->next->prev = this_host->prev;
    }
    else {
        fragtable[hash_index] = this_host->next;
        if (this_host->next)
            this_host->next->prev = 0;
    }
    free(this_host);
    this_host = 0;
}

static void ip_expire(struct ipq *qp)
{
    struct ipfrag *fp;
    struct ipfrag *xp;

    del_timer(&qp->timer);

    if (qp->prev == NULL) {
        this_host->ipqueue = qp->next;
        if (this_host->ipqueue != NULL)
            this_host->ipqueue->prev = NULL;
        else
            rmthis_host();
    }
    else {
        qp->prev->next = qp->next;
        if (qp->next != NULL)
            qp->next->prev = qp->prev;
    }

    fp = qp->fragments;
    while (fp != NULL) {
        xp = fp->next;
        free(fp->skb);
        free(fp);
        fp = xp;
    }

    free(qp->iph);
    free(qp);
}


static struct ipq *ip_create(struct ip *iph)
{
    struct ipq *qp;
    int ihlen;

    qp = (struct ipq *) malloc(sizeof(struct ipq));
    if (!qp)
        panic("No enough memory\n");
    memset(qp, 0, sizeof(struct ipq));

    ihlen = iph->ip_hl * 4;
    qp->iph = (struct ip *)malloc(64);
    if (!qp->iph)
        panic("No enough memory\n");
    memcpy(qp->iph, iph, ihlen);
    qp->len = 0;
    qp->ihlen = ihlen;
    qp->fragments = NULL;
    qp->hf = this_host;

    qp->timer.expires = jiffies() + IP_FRAG_TIME;
    qp->timer.data = qp;
    qp->timer.function = ip_expire;
    add_timer(&qp->timer);

    qp->prev = NULL;
    qp->next = this_host->ipqueue;
    if (qp->next != NULL)
        qp->next->prev = qp;
    this_host->ipqueue = qp;

    return qp;
}

static int frag_index(struct ip *iph)
{
    unsigned int ip = ntohl(iph->ip_dst.s_addr);
    return (ip % hash_size);
}

static int hostfrag_find(struct ip *iph)
{
    int hash_index = frag_index(iph);
    struct hostfrags *hf;

    this_host = 0;
    for (hf = fragtable[hash_index]; hf; hf = hf->next)
        if (hf->ip == iph->ip_dst.s_addr) {
            this_host = hf;
            break;
        }
    if (!this_host)
        return 0;
    else
        return 1;
}

static void hostfrag_create(struct ip *iph)
{
    struct hostfrags *hf = (struct hostfrags *) malloc(sizeof(struct hostfrags));
    int hash_index = frag_index(iph);

    hf->prev = 0;
    hf->next = fragtable[hash_index];
    if (hf->next)
        hf->next->prev = hf;
    fragtable[hash_index] = hf;

    hf->ip = iph->ip_dst.s_addr;
    hf->ipqueue = 0;
    hf->hash_index = hash_index;
    this_host = hf;
}


static struct ipq *ip_find(struct ip *iph)
{
    struct ipq *qp;

    for (qp = this_host->ipqueue; qp; qp = qp->next) {
        if (iph->ip_id ==qp->iph->ip_id &&
            iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
            iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
            iph->ip_p == qp->iph->ip_p) {
            del_timer(&qp->timer);
            return qp;
        }
    }

    return NULL;
}

static struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff *skb, unsigned char *ptr)
{
    struct ipfrag *fp;

    fp = (struct ipfrag *) malloc(sizeof(struct ipfrag));
    if (fp == NULL)
        panic("No enough menory\n");
    memset(fp, 0, sizeof(struct ipfrag));

    fp->offset = offset;
    fp->end = end;
    fp->len = end - offset;
    fp->skb = skb;
    fp->ptr = ptr;

    return fp;
}

static int ip_done(struct ipq * qp)
{
    struct ipfrag *fp;
    int offset;

    if (qp->len == 0)
        return 0;

    fp = qp->fragments;
    offset = 0;
    while (fp != NULL) {
        if (fp->offset > offset)
            return 0;
        offset = fp->end;
        fp = fp->next;
    }

    return 1;
}

static char *ip_glue(struct ipq *qp)
{
    char *skb;
    struct ip *iph;
    struct ipfrag *fp;
    unsigned char *ptr;
    int count, len;

    len = qp->ihlen + qp->len;

    if (len > 65536) {
        ip_expire(qp);
        return NULL;
    }

    if ((skb = (char *) malloc(len)) == NULL)
        panic("No enough memory\n");

    ptr = (unsigned char *)skb;
    memcpy(ptr, qp->iph, qp->ihlen);
    ptr += qp->ihlen;
    count = 0;

    fp = qp->fragments;
    while (fp != NULL) {
        if (fp->len < 0 || fp->offset + qp->ihlen + fp->len > len) {
            ip_expire(qp);
            free(skb);
            return NULL;
        }
        memcpy((ptr + fp->offset), fp->ptr, fp->len);
        count += fp->len;
        fp = fp->next;
    }

    ip_expire(qp);

    iph = (struct ip *)skb;
    iph->ip_off = 0;
    iph->ip_len = htons((iph->ip_hl * 4) + count);

    return skb;
}

static char *ip_defrag(struct ip *iph, struct sk_buff *skb)
{
    struct ipfrag *prev, *next, *tmp;
    struct ipfrag *tfp;
    struct ipq *qp;
    char *skb2;
    unsigned char *ptr;
    int flags, offset;
    int i, ihl, end;

    if (!hostfrag_find(iph) && skb)
        hostfrag_create(iph);

    if (this_host)
        qp = ip_find(iph);
    else
        qp = 0;

    offset = ntohs(iph->ip_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;

    if ((flags & IP_MF) == 0 && offset == 0) {
        if (qp != NULL)
            ip_expire(qp);
        return 0;
    }

    offset <<= 3;
    ihl = iph->ip_hl * 4;

    if (qp != NULL) {
        if (offset == 0) {
            qp->ihlen = ihl;
            memcpy(qp->iph, iph, ihl);
        }

        qp->timer.expires = jiffies() + IP_FRAG_TIME;
        qp->timer.data = qp;
        qp->timer.function = ip_expire;
        add_timer(&qp->timer);
    }
    else
        qp = ip_create(iph);

    if (ntohs(iph->ip_len) + offset > 65536) {
        free(skb);
        return NULL;
    }

    end = offset + ntohs(iph->ip_len) - ihl;
    ptr = (unsigned char *)(skb->data + ihl);

    if ((flags & IP_MF) == 0)
        qp->len = end;

    prev = NULL;
    for (next = qp->fragments; next != NULL; next = next->next) {
        if (next->offset >= offset)
            break;
        prev = next;
    }

    if (prev != NULL && offset < prev->end) {
        i = prev->end - offset;
        offset += i;
        ptr += i;
    }

    for (tmp = next; tmp != NULL; tmp = tfp) {
        tfp = tmp->next;
        if (tmp->offset >= end)
            break;

        i = end - next->offset;
        tmp->len -= i;
        tmp->offset += i;
        tmp->ptr += i;

        if (tmp->len <= 0) {
            if (tmp->prev != NULL)
                tmp->prev->next = tmp->next;
            else
                qp->fragments = tmp->next;

            if (tmp->next != NULL)
                tmp->next->prev = tmp->prev;

            next = tfp;

            free(tmp->skb);
            free(tmp);
        }
    }

    tfp = NULL;
    tfp = ip_frag_create(offset, end, skb, ptr);

    tfp->prev = prev;
    tfp->next = next;
    if (prev != NULL)
        prev->next = tfp;
    else
        qp->fragments = tfp;
    if (next != NULL)
        next->prev = tfp;

    if (ip_done(qp)) {
        skb2 = ip_glue(qp);
        return skb2;
    }

    return NULL;
}

int ip_defrag_stub(struct ip *iph, u_char **defrag)
{
    int offset, flags, tot_len;
    struct sk_buff *skb;

    timenow = 0;
    while (timer_head && timer_head->expires < jiffies()) {
        this_host = (timer_head->data)->hf;
        timer_head->function(timer_head->data);
    }

    offset = ntohs(iph->ip_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;

    if ((flags & IP_MF) == 0 && offset == 0) {
        ip_defrag(iph, 0);
        return IPF_NOTF;
    }

    tot_len = ntohs(iph->ip_len);
    skb = (struct sk_buff *) malloc(tot_len + sizeof(struct sk_buff));
    if (!fragtable)
        panic("No enough memory\n");
    skb->data = (char *)(skb + 1);
    memcpy(skb->data, iph, tot_len);

    if (((*defrag) = (u_char *)ip_defrag((struct ip *)(skb->data), skb)) != NULL)
        return IPF_NEW;

    return IPF_ISF;
}


void ip_frag_init(int n)
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    time0 = tv.tv_sec;
    fragtable = (struct hostfrags **) calloc(n, sizeof(struct hostfrags *));
    if (!fragtable)
        panic("No enough memory\n");

    hash_size = n;
}
