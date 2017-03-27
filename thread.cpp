#include "thread.h"
#include <QDebug>

struct pkt *pkt_head, *pkt_tail, *pkt_now;

void add_pkt(struct pkt *p)
{
    if(pkt_tail) {
        p->id = pkt_tail->id + 1;
        pkt_tail->next = p;
        p->prev = pkt_tail;
        p->next = 0;
        pkt_tail = p;

    }
    else {
        p->prev = 0;
        p->next = 0;
        p->id = 0;
        pkt_tail = pkt_head = p;
    }
}


Thread::Thread()
{
    stopped = false;

}

void Thread::run()
{
    while (!stopped) {
        //m_mutex.lock();


        struct pkt *packet;
        struct pcap_pkthdr h;
        const u_char *d;
        u_char *dd;

        d = pcap_next(phandle, &h);
        struct ether_header *ethHdr = (struct ether_header *)d;
        if (!(ntohs(ethHdr->ether_type) == ETHERTYPE_IP)) {
            packet = (struct pkt *) malloc(sizeof(struct pkt));
            dd = (u_char *) malloc(h.caplen);
            memcpy(dd, d, h.caplen);
            packet->data = dd;
            packet->len = h.caplen;
            packet->type = TYPE_NIP;
            add_pkt(packet);
            emit rcvone();
        }
        else {
            int ipf;

            ipf = ip_defrag_stub((struct ip *)(d + 14), &dd);

            if (ipf == IPF_NOTF) {
                packet = (struct pkt *) malloc(sizeof(struct pkt));
                dd = (u_char *) malloc(h.caplen - 14);
                memcpy(dd, d + 14, h.caplen - 14);
                packet->data = dd;
                packet->len = h.caplen - 14;
                packet->type = TYPE_IP;
                add_pkt(packet);
                emit rcvone();

            }
            else if (ipf == IPF_NEW) {
                packet = (struct pkt *) malloc(sizeof(struct pkt));
                struct ip *iph = (struct ip *)(dd);
                int l = ntohs(iph->ip_len);
                packet->data = dd;
                packet->len = l;
                packet->type = TYPE_IP;
                add_pkt((packet));
                emit rcvone();
            }
        }



        //m_mutex.unlock();
    }
}

void Thread::thread_start()
{
    struct pkt *packet2, *packet = pkt_head;

    while (packet != NULL) {
        packet2 = packet->next;
        free(packet->data);
        free(packet);

        packet = packet2;
    }
    pkt_head = pkt_tail = pkt_now = NULL;


    stopped = false;
    this->start();
}



void Thread::cap_ctl()
{
    if (stopped == false) {

        //m_mutex.lock();
        stopped = true;
    }
    else {
        //m_mutex.unlock();
        stopped = false;
        this->start();
    }
}


void Thread::stop_cap()
{
    if (stopped == false)
        stopped = true;


}
