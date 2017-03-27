#ifndef THREAD_H
#define THREAD_H

#include <QThread>
//#include <QMutex>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <string.h>
#include <netinet/udp.h>
#include "filterdialog.h"
#include "ipdefrag.h"

class Thread : public QThread
{
    Q_OBJECT;

public:
    Thread();
    volatile bool stopped;
    
private:
    void run();

    //QMutex m_mutex;
    
signals:
    void rcvone();
    
private slots:
    void cap_ctl();
    void thread_start();
    void stop_cap();

};


#define TYPE_IP 0
#define TYPE_NIP 1

struct pkt {
    struct pkt *next = NULL;
    struct pkt *prev = NULL;
    u_char type;
    unsigned int id;
    unsigned int len;
    u_char *data;

};



void add_pkt(struct pkt *);

extern struct pkt *pkt_head, *pkt_tail, *pkt_now;

#endif // THREAD_H
