#include "mainwindow.h"
#include <QApplication>
#include <stdio.h>
#include <pcap.h>
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


//bpf_u_int32 ipAddress, ipMask;




int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;


    pcap_if_t *devs;


    if (pcap_findalldevs(&devs, errbuf) == -1) {
        w.showError(errbuf);
        //printf("error: %s\n", errbuf);
        //exit(-1);
    }

    w.showDevice(devs);

    ip_frag_init(5);




    w.show();

    return a.exec();
}
