#include "searchdialog.h"
#include "ui_searchdialog.h"
#include <QDebug>

SearchDialog::SearchDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SearchDialog),
    pkt_model(new QStandardItemModel)
{
    ui->setupUi(this);
}

SearchDialog::~SearchDialog()
{
    delete ui;
}

void SearchDialog::initial()
{
    this->show();
    pkt_model->clear();
    ui->tBrowser->clear();
    ui->tBrowser_2->clear();

    pkt_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ID")));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Dest IP")));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Protocol")));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Length")));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Infomation")));

    ui->tView->setModel(pkt_model);
    ui->tView->verticalHeader()->hide();

    ui->tView->setColumnWidth(0, 40);
    ui->tView->setColumnWidth(3, 60);
    ui->tView->setColumnWidth(4, 60);
    ui->tView->setColumnWidth(5, 400);
    ui->tView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(this->ui->tView, SIGNAL(clicked(QModelIndex)), this, SLOT(tableView_clicked(QModelIndex)));
}



void SearchDialog::on_searchButton_clicked()
{
    pkt_model->clear();
    ui->tBrowser->clear();
    ui->tBrowser_2->clear();

    pkt_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ID")));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Dest IP")));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Protocol")));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Length")));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Infomation")));
    ui->tView->setColumnWidth(0, 40);
    ui->tView->setColumnWidth(3, 60);
    ui->tView->setColumnWidth(4, 60);
    ui->tView->setColumnWidth(5, 400);


    QString s = ui->keyWord->text();
    QByteArray ba = s.toLatin1();
    char *str = ba.data();
    struct pkt *packet = pkt_head;

    for (int k = 0; packet != NULL; packet = packet->next) {
        bool flag = false;
        u_char *d = packet->data;
        unsigned int l = packet->len;
        for (int i = 0; i < l; i++) {
            int j;
            for (j = 0; str[j] != 0 && i + j < l && str[j] == d[i + j]; j++);
            if (str[j] == 0) {
                flag = true;
                break;
            }
        }
        if (flag == true) {


            unsigned int i = packet->id;
            //struct ether_header *ethHdr = (struct ether_header*)(d);

            pkt_model->setItem(k, 0, new QStandardItem(QString::number(i + 1, 10)));
            pkt_model->setItem(k, 4, new QStandardItem(QString::number(l, 10)));

            if (packet->type != TYPE_IP) {
                struct ether_header *ethHdr = (struct ether_header*)(d);
                if (ntohs(ethHdr->ether_type) == ETHERTYPE_ARP) {
                    pkt_model->setItem(k, 3, new QStandardItem("ARP"));
                    arp_handle(d, i);
                }
                else if (ntohs(ethHdr->ether_type) == ETHERTYPE_REVARP)
                    pkt_model->setItem(k, 3, new QStandardItem("RARP"));
                else
                    pkt_model->setItem(k, 3, new QStandardItem("Unknown"));
            }
            else
                ip_handle(d, k);

            k++;
        }
    }
}


void SearchDialog::arp_handle(u_char *pktData, unsigned int i)
{
    struct ether_arp *arpHdr = (struct ether_arp*)(pktData + 14);
    if (arpHdr->ea_hdr.ar_op == 0x0100) {
        QString s = QString("Who has %1? Tell %2").arg(inet_ntoa(*(struct in_addr*)&arpHdr->arp_tpa)).arg(inet_ntoa(*(struct in_addr*)&arpHdr->arp_spa));
        pkt_model->setItem(i, 5, new QStandardItem(s));
        pkt_model->setItem(i, 1, new QStandardItem(inet_ntoa(*(struct in_addr*)&arpHdr->arp_spa)));
        pkt_model->setItem(i, 2, new QStandardItem("BroadCast"));
    }
    else if (arpHdr->ea_hdr.ar_op == 0x0200) {
        QString s = QString("%1 tell %2 its hardware address").arg(inet_ntoa(*(struct in_addr*)&arpHdr->arp_spa)).arg(inet_ntoa(*(struct in_addr*)&arpHdr->arp_tpa));
        pkt_model->setItem(i, 5, new QStandardItem(s));
        pkt_model->setItem(i, 1, new QStandardItem(inet_ntoa(*(struct in_addr*)&arpHdr->arp_spa)));
        pkt_model->setItem(i, 2, new QStandardItem(inet_ntoa(*(struct in_addr*)&arpHdr->arp_tpa)));
    }
}

void SearchDialog::ip_handle(u_char *pktData, unsigned int i)
{
    struct iphdr *ipHdr = (struct iphdr *)(pktData);
    char *proto;
    switch(ipHdr->protocol) {
        case 1:
            proto = "ICMP";
            break;
        case 2:
            proto = "IGMP";
            break;
        case 6:
            proto = "TCP";
            break;
        case 17:
            proto = "UDP";
            break;
        default:
            proto = "UNKNOWN";
    }
    pkt_model->setItem(i, 3, new QStandardItem(proto));
    pkt_model->setItem(i, 1, new QStandardItem(inet_ntoa(*(struct in_addr*)&ipHdr->saddr)));
    pkt_model->setItem(i, 2, new QStandardItem(inet_ntoa(*(struct in_addr*)&ipHdr->daddr)));

    switch(ipHdr->protocol) {
        case 1:
            icmp_handle(pktData, i);
            break;
        case 6:
            tcp_handle(pktData, i);
            break;
        case 17:
            udp_handle(pktData, i);
            break;
    }
}


void SearchDialog::icmp_handle(u_char *pktData, unsigned int i)
{
    struct iphdr *ipHdr = (struct iphdr*)(pktData);
    struct icmphdr *icmpHdr = (struct icmphdr*)(pktData + ipHdr->ihl * 4);
    if (icmpHdr->type == 8) {
        QString s = QString("Echo (ping) request, id=%1, seq=%2").arg(ntohs(icmpHdr->id)).arg(ntohs(icmpHdr->seq));
        pkt_model->setItem(i, 5, new QStandardItem(s));
        //printf("Echo (ping) request, id=%hu, seq=%hu\n", ntohs(icmpHdr->id), ntohs(icmpHdr->seq));
    }
    else if (icmpHdr->type == 0) {
        QString s = QString("Echo (ping) reply, id=%1, seq=%2").arg(ntohs(icmpHdr->id)).arg(ntohs(icmpHdr->seq));
        pkt_model->setItem(i, 5, new QStandardItem(s));
        //printf("Echo (ping) reply, id=%hu, seq=%hu\n", ntohs(icmpHdr->id), ntohs(icmpHdr->seq));

    }
}

void SearchDialog::tcp_handle(u_char *pktData, unsigned int i)
{
    struct iphdr *ipHdr = (struct iphdr*)(pktData);
    struct tcphdr *tcpHdr = (struct tcphdr*)(pktData + ipHdr->ihl * 4);
    QString s = QString("%1->%2  ").arg(ntohs(tcpHdr->source)).arg(ntohs(tcpHdr->dest));
    //printf("%hu->%hu", ntohs(tcpHdr->source), ntohs(tcpHdr->dest));

    char flags[30] = {0};
    strcat(flags, "[");
    if (tcpHdr->urg)
        strcat(flags, "URG ");
    if (tcpHdr->ack)
        strcat(flags, "ACK ");
    if (tcpHdr->psh)
        strcat(flags, "PSH ");
    if (tcpHdr->rst)
        strcat(flags, "RST ");
    if (tcpHdr->syn)
        strcat(flags, "SYN ");
    if (tcpHdr->fin)
        strcat(flags, "FIN ");
    strcat(flags, "]");
    s += flags;
    //printf("  %s", flags);
    s += QString("  Seq=%1 Ack=%2 Win=%3").arg(ntohl(tcpHdr->seq)).arg(ntohl(tcpHdr->ack_seq)).arg(ntohs(tcpHdr->window));
    //printf("Seq=%u Ack=%u Win=%hu\n", ntohl(tcpHdr->seq), ntohl(tcpHdr->ack_seq), ntohs(tcpHdr->window));
    pkt_model->setItem(i, 5, new QStandardItem(s));
}

void SearchDialog::udp_handle(u_char *pktData, unsigned int i)
{
    struct iphdr *ipHdr = (struct iphdr*)(pktData);
    struct udphdr *udpHdr = (struct udphdr*)(pktData + ipHdr->ihl * 4);
    QString s = QString("%1->%2").arg(ntohs(udpHdr->source)).arg(ntohs(udpHdr->dest));
    //printf("%hu->%hu\n", ntohs(udpHdr->source), ntohs(udpHdr->dest));
    pkt_model->setItem(i, 5, new QStandardItem(s));
}

void SearchDialog::tableView_clicked(const QModelIndex &index)
{
    struct pkt *packet = pkt_head;
    int r = index.row();
    int row = pkt_model->index(r, 0).data().toInt() - 1;
    for (int i = 0; i < row; i++)
        packet = packet->next;

    u_char *d = packet->data;

    QString s, s1, s2;
    for(unsigned int i = 0; i < packet->len; i++) {
        s.sprintf(" %02x", d[i]);
        s1 += s;
        s.sprintf("%c", d[i]);
        s2 += s;
        if ((i + 1) % 16 == 0) {
            s1 += "\n";
            s2 += "\n";
        }
    }
    ui->tBrowser->setText(s1);
    ui->tBrowser_2->setText(s2);
}
