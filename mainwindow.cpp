#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtDebug>


char errbuf[PCAP_ERRBUF_SIZE];



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    dialog(new errodialog(this)),
    fdlg(new filterDialog(this)),
    pkt_model(new QStandardItemModel),
    thread(new Thread()),
    filesave(new QFileDialog),
    searchDialog(new SearchDialog(this)),
    tcpDialog(new TcpDialog(this)),
    started(false)
{
    ui->setupUi(this);
    ui->pushButton_2->hide();

    pkt_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ID")));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Dest IP")));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Protocol")));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Length")));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Infomation")));

    ui->tableView->setModel(pkt_model);
    ui->tableView->verticalHeader()->hide();

    ui->tableView->setColumnWidth(0, 40);
    ui->tableView->setColumnWidth(3, 60);
    ui->tableView->setColumnWidth(4, 60);
    ui->tableView->setColumnWidth(5, 400);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(ui->pushButton, SIGNAL(clicked()), this, SLOT(sscap()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(pushButton_2_clicked()));
    connect(fdlg, SIGNAL(error()), dialog, SLOT(showErr()));
    connect(fdlg, SIGNAL(success()), thread, SLOT(thread_start()));
    connect(fdlg, SIGNAL(success()), this, SLOT(changeButton1()));
    connect(fdlg, SIGNAL(success()), this, SLOT(showButton2()));
    connect(thread, SIGNAL(rcvone()), this, SLOT(cap()));
    connect(this, SIGNAL(end_cap()), thread, SLOT(stop_cap()));
    connect(this, SIGNAL(end_cap()), this, SLOT(hideButton2()));
    connect(this, SIGNAL(pause()), thread, SLOT(cap_ctl()));
    connect(this, SIGNAL(search()), searchDialog, SLOT(initial()));
    connect(ui->tableView, SIGNAL(clicked(QModelIndex)), this, SLOT(on_tableView_clicked(QModelIndex)));
    connect(this, SIGNAL(defrag()), tcpDialog, SLOT(defrag()));
    connect(tcpDialog, SIGNAL(err(char*)), this, SLOT(rerr(char *)));
}

MainWindow::~MainWindow()
{
    delete ui;
    delete dialog;
    delete fdlg;
    delete pkt_model;
    delete thread;
    delete filesave;
    delete searchDialog;
}

void MainWindow::showError(char *errbuf)
{
    dialog->setLabel(errbuf);
    dialog->show();
}

void MainWindow::showDevice(pcap_if_t *devs)
{
    QStringList list;
    while (devs) {
        QString str;
        str += devs->name;
        //printf("%s", devs->name);
        //if (devs->description)
            //printf(": %s\n", devs->description);

        list.append(str);
        devs = devs->next;
    }
    ui->comboBox->addItems(list);
}

void MainWindow::sscap()
{
    if (started == false) {

        phandle = pcap_open_live(qPrintable(ui->comboBox->currentText()), 65536, 1, 0, errbuf);
        if (phandle == NULL) {
            dialog->setLabel(errbuf);
            dialog->show();
        }
        else{

            fdlg->show();
        }
    }
    else {

        emit end_cap();
        ui->label->setText("Select network card:");
        ui->comboBox->show();
        //pcap_close(phandle);
        started = false;
        //pkt_model->clear();
        ui->pushButton->setText("Start Cap");

    }

}

void MainWindow::changeButton1()
{
    ui->textBrowser->clear();
    ui->textBrowser_2->clear();
    pkt_model->clear();
    pkt_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ID")));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Dest IP")));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Protocol")));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Length")));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Infomation")));
    ui->tableView->setColumnWidth(0, 40);
    ui->tableView->setColumnWidth(3, 60);
    ui->tableView->setColumnWidth(4, 60);
    ui->tableView->setColumnWidth(5, 400);

    ui->label->setText("Capturing packets from " + ui->comboBox->currentText());
    ui->comboBox->hide();
    ui->pushButton->setText("Stop Cap");
    started = true;
}

void MainWindow::showButton2()
{
    ui->pushButton_2->setText("Pause");
    ui->pushButton_2->show();
}

void MainWindow::hideButton2()
{
    ui->pushButton_2->hide();

}

void MainWindow::pushButton_2_clicked()
{
    emit pause();

    if (thread->stopped == false)
        ui->pushButton_2->setText("Pause");
    else
        ui->pushButton_2->setText("Continue");
}

void MainWindow::cap()
{

    if (pkt_now)
        pkt_now = pkt_now->next;
    else
        pkt_now = pkt_head;

    u_char *d = pkt_now->data;
    unsigned int l = pkt_now->len;
    unsigned int i = pkt_now->id;
    //struct ether_header *ethHdr = (struct ether_header*)(d);

    pkt_model->setItem(i, 0, new QStandardItem(QString::number(i + 1, 10)));
    pkt_model->setItem(i, 4, new QStandardItem(QString::number(l, 10)));
    //pkt_model->setItem(i, 1, new QStandardItem(ether_ntoa((ether_addr *)ethHdr->ether_shost)));
    //pkt_model->setItem(i, 2, new QStandardItem(ether_ntoa((ether_addr *)ethHdr->ether_dhost)));
    if (pkt_now->type != TYPE_IP) {
        struct ether_header *ethHdr = (struct ether_header*)(d);
        if (ntohs(ethHdr->ether_type) == ETHERTYPE_ARP) {
            pkt_model->setItem(i, 3, new QStandardItem("ARP"));
            arp_handle(d, i);
        }
        else if (ntohs(ethHdr->ether_type) == ETHERTYPE_REVARP)
            pkt_model->setItem(i, 3, new QStandardItem("RARP"));
        else
            pkt_model->setItem(i, 3, new QStandardItem("Unknown"));
    }
    else
        ip_handle(d, i);



}

void MainWindow::arp_handle(u_char *pktData, unsigned int i)
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


void MainWindow::ip_handle(u_char *pktData, unsigned int i)
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

void MainWindow::icmp_handle(u_char *pktData, unsigned int i)
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

void MainWindow::tcp_handle(u_char *pktData, unsigned int i)
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

void MainWindow::udp_handle(u_char *pktData, unsigned int i)
{
    struct iphdr *ipHdr = (struct iphdr*)(pktData);
    struct udphdr *udpHdr = (struct udphdr*)(pktData + ipHdr->ihl * 4);
    QString s = QString("%1->%2").arg(ntohs(udpHdr->source)).arg(ntohs(udpHdr->dest));
    //printf("%hu->%hu\n", ntohs(udpHdr->source), ntohs(udpHdr->dest));
    pkt_model->setItem(i, 5, new QStandardItem(s));
}




void MainWindow::on_tableView_clicked(const QModelIndex &index)
{
    struct pkt *packet = pkt_head;
    int row = index.row();
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
    ui->textBrowser->setText(s1);
    ui->textBrowser_2->setText(s2);
}

void MainWindow::on_pushButton_3_clicked()
{
    QModelIndexList selected = ui->tableView->selectionModel()->selectedIndexes();
    if (selected.isEmpty()) {
        showError("No packets were selected!");
    }
    else {
        QString filename = filesave->getSaveFileName(this, "Save as", "./packets.txt");
        QFile file(filename);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
            showError("File wasn't written!");
        else {
            int i = 0;
            foreach(QModelIndex index, selected) {
                if (index.column() == 0) {
                    int row = index.row();
                    struct pkt *packet = pkt_head;
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
                    s1 += "\n";
                    s2 += "\n\n";

                    i++;
                    QTextStream in(&file);
                    in << QString("Packet ID: %1\nSource IP: %2  Dest IP: %3\nProtocol: %4  Length: %5\nInfomation: %6\n").arg(pkt_model->data(pkt_model->index(row, 0)).toString()).arg(pkt_model->data(pkt_model->index(row, 1)).toString()).arg(pkt_model->data(pkt_model->index(row, 2)).toString()).arg(pkt_model->data(pkt_model->index(row, 3)).toString()).arg(pkt_model->data(pkt_model->index(row, 4)).toString()).arg(pkt_model->data(pkt_model->index(row, 5)).toString()) << s1 << s2;

                }
            }
            file.close();
        }
    }
}

void MainWindow::on_pushButton_4_clicked()
{
    if (pkt_tail == NULL) {
        showError("No packets were captured!");
    }
    else
        emit search();
}

void MainWindow::on_pushButton_5_clicked()
{
    if (pkt_tail == NULL) {
        showError("No packets were captured!");
    }
    else
        emit defrag();
}


void MainWindow::rerr(char *err)
{
    showError(err);
}
