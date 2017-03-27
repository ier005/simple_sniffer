#include "tcpdialog.h"
#include "ui_tcpdialog.h"
#include "tcpdefrag.h"
#include "thread.h"
#include <QDebug>

struct pkt *tcp_head, *tcp_tail;

static void add_tcp(struct pkt *p)
{
    if(tcp_tail) {
        p->id = tcp_tail->id + 1;
        tcp_tail->next = p;
        p->prev = tcp_tail;
        p->next = 0;
        tcp_tail = p;

    }
    else {
        p->prev = 0;
        p->next = 0;
        p->id = 0;
        tcp_tail = tcp_head = p;
    }
}

static void del_tcp()
{
    struct pkt *packet2, *packet = tcp_head;

    while (packet != NULL) {
        packet2 = packet->next;
        free(packet->data);
        free(packet);

        packet = packet2;
    }
    tcp_head = tcp_tail = NULL;
}


TcpDialog::TcpDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TcpDialog),
    pkt_model(new QStandardItemModel),
    filesv(new QFileDialog)
{
    ui->setupUi(this);

    connect(this->ui->tcpView, SIGNAL(clicked(QModelIndex)), this, SLOT(tcpView_clicked(QModelIndex)));
}

TcpDialog::~TcpDialog()
{
    delete ui;
}

void TcpDialog::defrag()
{
    this->show();
    pkt_model->clear();
    ui->textBrws1->clear();
    ui->textBrws2->clear();

    pkt_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("ID")));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Source IP")));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Dest IP")));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Source Port")));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Dest Port")));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Length")));

    ui->tcpView->setModel(pkt_model);
    ui->tcpView->verticalHeader()->hide();
    ui->tcpView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tcpView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    struct pkt *p = pkt_head;
    int i = 0;
    tcp_init(1040);
    while (p) {
        if (p->type == TYPE_IP) {
            struct ip *iph = (struct ip *)(p->data);
            if (iph->ip_p == 6) {
                struct tcp_stream *tcps;
                int flag = process_tcp(p->data, p->len, &tcps);

                if (flag) {

                    pkt_model->setItem(i, 0, new QStandardItem(QString::number(i + 1, 10)));
                    pkt_model->setItem(i, 1, new QStandardItem(inet_ntoa(*(struct in_addr*)&tcps->addr.saddr)));
                    pkt_model->setItem(i, 2, new QStandardItem(inet_ntoa(*(struct in_addr*)&tcps->addr.daddr)));
                    pkt_model->setItem(i, 3, new QStandardItem(QString::number(tcps->addr.source, 10)));
                    pkt_model->setItem(i, 4, new QStandardItem(QString::number(tcps->addr.dest, 10)));
                    pkt_model->setItem(i, 5, new QStandardItem(QString::number(tcps->server.count, 10)));
                    struct pkt *tcp = (struct pkt *) malloc(sizeof(struct pkt));
                    tcp->len = tcps->server.count;
                    tcp->data = (u_char *) malloc(tcp->len);
                    memcpy(tcp->data, tcps->server.data, tcp->len);
                    add_tcp(tcp);
                    i++;

                    pkt_model->setItem(i, 0, new QStandardItem(QString::number(i + 1, 10)));
                    pkt_model->setItem(i, 1, new QStandardItem(inet_ntoa(*(struct in_addr*)&tcps->addr.daddr)));
                    pkt_model->setItem(i, 2, new QStandardItem(inet_ntoa(*(struct in_addr*)&tcps->addr.saddr)));
                    pkt_model->setItem(i, 3, new QStandardItem(QString::number(tcps->addr.dest, 10)));
                    pkt_model->setItem(i, 4, new QStandardItem(QString::number(tcps->addr.source, 10)));
                    pkt_model->setItem(i, 5, new QStandardItem(QString::number(tcps->client.count, 10)));
                    tcp = (struct pkt *) malloc(sizeof(struct pkt));
                    tcp->len = tcps->client.count;
                    tcp->data = (u_char *) malloc(tcp->len);
                    memcpy(tcp->data, tcps->client.data, tcp->len);
                    add_tcp(tcp);
                    i++;
                }
            }
        }
        p = p->next;
    }
    tcp_exit();

}

void TcpDialog::tcpView_clicked(const QModelIndex &index)
{
    struct pkt *packet = tcp_head;
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
    ui->textBrws1->setText(s1);
    ui->textBrws2->setText(s2);
}

void TcpDialog::on_canc_clicked()
{
    this->hide();
    del_tcp();
}

void TcpDialog::on_tcpSave_clicked()
{
    QModelIndex ind = ui->tcpView->currentIndex();
    if (ind.row() == -1) {
        emit err("No stream was selected!");
        return;
    }

    struct pkt *packet = tcp_head;
    int r = ind.row();
    int row = pkt_model->index(r, 0).data().toInt() - 1;
    for (int i = 0; i < row; i++)
        packet = packet->next;

    QString filename = filesv->getSaveFileName(this, "Save as", "./tcp.dat");
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly))
        emit err("File wasn't written!");
    else {
        QDataStream out(&file);
        out.writeRawData((char *)packet->data, packet->len);
        file.close();
    }
}
