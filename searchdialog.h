#ifndef SEARCHDIALOG_H
#define SEARCHDIALOG_H

#include <QDialog>
#include <QStandardItemModel>
#include "thread.h"
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

namespace Ui {
class SearchDialog;
}

class SearchDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SearchDialog(QWidget *parent = 0);
    ~SearchDialog();
    void arp_handle(u_char *, unsigned int);
    void ip_handle(u_char *, unsigned int);
    void show_data(u_char *, unsigned int);
    void icmp_handle(u_char *, unsigned int);
    void tcp_handle(u_char *, unsigned int);
    void udp_handle(u_char *, unsigned int);

private:
    Ui::SearchDialog *ui;
    QStandardItemModel *pkt_model;

private slots:
    void initial();
    void on_searchButton_clicked();
    void tableView_clicked(const QModelIndex &index);
};



struct icmphdr {
    u_char type;
    u_char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
};

#endif // SEARCHDIALOG_H
