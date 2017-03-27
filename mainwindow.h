#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "errodialog.h"
#include "filterdialog.h"
#include <pcap.h>
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
#include <QFileDialog>
#include "searchdialog.h"
#include "tcpdialog.h"


extern char errbuf[PCAP_ERRBUF_SIZE];


namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void showError(char *);
    void showDevice(pcap_if_t *);
    void addpkt();
    void arp_handle(u_char *, unsigned int);
    void ip_handle(u_char *, unsigned int);
    void show_data(u_char *, unsigned int);
    void icmp_handle(u_char *, unsigned int);
    void tcp_handle(u_char *, unsigned int);
    void udp_handle(u_char *, unsigned int);

private:
    Ui::MainWindow *ui;
    errodialog *dialog;
    filterDialog *fdlg;
    QStandardItemModel *pkt_model;
    Thread *thread;
    QFileDialog *filesave;
    SearchDialog *searchDialog;
    TcpDialog *tcpDialog;
    bool started;

signals:
    void end_cap();
    void pause();
    void search();
    void defrag();

private slots:
    void sscap();
    void cap();
    void changeButton1();
    void showButton2();
    void pushButton_2_clicked();
    void hideButton2();
    void rerr(char *);
    void on_tableView_clicked(const QModelIndex &index);
    void on_pushButton_3_clicked();
    void on_pushButton_4_clicked();
    void on_pushButton_5_clicked();
};






#endif // MAINWINDOW_H
