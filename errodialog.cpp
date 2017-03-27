#include "errodialog.h"


errodialog::errodialog(QWidget *parent):
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
}

errodialog::~errodialog()
{
    delete ui;
}

void errodialog::setLabel(char *errbuf)
{
    ui->label_2->setText(errbuf);
}

void errodialog::showErr()
{
    ui->label_2->setText(pcap_geterr(phandle));
    this->show();
}
