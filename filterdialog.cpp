#include "filterdialog.h"
#include "ui_filterdialog.h"


struct bpf_program fcode;
//char filterString[1024];
pcap_t *phandle;

filterDialog::filterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::filterDialog)
{
    ui->setupUi(this);
}

filterDialog::~filterDialog()
{
    delete ui;
}

void filterDialog::on_pushButton_2_clicked()
{
    this->hide();
}

void filterDialog::on_pushButton_clicked()
{
    if(pcap_compile(phandle, &fcode, qPrintable(ui->lineEdit->text()), 0, 0) == -1)
        emit error();
    else {
        if (pcap_setfilter(phandle, &fcode) == -1)
            emit error();
        else {
            emit success();
            this->hide();
        }
    }
}


