#ifndef ERRODIALOG_H
#define ERRODIALOG_H

#include <QDialog>
#include "ui_errodialog.h"
#include <pcap.h>

extern pcap_t *phandle;

namespace Ui {
    class Dialog;
}

class errodialog : public QDialog
{
    Q_OBJECT

public:
    errodialog(QWidget *parent = 0);
    ~errodialog();
    void setLabel(char *);

private:
    Ui::Dialog *ui;

private slots:
    void showErr();
};

#endif // ERRODIALOG_H
