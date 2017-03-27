#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>
#include <pcap.h>

extern pcap_t *phandle;

namespace Ui {
    class filterDialog;
}

class filterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit filterDialog(QWidget *parent = 0);
    ~filterDialog();

signals:
    void error();
    void success();

private slots:
    void on_pushButton_2_clicked();

    void on_pushButton_clicked();

private:
    Ui::filterDialog *ui;
};

#endif // FILTERDIALOG_H
