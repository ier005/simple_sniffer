#ifndef TCPDIALOG_H
#define TCPDIALOG_H

#include <QDialog>
#include <QStandardItemModel>
#include <QFileDialog>

namespace Ui {
class TcpDialog;
}

class TcpDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TcpDialog(QWidget *parent = 0);
    ~TcpDialog();

private:
    Ui::TcpDialog *ui;
    QStandardItemModel *pkt_model;
    QFileDialog *filesv;

signals:
    void err(char *);

private slots:
    void defrag();
    void tcpView_clicked(const QModelIndex &index);
    void on_canc_clicked();
    void on_tcpSave_clicked();
};

#endif // TCPDIALOG_H
