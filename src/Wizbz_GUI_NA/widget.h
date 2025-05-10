#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QRegularExpression>
#include <QList>

//#include "../../include/pcapcontroller.h"
#include "../../include/arpspoofing.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

    PcapController* networkController_ = nullptr;

    void init();

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:

    void on_pbAttack_clicked();

    void on_tbAdd_clicked();

    void on_tbRemove_clicked();

    void on_pbStop_clicked();

    void on_pbInterfaceAply_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
