#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QRegularExpression>

#include "../../include/networkcontroller.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

    NetworkController* nc_ = nullptr;

    void init();

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:

    void on_pbAttack_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
