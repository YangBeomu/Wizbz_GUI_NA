#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    networkController_ = new ArpSpoofing;
    init();
}

Widget::~Widget()
{
    delete ui;
    delete(networkController_);
}

void Widget::init() {
    auto interfaceNames = networkController_->GetInterfaces();

    for(auto name : interfaceNames)
        ui->cbInterface->addItem(name);

    //mask
    //ui->leSenderIP->setInputMask("000.000.000.000");
    //ui->leTargetIP->setInputMask("000.000.000.000");

    QRegularExpressionValidator ipExprValidator(
        QRegularExpression(R"((^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$))"));

    ui->leSenderIP->setValidator(&ipExprValidator);
    ui->leTargetIP->setValidator(&ipExprValidator);

    ui->rbARP->setChecked(true);

    if(networkController_->GetCurrentInterface().isEmpty()) {
        ui->tbAdd->setEnabled(false);
        ui->tbRemove->setEnabled(false);
    }

}


void Widget::on_pbAttack_clicked()
{
    if(ui->rbARP->isChecked())
        reinterpret_cast<ArpSpoofing*>(networkController_)->Run();
}


void Widget::on_tbAdd_clicked()
{
    auto senderIP = ui->leSenderIP->text();
    auto targetIP = ui->leTargetIP->text();

    reinterpret_cast<ArpSpoofing*>(networkController_)->Register(senderIP, targetIP);

    QString ret;


    //ret.append("Flow(" + senderIP + " , " + targetIP + ")");
    ret.append(senderIP + " , " + targetIP);

    ui->lvFlow->addItem(ret);
}


void Widget::on_tbRemove_clicked()
{
    auto cItem = ui->lvFlow->currentItem();
    auto itemList = cItem->text().split(" , ");

    reinterpret_cast<ArpSpoofing*>(networkController_)->Delete(itemList[0], itemList[1]);

    delete(cItem);
}


void Widget::on_pbStop_clicked()
{
    networkController_->Stop();
}


void Widget::on_pbInterfaceAply_clicked()
{
    if(networkController_->SetCurrentInterface(ui->cbInterface->currentText())) {
        networkController_->SetFilter("not host 192.168.0.100");
        ui->tbAdd->setEnabled(!ui->tbAdd->isEnabled());
        ui->tbRemove->setEnabled(!ui->tbRemove->isEnabled());
    }
}

