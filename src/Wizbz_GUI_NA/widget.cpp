#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    nc_ = new NetworkController;
    init();
}

Widget::~Widget()
{
    delete ui;
    delete(nc_);
}

void Widget::init() {
    auto interfaceNames = nc_->GetInterfaces();

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

}


void Widget::on_pbAttack_clicked()
{
    auto interfaceName = ui->cbInterface->currentText();
    auto senderIP = ui->leSenderIP->text();
    auto targetIP = ui->leTargetIP->text();

    if(ui->rbARP->isChecked())
        nc_->ArpSpoofing(interfaceName, senderIP, targetIP);
        nc_->ArpSpoofing(interfaceName, targetIP, senderIP);
}

