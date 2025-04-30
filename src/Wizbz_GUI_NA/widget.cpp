#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    asf_ = new ArpSpoofing;
    init();
}

Widget::~Widget()
{
    delete ui;
    delete(asf_);
}

void Widget::init() {
    auto interfaceNames = asf_->GetInterfaces();

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

    if(ui->rbARP->isChecked()) {
        if(asf_->GetCurrentInterface() != interfaceName)
            asf_->SetCurrentInterface(interfaceName);

        asf_->Run();
    }
}


void Widget::on_tbAdd_clicked()
{
    auto senderIP = ui->leSenderIP->text();
    auto targetIP = ui->leTargetIP->text();

    asf_->Register(senderIP, targetIP);

    QString ret;


    //ret.append("Flow(" + senderIP + " , " + targetIP + ")");
    ret.append(senderIP + " , " + targetIP);

    ui->lvFlow->addItem(ret);
}


void Widget::on_tbRemove_clicked()
{
    auto cItem = ui->lvFlow->currentItem();
    auto itemList = cItem->text().split(" , ");

    asf_->Delete(itemList[0], itemList[1]);

    delete(cItem);
}


void Widget::on_pbStop_clicked()
{
    asf_->Stop();
}

