#include <nekobox/ui/profile/edit_native_vpn.h>
#include <nekobox/configs/proxy/NativeVPNBean.hpp>
#include <nekobox/dataStore/ProxyEntity.hpp>
#include <QComboBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QSpinBox>

EditNativeVPN::EditNativeVPN(bool l2tp, QWidget *parent) : QWidget(parent), l2tp(l2tp) {
    auto layout = new QFormLayout(this);
    username = new QLineEdit(this);
    password = new QLineEdit(this);
    password->setEchoMode(QLineEdit::Password);
    psk = new QLineEdit(this);
    psk->setEchoMode(QLineEdit::Password);
    authentication = new QComboBox(this);
    authentication->addItem("MSCHAPv2", "mschapv2");
    if (l2tp) {
        authentication->addItem("PAP", "pap");
        authentication->addItem("CHAP", "chap");
    }
    connectTimeout = new QSpinBox(this);
    connectTimeout->setRange(5, 120);
    connectTimeout->setSuffix(tr(" s"));
    layout->addRow(tr("Username"), username);
    layout->addRow(tr("Password"), password);
    if (l2tp) layout->addRow(tr("IPsec pre-shared key"), psk);
    else psk->hide();
    layout->addRow(tr("Authentication"), authentication);
    layout->addRow(tr("Connection timeout"), connectTimeout);
    auto hint = new QLabel(tr("Windows only. Run NekoBox as administrator. Routing rules choose which IPv4 traffic uses this VPN. The connection and its temporary Windows profile are removed when stopped."), this);
    hint->setWordWrap(true);
    layout->addRow(hint);
}

void EditNativeVPN::onStart(std::shared_ptr<Configs::ProxyEntity> value) {
    ent = value;
    auto bean = ent->NativeVPNBean();
    username->setText(bean->username);
    password->setText(bean->password);
    psk->setText(bean->psk);
    authentication->setCurrentIndex(qMax(0, authentication->findData(bean->authentication)));
    connectTimeout->setValue(bean->connect_timeout);
}

bool EditNativeVPN::onEnd() {
    if (username->text().isEmpty() || (l2tp && psk->text().isEmpty())) {
        QMessageBox::warning(this, tr("Windows VPN"), tr("Enter the username and, for L2TP/IPsec, the pre-shared key."));
        return false;
    }
    auto bean = ent->unlock(ent->NativeVPNBean());
    bean->username = username->text();
    bean->password = password->text();
    bean->psk = psk->text();
    bean->authentication = authentication->currentData().toString();
    bean->connect_timeout = connectTimeout->value();
    return true;
}
