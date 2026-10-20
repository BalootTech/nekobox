#include <nekobox/ui/profile/edit_openvpn.h>
#include <nekobox/configs/proxy/OpenVPNBean.hpp>
#include <nekobox/configs/proxy/OpenVPNConfig.hpp>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>

EditOpenVPN::EditOpenVPN(QWidget *parent) : QWidget(parent) {
    auto layout = new QFormLayout(this);
    auto import = new QPushButton(tr("Import .ovpn"), this);
    username = new QLineEdit(this);
    password = new QLineEdit(this);
    password->setEchoMode(QLineEdit::Password);
    config = new QPlainTextEdit(this);
    config->setMinimumSize(460, 280);
    config->setPlaceholderText(tr("Paste an OpenVPN configuration with inline certificates, or import an .ovpn file."));
    auto hint = new QLabel(tr("Routing and DNS follow NekoBox rules. External certificate/key files are bundled when importing. Interactive authentication and TAP are not supported."), this);
    hint->setWordWrap(true);
    layout->addRow(import);
    layout->addRow(tr("Username"), username);
    layout->addRow(tr("Password"), password);
    layout->addRow(tr("Configuration"), config);
    layout->addRow(hint);
    connect(import, &QPushButton::clicked, this, [this] {
        const auto path = QFileDialog::getOpenFileName(this, tr("Import OpenVPN"), {}, tr("OpenVPN files (*.ovpn *.conf);;All files (*)"));
        if (path.isEmpty()) return;
        QString text, error;
        if (!Configs::OpenVPN::LoadFile(path, text, error)) {
            QMessageBox::warning(this, tr("OpenVPN"), error);
            return;
        }
        config->setPlainText(text);
    });
}

void EditOpenVPN::onStart(std::shared_ptr<Configs::ProxyEntity> value) {
    ent = value;
    auto bean = ent->OpenVPNBean();
    config->setPlainText(bean->config);
    username->setText(bean->username);
    password->setText(bean->password);
}

bool EditOpenVPN::onEnd() {
    const auto parsed = Configs::OpenVPN::Parse(config->toPlainText());
    if (!parsed.error.isEmpty()) {
        QMessageBox::warning(this, tr("OpenVPN"), parsed.error);
        return false;
    }
    auto bean = ent->unlock(ent->OpenVPNBean());
    QString error;
    if (!bean->ParseConfig(config->toPlainText(), error)) return false;
    bean->username = username->text();
    bean->password = password->text();
    return true;
}
