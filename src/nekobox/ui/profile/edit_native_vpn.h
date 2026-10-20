#pragma once
#include "profile_editor.h"
#include <QWidget>

class QLineEdit;
class QComboBox;
class QSpinBox;

class EditNativeVPN : public QWidget, public ProfileEditor {
public:
    explicit EditNativeVPN(bool l2tp, QWidget *parent = nullptr);
    void onStart(std::shared_ptr<Configs::ProxyEntity> ent) override;
    bool onEnd() override;
private:
    std::shared_ptr<Configs::ProxyEntity> ent;
    QLineEdit *username;
    QLineEdit *password;
    QLineEdit *psk;
    QComboBox *authentication;
    QSpinBox *connectTimeout;
    bool l2tp;
};
