#pragma once
#include "profile_editor.h"
#include <QWidget>

class QLineEdit;
class QPlainTextEdit;

class EditOpenVPN : public QWidget, public ProfileEditor {
public:
    explicit EditOpenVPN(QWidget *parent = nullptr);
    void onStart(std::shared_ptr<Configs::ProxyEntity> ent) override;
    bool onEnd() override;

private:
    std::shared_ptr<Configs::ProxyEntity> ent;
    QLineEdit *username;
    QLineEdit *password;
    QPlainTextEdit *config;
};
