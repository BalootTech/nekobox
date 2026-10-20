#pragma once
#include "AbstractBean.hpp"

namespace Configs {
class OpenVPNBean : public AbstractBean {
public:
    QString config;
    QString username;
    QString password;

    explicit OpenVPNBean(ProxyEntity *entity) : AbstractBean(entity, 0) {}
    INIT_BEAN_MAP
        ADD_MAP("config", config, string);
        ADD_MAP("username", username, string);
        ADD_MAP("password", password, string);
    STOP_MAP

    QString type() const override { return "openvpn"; }
    bool IsEndpoint() const override { return true; }
    CoreObjOutboundBuildResult BuildCoreObjSingBox() const override;
    bool TryParseJson(const Data::Node &obj) override;
    bool ParseConfig(const QString &text, QString &error);
    QString ToShareLink() const override { return ToNekorayShareLink(); }
};
}
