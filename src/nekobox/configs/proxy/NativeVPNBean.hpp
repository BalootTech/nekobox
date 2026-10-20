#pragma once
#include "AbstractBean.hpp"

namespace Configs {
class NativeVPNBean : public AbstractBean {
public:
    QString protocol;
    QString username;
    QString password;
    QString psk;
    QString authentication = "mschapv2";
    int connect_timeout = 30;

    explicit NativeVPNBean(ProxyEntity *entity, bool l2tp = false)
        : AbstractBean(entity, 0), protocol(l2tp ? "l2tp" : "pptp") {}
    INIT_BEAN_MAP
        ADD_MAP("protocol", protocol, string);
        ADD_MAP("username", username, string);
        ADD_MAP("password", password, string);
        ADD_MAP("psk", psk, string);
        ADD_MAP("authentication", authentication, string);
        ADD_MAP("connect_timeout", connect_timeout, integer);
    STOP_MAP

    QString type() const override { return protocol; }
    CoreObjOutboundBuildResult BuildCoreObjSingBox() const override;
    bool TryParseJson(const Data::Node &obj) override;
    QString ToShareLink() const override { return ToNekorayShareLink(); }
};
}
