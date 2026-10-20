#include <nekobox/configs/proxy/NativeVPNBean.hpp>
#include <nekobox/dataStore/ProxyEntity.hpp>

namespace Configs {
CoreObjOutboundBuildResult NativeVPNBean::BuildCoreObjSingBox() const {
    CoreObjOutboundBuildResult result;
    if (protocol != "pptp" && protocol != "l2tp") {
        result.error = "Windows VPN: invalid protocol";
    } else if (entity->serverAddress.trimmed().isEmpty() || username.isEmpty()) {
        result.error = "Windows VPN: enter the server address and username";
    } else if (protocol == "l2tp" && psk.isEmpty()) {
        result.error = "L2TP/IPsec: enter the pre-shared key";
    } else if (connect_timeout < 5 || connect_timeout > 120) {
        result.error = "Windows VPN: connection timeout must be between 5 and 120 seconds";
    } else {
        result.outbound = {{"type", "windows-vpn"}, {"protocol", protocol},
            {"server", entity->serverAddress.trimmed()}, {"username", username},
            {"password", password}, {"authentication", authentication},
            {"connect_timeout", connect_timeout}};
        if (protocol == "l2tp") result.outbound["psk"] = psk;
    }
    return result;
}

bool NativeVPNBean::TryParseJson(const Data::Node &obj) {
    auto kind = obj["type"].toString();
    if (kind == "windows-vpn") kind = obj["protocol"].toString();
    if (kind != "pptp" && kind != "l2tp") return false;
    protocol = entity->type = kind;
    entity->serverAddress = obj["server"].toString();
    entity->serverPort = kind == "pptp" ? 1723 : 1701;
    entity->name = obj["tag"].toString();
    username = obj["username"].toString();
    password = obj["password"].toString();
    psk = obj["psk"].toString();
    authentication = obj["authentication"].toString();
    if (authentication.isEmpty()) authentication = "mschapv2";
    connect_timeout = obj["connect_timeout"].toInt();
    if (connect_timeout == 0) connect_timeout = 30;
    return BuildCoreObjSingBox().error.isEmpty();
}
}
