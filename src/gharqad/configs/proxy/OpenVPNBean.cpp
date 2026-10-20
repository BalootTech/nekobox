#include <nekobox/configs/proxy/OpenVPNBean.hpp>
#include <nekobox/configs/proxy/OpenVPNConfig.hpp>
#include <nekobox/dataStore/ProxyEntity.hpp>
#include <QJsonArray>
#include <QJsonDocument>

namespace Configs {
namespace {
void setRemote(ProxyEntity *entity, const QJsonObject &endpoint) {
    auto remote = endpoint;
    if (!endpoint["servers"].toArray().isEmpty()) remote = endpoint["servers"].toArray().first().toObject();
    entity->serverAddress = remote["server"].toString();
    entity->serverPort = remote["server_port"].toInt(1194);
}
}

CoreObjOutboundBuildResult OpenVPNBean::BuildCoreObjSingBox() const {
    CoreObjOutboundBuildResult result;
    const auto parsed = OpenVPN::Parse(config);
    result.error = parsed.error;
    if (!result.error.isEmpty()) return result;
    auto endpoint = parsed.endpoint;
    if (!username.isEmpty()) endpoint["username"] = username;
    if (!password.isEmpty()) endpoint["password"] = password;
    if (parsed.needsCredentials && endpoint["username"].toString().isEmpty()) {
        result.error = "OpenVPN: enter the username and password in the profile editor";
        return result;
    }
    result.outbound = endpoint;
    return result;
}

bool OpenVPNBean::ParseConfig(const QString &text, QString &error) {
    const auto parsed = OpenVPN::Parse(text);
    error = parsed.error;
    if (!error.isEmpty()) return false;
    config = text;
    setRemote(entity, parsed.endpoint);
    if (entity->name.isEmpty()) entity->name = "OpenVPN";
    return true;
}

bool OpenVPNBean::TryParseJson(const Data::Node &obj) {
    auto endpoint = QJsonObject::fromVariantMap(obj.toVariantMap());
    const auto type = endpoint["type"].toString();
    if (type != "openvpn-client" && type != "openvpn") return false;
    endpoint["type"] = "openvpn-client";
    QString error;
    if (!ParseConfig(QString::fromUtf8(QJsonDocument(endpoint).toJson()), error)) return false;
    entity->name = endpoint["tag"].toString("OpenVPN");
    return true;
}
}
