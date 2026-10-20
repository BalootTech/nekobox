#include <nekobox/configs/proxy/OpenVPNConfig.hpp>
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <iostream>
#include <cstdlib>

using namespace Configs::OpenVPN;
int checks = 0;
void require(bool ok, const char *message) {
    ++checks;
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
const QString base = "client\ndev tun\nremote vpn.example.com 1194\n<ca>\nCA DATA\n</ca>\n";

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    if (app.arguments().size() == 3 && app.arguments()[1] == "--emit-core") {
        QFile cert(app.arguments()[2]);
        require(cert.open(QIODevice::ReadOnly), "read core fixture material");
        const QString material = "<ca>\n" + QString::fromUtf8(cert.readAll()) + "</ca>\n";
        for (const QString proto : {QString("udp"), QString("udp-client"), QString("tcp-client")}) {
            auto parsed = Parse("client\ndev tun\nremote 127.0.0.1 1194\nproto " + proto + "\n" + material);
            require(parsed.error.isEmpty(), "core fixture parses");
            auto endpoint = parsed.endpoint;
            endpoint["tag"] = "vpn";
            QJsonObject configuration{{"endpoints", QJsonArray{endpoint}},
                {"outbounds", QJsonArray{QJsonObject{{"type", "direct"}, {"tag", "direct"}}}},
                {"route", QJsonObject{{"final", "vpn"}}}};
            std::cout << QJsonDocument(configuration).toJson(QJsonDocument::Compact).constData() << '\n';
        }
        return 0;
    }
    auto parsed = Parse(base + "auth-user-pass\nremote-cert-tls server\n");
    require(parsed.error.isEmpty(), "standard TLS config imports");
    require(parsed.needsCredentials, "auth-user-pass requests editor credentials");
    require(parsed.endpoint["type"] == "openvpn-client", "native endpoint type");
    require(!parsed.endpoint["system"].toBool(), "internal network stack");
    require(parsed.endpoint["route_no_pull"].toBool(), "application owns routing and DNS");
    require(parsed.endpoint["tls"].toObject()["certificate"] == "CA DATA", "inline CA retained");
    auto servers = parsed.endpoint["servers"].toArray();
    require(servers.size() == 1 && servers[0].toObject()["server_port"] == 1194, "remote port");

    parsed = Parse(base + "proto tcp-client\nremote backup.example.com 443 udp6\nremote-random\n");
    servers = parsed.endpoint["servers"].toArray();
    require(parsed.error.isEmpty() && servers.size() == 2, "multiple remotes");
    require(servers[0].toObject()["network"] == "tcp", "global proto applies after remote");
    require(servers[1].toObject()["network"] == "udp6", "per-remote proto wins");
    require(parsed.endpoint["remote_random"].toBool(), "remote random");
    parsed = Parse("remote vpn.example.com\nport 443\nproto tcp4-client\n<ca>\nx\n</ca>\n");
    require(parsed.endpoint["servers"].toArray()[0].toObject()["server_port"] == 443, "global port applies after remote");
    require(parsed.endpoint["network"] == "tcp4", "IPv4 transport preserved");

    parsed = Parse("client\ndev tun\nproto udp-client\nremote vpn.example.com\nport 80\n"
        "auth SHA1\ncipher AES-128-CBC\nauth-user-pass\n<ca>\nCA DATA\n</ca>\n");
    require(parsed.error.isEmpty() && parsed.needsCredentials, "provider udp-client configuration imports");
    require(parsed.endpoint["network"] == "udp", "udp-client normalizes to native UDP");
    servers = parsed.endpoint["servers"].toArray();
    require(servers[0].toObject()["network"] == "udp" && servers[0].toObject()["server_port"] == 80,
        "udp-client remote retains UDP and global port");
    parsed = Parse(base + "remote backup.example.com 80 udp-client\n");
    require(parsed.error.isEmpty() && parsed.endpoint["servers"].toArray()[1].toObject()["network"] == "udp",
        "per-remote udp-client normalizes to UDP");

    parsed = Parse(base + "<cert>\nCLIENT CERT\n</cert>\n<key>\nCLIENT KEY\n</key>\n"
        "tls-auth [inline] 1\n<tls-auth>\nCONTROL KEY\n</tls-auth>\n"
        "verify-x509-name \"VPN Server\" name\n");
    require(parsed.error.isEmpty(), "mutual TLS and tls-auth import");
    auto tls = parsed.endpoint["tls"].toObject();
    require(tls["client_key"] == "CLIENT KEY", "client key preserved");
    require(tls["server_name"] == "VPN Server" && tls["server_name_type"] == "name", "quoted name verification");
    require(tls["control_wrap"].toObject()["direction"] == "client", "tls-auth direction 1");
    parsed = Parse(base + "key-direction 0\n<tls-auth>\nKEY\n</tls-auth>\n");
    require(parsed.endpoint["tls"].toObject()["control_wrap"].toObject()["direction"] == "server", "tls-auth direction 0");
    for (const QString kind : {QString("tls-crypt"), QString("tls-crypt-v2")}) {
        parsed = Parse(base + "<" + kind + ">\nKEY\n</" + kind + ">\nkey-direction 1\n");
        require(parsed.error.isEmpty(), "tls-crypt imports");
        require(!parsed.endpoint["tls"].toObject()["control_wrap"].toObject().contains("direction"), "no direction on tls-crypt");
    }
    parsed = Parse(base + "data-ciphers AES-256-GCM:AES-128-GCM\ncipher AES-256-CBC\nauth SHA256\n"
        "reneg-sec 0\nping-restart 0\nmssfix 0\n");
    require(parsed.error.isEmpty() && parsed.endpoint["data_ciphers"].toArray().size() == 2, "cipher negotiation");
    require(parsed.endpoint["data_ciphers_fallback"] == "AES-256-CBC", "legacy cipher fallback");
    require(parsed.endpoint["renegotiate_disabled"].toBool() && parsed.endpoint["ping_restart_disabled"].toBool()
        && parsed.endpoint["mss_fix_disabled"].toBool(), "zero values disable their timers/features");
    parsed = Parse(base + "<auth-user-pass>\nuser\npass\n</auth-user-pass>\n");
    require(parsed.endpoint["username"] == "user" && parsed.endpoint["password"] == "pass", "inline credentials");
    require(Parse(base + "route 10.0.0.0 255.0.0.0\nredirect-gateway def1\ndhcp-option DNS 10.0.0.1\n").error.isEmpty(), "app-owned routing directives accepted");
    require(LooksLikeConfig("# comment\nclient\nremote vpn.example.com 1194"), "config detection");
    require(!LooksLikeConfig("vless://example\nss://example"), "share links are not OpenVPN");

    for (const QString invalid : {
        base + "dev tap\n", base + "proto tcp-server\n", base + "proto udp-server\n", base + "remote bad 70000\n",
        base + "up /tmp/script\n", base + "plugin unsafe.so\n", base + "config another.ovpn\n",
        base + "ca relative.crt\n", base + "key-direction 2\n", base + "auth-retry interact\n",
        base + "remote \"unclosed\n", base + "<key>\nx\n", base + "<key>\nx\n</key>\n",
        base + "<ca>\nduplicate\n</ca>\n", base + "<unknown>\nx\n</unknown>\n",
        QString("client\nremote vpn.example.com\n"), base + "tls-auth [inline]\n",
        base + "<tls-auth>\nx\n</tls-auth>\n<tls-crypt>\ny\n</tls-crypt>\n"}) {
        parsed = Parse(invalid);
        require(!parsed.error.isEmpty() && parsed.endpoint.isEmpty(), "unsupported or malformed config fails closed");
    }

    QTemporaryDir dir;
    require(dir.isValid(), "temporary fixture directory");
    auto write = [&](const QString &name, const QByteArray &data) {
        QFile file(dir.filePath(name));
        require(file.open(QIODevice::WriteOnly) && file.write(data) == data.size(), "write fixture");
    };
    write("ca cert.pem", "CA FILE");
    write("client.pem", "CLIENT FILE");
    write("client.key", "PRIVATE FILE");
    write("ta.key", "CONTROL FILE");
    write("auth.txt", "alice\nsecret\n");
    write("vpn.ovpn", "client\nremote vpn.example.com 443 tcp-client\nca \"ca cert.pem\"\ncert client.pem\nkey client.key\ntls-auth ta.key 1\nauth-user-pass auth.txt\n");
    QString bundled, error;
    require(LoadFile(dir.filePath("vpn.ovpn"), bundled, error), "relative files bundle successfully");
    parsed = Parse(bundled);
    require(parsed.error.isEmpty() && parsed.endpoint["username"] == "alice", "bundled credentials work");
    require(parsed.endpoint["tls"].toObject()["certificate"] == "CA FILE", "quoted relative CA path resolves");
    require(!bundled.contains("ca cert.pem") && !bundled.contains("client.key"), "saved profile has no original file dependencies");
    write("udp-client.ovpn", "client\nproto udp-client\nremote vpn.example.com\nport 80\nca \"ca cert.pem\"\nauth-user-pass\n");
    require(LoadFile(dir.filePath("udp-client.ovpn"), bundled, error), "udp-client file import succeeds");
    parsed = Parse(bundled);
    require(parsed.endpoint["servers"].toArray()[0].toObject()["network"] == "udp", "udp-client file builds UDP endpoint");
    write("missing.ovpn", "client\nremote example.com\nca missing.pem\n");
    require(!LoadFile(dir.filePath("missing.ovpn"), bundled, error), "missing external material rejected");
    write("injection.pem", "CERT\n</ca>\nup evil");
    write("injection.ovpn", "client\nremote example.com\nca injection.pem\n");
    require(!LoadFile(dir.filePath("injection.ovpn"), bundled, error), "material cannot inject options");

    const QJsonObject native{{"type", "openvpn-client"}, {"tag", "original"},
        {"server", "vpn.example.com"}, {"server_port", 443}, {"tls", QJsonObject{{"certificate", "CA"}}},
        {"system", true}, {"route_no_pull", false}, {"detour", "old"}};
    parsed = Parse(QString::fromUtf8(QJsonDocument(native).toJson()));
    require(parsed.error.isEmpty(), "native endpoint JSON imports");
    require(!parsed.endpoint["system"].toBool() && parsed.endpoint["route_no_pull"].toBool(), "native JSON uses app routing/netstack");
    require(!parsed.endpoint.contains("tag") && !parsed.endpoint.contains("detour"), "app assigns tags/detours");
    std::cout << "Passed " << checks << " OpenVPN checks\n";
}
