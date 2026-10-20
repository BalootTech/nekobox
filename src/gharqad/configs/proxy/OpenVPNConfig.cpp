#include <nekobox/configs/proxy/OpenVPNConfig.hpp>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QRegularExpression>
#include <QSet>

namespace Configs::OpenVPN {
namespace {
// OpenVPN quoting differs from shell parsing: preserve whitespace in quoted
// paths and names, recognize escaped quotes, and never evaluate substitutions.
bool tokenize(const QString &line, QStringList &tokens) {
    QString token;
    QChar quote;
    bool escaped = false, started = false;
    for (QChar ch : line) {
        if (escaped) {
            token += ch;
            escaped = false;
            started = true;
        } else if (ch == '\\' && quote != '\'') {
            escaped = true;
            started = true;
        } else if (!quote.isNull()) {
            if (ch == quote) quote = QChar();
            else token += ch;
        } else if (ch == '"' || ch == '\'') {
            quote = ch;
            started = true;
        } else if (ch.isSpace()) {
            if (started) { tokens << token; token.clear(); started = false; }
        } else if ((ch == '#' || ch == ';') && !started) {
            break;
        } else {
            token += ch;
            started = true;
        }
    }
    if (escaped || !quote.isNull()) return false;
    if (started) tokens << token;
    if (!tokens.isEmpty() && tokens[0].startsWith("--")) tokens[0].remove(0, 2);
    return true;
}

bool transport(QString input, QString &output) {
    if (input == "udp" || input == "udp4" || input == "udp6") output = input;
    else if (input == "tcp" || input == "tcp-client") output = "tcp";
    else if (input == "tcp4" || input == "tcp4-client") output = "tcp4";
    else if (input == "tcp6" || input == "tcp6-client") output = "tcp6";
    else return false;
    return true;
}

ParseResult fail(int line, const QString &message) {
    ParseResult result;
    result.error = line > 0 ? QString("OpenVPN line %1: %2").arg(line).arg(message)
                           : "OpenVPN: " + message;
    return result;
}

const QSet<QString> fileOptions = {"ca", "cert", "key", "tls-auth", "tls-crypt",
                                  "tls-crypt-v2", "auth-user-pass"};
}

bool LooksLikeConfig(const QString &text) {
    static const QRegularExpression marker(
        "(?:^|\\n)\\s*(?:--)?(?:client|remote|dev|tls-client)(?:\\s|$)");
    return marker.match(text).hasMatch();
}

ParseResult Parse(const QString &input) {
    QString text = input;
    text.remove(QChar(0xfeff));
    if (text.trimmed().startsWith('{')) {
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(text.toUtf8(), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject())
            return fail(0, "Invalid endpoint JSON");
        auto endpoint = document.object();
        if (endpoint["type"] != "openvpn-client")
            return fail(0, "Expected an openvpn-client endpoint");
        if (!endpoint["mode"].toString().isEmpty() && endpoint["mode"] != "tls")
            return fail(0, "Only TLS client mode is supported by this profile");
        if (endpoint["server"].toString().isEmpty() && endpoint["servers"].toArray().isEmpty())
            return fail(0, "No remote server configured");
        // This profile uses the internal network stack and application routing.
        endpoint["system"] = false;
        endpoint["route_no_pull"] = true;
        endpoint.remove("tag");
        endpoint.remove("detour"); // chains assign their own detour
        ParseResult result;
        result.endpoint = endpoint;
        return result;
    }

    QJsonObject endpoint{{"type", "openvpn-client"}, {"system", false},
                         {"route_no_pull", true}, {"mode", "tls"}};
    QJsonObject tls, wrap;
    QJsonArray remotes;
    QMap<QString, QString> blocks;
    QSet<QString> references;
    QString network = "udp", direction;
    int port = 1194;
    bool needsCredentials = false;
    const auto lines = text.split('\n');

    // Options owned by the application or relating only to the standalone
    // OpenVPN process. All other unimplemented options fail explicitly.
    const QSet<QString> ignored = {
        "client", "tls-client", "pull", "nobind", "persist-key", "persist-tun",
        "resolv-retry", "verb", "mute", "mute-replay-warnings", "auth-nocache",
        "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout",
        "route", "route-ipv6", "route-gateway", "route-metric", "route-delay",
        "route-nopull", "route-noexec", "redirect-gateway", "redirect-private",
        "dhcp-option", "register-dns", "block-outside-dns",
        "fast-io", "sndbuf", "rcvbuf", "tun-mtu-extra", "setenv"
    };
    const QMap<QString, QString> strings = {
        {"auth", "auth"}, {"cipher", "data_ciphers_fallback"},
        {"data-ciphers-fallback", "data_ciphers_fallback"},
        {"topology", "topology"}, {"compress", "compression"},
        {"comp-lzo", "compression_lzo"}, {"allow-compression", "allow_compression"}
    };
    const QMap<QString, QString> tlsStrings = {
        {"remote-cert-tls", "remote_certificate_tls"}, {"ns-cert-type", "ns_certificate_type"},
        {"tls-version-min", "version_min"}, {"tls-version-max", "version_max"},
        {"tls-cipher", "cipher"}, {"tls-groups", "groups"},
        {"remote-cert-eku", "remote_certificate_eku"}, {"tls-cert-profile", "certificate_profile"}
    };
    const QMap<QString, QString> durations = {
        {"ping", "ping_interval"}, {"ping-restart", "ping_restart"},
        {"reneg-sec", "renegotiate_interval"}, {"tls-timeout", "tls_timeout"},
        {"hand-window", "handshake_window"}
    };

    for (int i = 0; i < lines.size(); ++i) {
        const QString line = lines[i].trimmed();
        if (line.isEmpty() || line.startsWith('#') || line.startsWith(';')) continue;
        if (line.startsWith('<')) {
            if (!line.endsWith('>') || line.startsWith("</"))
                return fail(i + 1, "Malformed inline block");
            const QString name = line.mid(1, line.size() - 2);
            if (!fileOptions.contains(name)) return fail(i + 1, "Unsupported inline block: " + name);
            if (blocks.contains(name)) return fail(i + 1, "Duplicate inline block: " + name);
            const int start = i + 1;
            QStringList content;
            while (++i < lines.size() && lines[i].trimmed() != "</" + name + ">") content << lines[i];
            if (i == lines.size()) return fail(start, "Unterminated inline block: " + name);
            blocks[name] = name == "auth-user-pass" ? content.join('\n') : content.join('\n').trimmed();
            if (blocks[name].trimmed().isEmpty()) return fail(start, "Empty inline block: " + name);
            continue;
        }
        QStringList tokens;
        if (!tokenize(line, tokens)) return fail(i + 1, "Invalid quoting");
        if (tokens.isEmpty()) continue;
        const QString option = tokens.takeFirst();
        auto count = [&](int min, int max) { return tokens.size() >= min && tokens.size() <= max; };
        if (ignored.contains(option)) continue;
        if (option == "dev" || option == "dev-type") {
            if (!count(1, 1) || (option == "dev-type" ? tokens[0] != "tun" : !tokens[0].startsWith("tun")))
                return fail(i + 1, "Only TUN devices are supported");
        } else if (option == "proto") {
            if (!count(1, 1) || !transport(tokens[0], network)) return fail(i + 1, "Unsupported transport");
        } else if (option == "port" || option == "rport") {
            bool ok = false;
            const int value = count(1, 1) ? tokens[0].toInt(&ok) : 0;
            if (!ok || value < 1 || value > 65535) return fail(i + 1, "Invalid port");
            port = value;
        } else if (option == "remote") {
            if (!count(1, 3) || tokens[0].isEmpty()) return fail(i + 1, "Invalid remote");
            QJsonObject remote{{"server", tokens[0]}};
            if (tokens.size() >= 2) {
                bool ok = false;
                const int value = tokens[1].toInt(&ok);
                if (!ok || value < 1 || value > 65535) return fail(i + 1, "Invalid remote port");
                remote["server_port"] = value;
            }
            if (tokens.size() == 3) {
                QString proto;
                if (!transport(tokens[2], proto)) return fail(i + 1, "Unsupported remote transport");
                remote["network"] = proto;
            }
            remotes.append(remote);
        } else if (option == "remote-random") {
            if (!count(0, 0)) return fail(i + 1, "Invalid remote-random");
            endpoint["remote_random"] = true;
        } else if (fileOptions.contains(option)) {
            if (option == "auth-user-pass" && tokens.isEmpty()) { needsCredentials = true; continue; }
            if (!count(1, option == "tls-auth" ? 2 : 1)) return fail(i + 1, "Invalid " + option);
            if (tokens[0] != "[inline]")
                return fail(i + 1, "External " + option + " file: use Import .ovpn to bundle it");
            references.insert(option);
            if (tokens.size() == 2) direction = tokens[1];
        } else if (option == "key-direction") {
            if (!count(1, 1)) return fail(i + 1, "Invalid key-direction");
            direction = tokens[0];
        } else if (option == "verify-x509-name") {
            if (!count(1, 2)) return fail(i + 1, "Invalid verify-x509-name");
            tls["server_name"] = tokens[0];
            tls["server_name_type"] = tokens.size() == 2 ? tokens[1] : "subject";
        } else if (option == "peer-fingerprint") {
            if (!count(1, 1)) return fail(i + 1, "Invalid peer-fingerprint");
            tls["peer_fingerprint"] = tokens[0].remove(':').toLower();
        } else if (option == "data-ciphers" || option == "ncp-ciphers") {
            if (!count(1, 1)) return fail(i + 1, "Invalid cipher list");
            endpoint["data_ciphers"] = QJsonArray::fromStringList(tokens[0].split(':', Qt::SkipEmptyParts));
        } else if (strings.contains(option)) {
            if (tokens.isEmpty() && (option == "compress" || option == "comp-lzo"))
                tokens << (option == "compress" ? "stub" : "adaptive");
            if (!count(1, 1)) return fail(i + 1, "Invalid " + option);
            endpoint[strings[option]] = tokens[0];
        } else if (tlsStrings.contains(option)) {
            if (!count(1, 1)) return fail(i + 1, "Invalid " + option);
            tls[tlsStrings[option]] = tokens[0];
        } else if (option == "remote-cert-ku") {
            if (tokens.isEmpty()) return fail(i + 1, "Invalid remote-cert-ku");
            tls["remote_certificate_ku"] = QJsonArray::fromStringList(tokens);
        } else if (durations.contains(option)) {
            bool ok = false;
            const int value = count(1, 1) ? tokens[0].toInt(&ok) : -1;
            if (!ok || value < 0) return fail(i + 1, "Invalid " + option);
            if (value == 0 && option == "reneg-sec") endpoint["renegotiate_disabled"] = true;
            else if (value == 0 && option == "ping-restart") endpoint["ping_restart_disabled"] = true;
            else endpoint[durations[option]] = QString::number(value) + "s";
        } else if (option == "tun-mtu" || option == "fragment" || option == "mssfix" ||
                   option == "reneg-bytes" || option == "reneg-pkts" || option == "explicit-exit-notify") {
            if (tokens.isEmpty() && (option == "mssfix" || option == "explicit-exit-notify"))
                tokens << (option == "mssfix" ? "1492" : "1");
            bool ok = false;
            const qint64 value = !tokens.isEmpty() ? tokens[0].toLongLong(&ok) : -1;
            if (!ok || value < 0 || !count(1, option == "mssfix" ? 2 : 1)) return fail(i + 1, "Invalid " + option);
            const QString field = option == "tun-mtu" ? "mtu" : option == "mssfix" ? "mss_fix" :
                option == "reneg-bytes" ? "renegotiate_bytes" : option == "reneg-pkts" ? "renegotiate_packets" :
                option == "explicit-exit-notify" ? "explicit_exit_notify" : "fragment";
            if (option == "mssfix" && value == 0) endpoint["mss_fix_disabled"] = true;
            else endpoint[field] = value;
            if (option == "mssfix" && tokens.size() == 2) {
                if (tokens[1] != "mtu" && tokens[1] != "fixed") return fail(i + 1, "Unsupported mssfix mode");
                endpoint["mss_fix_mode"] = tokens[1];
            }
        } else if (option == "block-ipv6") {
            if (!count(0, 0)) return fail(i + 1, "Invalid block-ipv6");
            endpoint["block_ipv6"] = true;
        } else if (option == "auth-retry") {
            if (!count(1, 1) || (tokens[0] != "none" && tokens[0] != "nointeract"))
                return fail(i + 1, "Interactive authentication is not supported");
            endpoint["auth_retry"] = tokens[0];
        } else {
            return fail(i + 1, "Unsupported option: " + option);
        }
    }
    if (remotes.isEmpty()) return fail(0, "No remote server configured");
    for (const auto &reference : references)
        if (!blocks.contains(reference)) return fail(0, "Missing inline block: " + reference);
    if (!direction.isEmpty() && direction != "0" && direction != "1") return fail(0, "key-direction must be 0 or 1");
    if (blocks.contains("ca")) tls["certificate"] = blocks["ca"];
    if (blocks.contains("cert")) tls["client_certificate"] = blocks["cert"];
    if (blocks.contains("key")) tls["client_key"] = blocks["key"];
    if (blocks.contains("cert") != blocks.contains("key")) return fail(0, "Client certificate and key must be provided together");
    if (!tls.contains("certificate") && !tls.contains("peer_fingerprint")) return fail(0, "A CA certificate or peer fingerprint is required");
    for (const QString &kind : {QString("tls-auth"), QString("tls-crypt"), QString("tls-crypt-v2")}) {
        if (!blocks.contains(kind)) continue;
        if (!wrap.isEmpty()) return fail(0, "Multiple TLS control wrapping modes");
        wrap = {{"type", QString(kind).replace('-', '_')}, {"key", blocks[kind]}};
        if (kind == "tls-auth" && !direction.isEmpty()) wrap["direction"] = direction == "1" ? "client" : "server";
    }
    if (!wrap.isEmpty()) tls["control_wrap"] = wrap;
    if (blocks.contains("auth-user-pass")) {
        const auto credentials = blocks["auth-user-pass"].split('\n');
        if (credentials.size() != 2) return fail(0, "Inline auth-user-pass must contain two lines");
        auto user = credentials[0], password = credentials[1];
        if (user.endsWith('\r')) user.chop(1);
        if (password.endsWith('\r')) password.chop(1);
        endpoint["username"] = user;
        endpoint["password"] = password;
    }
    for (int i = 0; i < remotes.size(); ++i) {
        auto remote = remotes[i].toObject();
        if (!remote.contains("server_port")) remote["server_port"] = port;
        if (!remote.contains("network")) remote["network"] = network;
        remotes[i] = remote;
    }
    endpoint["network"] = network;
    endpoint["servers"] = remotes;
    endpoint["tls"] = tls;
    ParseResult result;
    result.endpoint = endpoint;
    result.needsCredentials = needsCredentials;
    return result;
}

bool LoadFile(const QString &path, QString &text, QString &error) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 4 * 1024 * 1024) {
        error = "Cannot read OpenVPN file (maximum 4 MiB)";
        return false;
    }
    const auto lines = QString::fromUtf8(file.readAll()).split('\n');
    QStringList output;
    QString block;
    const QDir base = QFileInfo(path).absoluteDir();
    for (int i = 0; i < lines.size(); ++i) {
        const auto trimmed = lines[i].trimmed();
        if (!block.isEmpty()) {
            output << lines[i];
            if (trimmed == "</" + block + ">") block.clear();
            continue;
        }
        if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
            block = trimmed.mid(1, trimmed.size() - 2);
            output << lines[i];
            continue;
        }
        QStringList tokens;
        if (!tokenize(lines[i], tokens)) { error = QString("Invalid quoting on line %1").arg(i + 1); return false; }
        if (tokens.size() < 2 || !fileOptions.contains(tokens[0]) || tokens[1] == "[inline]") {
            output << lines[i];
            continue;
        }
        if (tokens.size() > (tokens[0] == "tls-auth" ? 3 : 2)) { error = "Invalid " + tokens[0]; return false; }
        QFile asset(base.absoluteFilePath(tokens[1]));
        if (!asset.open(QIODevice::ReadOnly) || asset.size() > 4 * 1024 * 1024) {
            error = QString("Cannot read %1 file referenced on line %2").arg(tokens[0]).arg(i + 1);
            return false;
        }
        auto content = QString::fromUtf8(asset.readAll());
        if (tokens[0] == "auth-user-pass") {
            while (content.endsWith('\n') || content.endsWith('\r')) content.chop(1);
        } else content = content.trimmed();
        // Prevent a referenced file from injecting additional profile options.
        if (content.contains(QRegularExpression("(?:^|\\n)\\s*</?[^>]+>"))) { error = "Invalid inline content for " + tokens[0]; return false; }
        output << "<" + tokens[0] + ">" << content << "</" + tokens[0] + ">";
        if (tokens.size() == 3) output << "key-direction " + tokens[2];
    }
    const auto bundled = output.join('\n');
    const auto parsed = Parse(bundled);
    if (!parsed.error.isEmpty()) { error = parsed.error; return false; }
    text = bundled;
    error.clear();
    return true;
}
}
