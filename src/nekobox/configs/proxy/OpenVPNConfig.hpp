#pragma once

#include <QJsonObject>
#include <QString>

namespace Configs::OpenVPN {
struct ParseResult {
    QJsonObject endpoint;
    QString error;
    bool needsCredentials = false;
};

// No file access or scripts during parsing. LoadFile explicitly bundles local
// certificate/key/auth files so saved profiles do not depend on the working dir.
ParseResult Parse(const QString &text);
bool LooksLikeConfig(const QString &text);
bool LoadFile(const QString &path, QString &text, QString &error);
}
