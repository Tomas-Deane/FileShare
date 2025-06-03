#ifndef SHAREDFILEMANAGER_H
#define SHAREDFILEMANAGER_H

#include <QObject>
#include <QMap>
#include <QString>

class SharedFileManager : public QObject
{
    Q_OBJECT

public:
    explicit SharedFileManager(QObject *parent = nullptr);
    ~SharedFileManager() override = default;

    // Returns true if we have cached bytes for this filename.
    bool has(const QString &filename) const;

    // Insert raw data (e.g. from `downloadSharedFileResult`) under this filename.
    void insert(const QString &filename, const QByteArray &data);

    // Retrieve the raw data (caller should check .has() first).
    QByteArray get(const QString &filename) const;

    // Clear the entire cache (e.g. on logout).
    void clear();

private:
    QMap<QString, QByteArray> m_cache;
};

#endif // SHAREDFILEMANAGER_H
