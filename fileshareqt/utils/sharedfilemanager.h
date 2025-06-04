// File: utils/sharedfilemanager.h

#ifndef SHAREDFILEMANAGER_H
#define SHAREDFILEMANAGER_H

#include <QObject>
#include "cache.h"

class SharedFileManager : public QObject
{
    Q_OBJECT

public:
    explicit SharedFileManager(QObject *parent = nullptr);
    ~SharedFileManager() override = default;

    // Returns true if we have cached bytes for this filename.
    bool has(const QString &filename) const;

    // Insert raw data (e.g. from downloadSharedFileResult) under this filename.
    void insert(const QString &filename, const QByteArray &data);

    // Retrieve the raw data (caller should check .has() first).
    QByteArray get(const QString &filename) const;

    // Clear the entire cache (e.g. on logout).
    void clear();

    // Number of items in the cache.
    int size() const;

private:
    // Use a QHash-based cache for O(1) lookups
    Cache<QString, QByteArray, true> m_cache;
};

#endif // SHAREDFILEMANAGER_H
