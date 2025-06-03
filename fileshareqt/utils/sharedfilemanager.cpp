#include "sharedfilemanager.h"

SharedFileManager::SharedFileManager(QObject *parent)
    : QObject(parent)
{}

bool SharedFileManager::has(const QString &filename) const
{
    return m_cache.contains(filename);
}

void SharedFileManager::insert(const QString &filename, const QByteArray &data)
{
    // Overwrite any existing entry; that’s fine
    m_cache.insert(filename, data);
}

QByteArray SharedFileManager::get(const QString &filename) const
{
    // If key does not exist, returns a default‐constructed (empty) QByteArray
    return m_cache.value(filename);
}

void SharedFileManager::clear()
{
    m_cache.clear();
}
