// File: utils/sharedfilemanager.cpp

#include "sharedfilemanager.h"

SharedFileManager::SharedFileManager(QObject *parent)
    : QObject(parent)
    , m_cache(parent)
{}

bool SharedFileManager::has(const QString &filename) const
{
    return m_cache.contains(filename);
}

void SharedFileManager::insert(const QString &filename, const QByteArray &data)
{
    m_cache.insert(filename, data);
}

QByteArray SharedFileManager::get(const QString &filename) const
{
    return m_cache.value(filename);
}

void SharedFileManager::clear()
{
    m_cache.clear();
}

int SharedFileManager::size() const
{
    return m_cache.size();
}
