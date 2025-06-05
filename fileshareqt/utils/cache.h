#ifndef CACHE_H
#define CACHE_H

#include <QMap>
#include <QHash>
#include <QString>

// A simple, generic cache that maps from Key→Value.
template<
    typename Key,
    typename Value,
    bool UseHash = true
    >
class Cache;

// TEMPLATE CLASS
template<typename Key, typename Value>
class Cache<Key, Value, true> {
public:
    Cache(QObject* parent = nullptr) : m_parent(parent) {}

    // Return true if key is present
    bool contains(const Key& key) const{
        return m_storage.contains(key);
    }

    // Insert or overwrite
    void insert(const Key& key, const Value& value) {
        m_storage.insert(key, value);
    }

    // Retrieve (returns default‐constructed Value if missing)
    Value value(const Key& key) const{
        return m_storage.value(key);
    }

    // Remove a key (no‐op if absent)
    void remove(const Key& key) {
        m_storage.remove(key);
    }

    // Clear entire cache
    void clear() {
        m_storage.clear();
    }

    // Number of entries
    int size() {
        return m_storage.size();
    }

private:
    QObject*            m_parent;
    QHash<Key, Value>   m_storage;
};

// for QMap-based cache
template<typename Key, typename Value>
class Cache<Key, Value, false> {
public:
    Cache(QObject* parent = nullptr) : m_parent(parent) {}

    bool contains(const Key& key) {
        return m_storage.contains(key);
    }

    void insert(const Key& key, const Value& value) {
        m_storage.insert(key, value);
    }

    Value value(const Key& key) {
        return m_storage.value(key);
    }

    void remove(const Key& key) {
        m_storage.remove(key);
    }

    void clear() {
        m_storage.clear();
    }

    int size() {
        return m_storage.size();
    }

private:
    QObject*           m_parent;
    QMap<Key, Value>   m_storage;
};

#endif // CACHE_H
