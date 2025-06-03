#ifndef FILEENTRY_H
#define FILEENTRY_H

#include <QString>

// simple struct to hold “filename + its server ID”
struct FileEntry {
    QString  filename;
    qint64   id;

    // Default destructor
    FileEntry() = default;

    // default destructor
    ~FileEntry() = default;

    // Deep copy constructor
    FileEntry(const FileEntry &other)
        : filename(other.filename)
        , id(other.id)
    {}

    // allows copy assignment (Qt containers need it)
    FileEntry& operator=(const FileEntry &other) = default;

    // parameterised constructor allows for a fileentry to be created in one line e.g:
    // fileList.append( FileEntry( fileObj.value("filename").toString(), static_cast<qint64>( fileObj.value("id").toInt() ) ) );
    // this is not currently used anywhere
    FileEntry(const QString &f, qint64 i)
        : filename(f)
        , id(i)
    {}
};

#endif // FILEENTRY_H
