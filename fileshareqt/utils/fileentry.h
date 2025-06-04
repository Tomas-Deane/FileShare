#ifndef FILEENTRY_H
#define FILEENTRY_H

#include <QString>

// simple struct to hold “filename + its server ID”
struct FileEntry {
    QString  filename;
    qint64   id;

    // Default constructor
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

    //  overload “less than” so you can sort by filename when listing files
    bool operator<(const FileEntry &other) const {
        return filename < other.filename;
    }
};

#endif // FILEENTRY_H
