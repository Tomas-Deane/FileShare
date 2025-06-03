// File: ./fileshareqt/utils/fileentry.h
#ifndef FILEENTRY_H
#define FILEENTRY_H

#include <QString>

// Simple struct to hold “filename + its server ID”
struct FileEntry {
    QString  filename;
    qint64   id;       // the database‐assigned file ID
};

#endif // FILEENTRY_H
