#include "FileRWLock.hpp"
#include <fstream>

FileRWLock::FileRWLock(const std::string& filename) : filename(filename), readersCount(0), writerPresent(false), mtx() {}

bool FileRWLock::openForRead() {
      #ifdef DEBUG
    printf("DEBUG>> Opening file %s for read\n", filename.c_str());
    #endif
  std::unique_lock<std::mutex> lock(mtx);

  // Wait for any writer or threads waiting to write
  while (writerPresent.load()) {
    cvReaders.wait(lock);
  }
  readersCount++;
  return true;
}

void FileRWLock::closeForRead() {
  std::unique_lock<std::mutex> lock(mtx);
  readersCount--;
  // If no readers and a writer is waiting, notify the writer
  if (readersCount == 0 && writerPresent.load()) {
    cvWriter.notify_one();
  }
}

bool FileRWLock::openForWrite() {
  std::unique_lock<std::mutex> lock(mtx);
  // Wait for all readers and any writer to finish
  while (readersCount > 0 || writerPresent.load()) {
    writerPresent = true;
    cvWriter.wait(lock);
    writerPresent = false;
  }
  return true;
}

void FileRWLock::closeForWrite() {
  std::unique_lock<std::mutex> lock(mtx);
  // Notify all waiting readers (if any)
  cvReaders.notify_all();
}
