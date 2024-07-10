#ifndef FILERWLOCK_HPP
#define FILERWLOCK_HPP

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>

class FileRWLock {
private:
  std::atomic<int> readersCount;
  std::atomic<bool> writerPresent;
  std::mutex mtx;
  std::condition_variable cvReaders, cvWriter;
  std::string filename;

public:
  FileRWLock(const std::string& filename);

  // Reader functions
  bool openForRead();
  void closeForRead();

  // Writer functions
  bool openForWrite();
  void closeForWrite();
};

#endif // FILERWLOCK_HPP
