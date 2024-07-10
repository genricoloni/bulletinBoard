#ifndef FILERWLOCK_HPP
#define FILERWLOCK_HPP

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>
#include "../utility/bbs.hpp"

class FileRWLock {
private:
  std::atomic<int> readersCount;
  std::atomic<bool> writerPresent;
  std::mutex mtx;
  std::condition_variable cvReaders, cvWriter;
  std::string filename;
  std::vector<message> messages;

public:
  FileRWLock(const std::string& filename);
  FileRWLock(const std::vector<message> messages);

  // Reader functions
  bool openForRead();
  void closeForRead();

  // Writer functions
  bool openForWrite();
  void closeForWrite();

  void printReaders() {
    printf("Readers count: %d\n", readersCount.load());
  }
};

#endif // FILERWLOCK_HPP
