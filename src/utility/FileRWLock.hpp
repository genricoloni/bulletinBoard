#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

class FileRWLock {
private:
  std::atomic<int> readersCount;
  std::atomic<bool> writerPresent;
  std::mutex mtx;
  std::condition_variable cvReaders, cvWriter;
  std::string filename;

public:
  FileRWLock(const std::string& filename);
  FileRWLock();

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

