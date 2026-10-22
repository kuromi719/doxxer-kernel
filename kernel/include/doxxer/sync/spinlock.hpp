#pragma once

#include <doxxer/types.hpp>

namespace doxxer::sync {
class SpinLock final {
  public:
    SpinLock() = default;
    SpinLock(const SpinLock&) = delete;
    SpinLock& operator=(const SpinLock&) = delete;

    void lock() {
        while (__atomic_test_and_set(&locked_, __ATOMIC_ACQUIRE)) {
            while (__atomic_load_n(&locked_, __ATOMIC_RELAXED)) {
                asm volatile("pause");
            }
        }
    }

    void unlock() { __atomic_clear(&locked_, __ATOMIC_RELEASE); }

  private:
    u8 locked_ = 0;
};

class LockGuard final {
  public:
    explicit LockGuard(SpinLock& lock) : lock_(lock) { lock_.lock(); }
    ~LockGuard() { lock_.unlock(); }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;

  private:
    SpinLock& lock_;
};
}
