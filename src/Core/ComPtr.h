#pragma once

namespace GuardDog {

// COM 接口指针的 RAII 封装。
// 与 ScopeHandle 分开的原因：COM 接口必须用 Release() 释放而不是 CloseHandle()，
// 且接口指针在失败分支上极易漏释放（服务是长驻进程，泄漏会持续累积）。
// 模板参数只做前向声明即可——成员函数体里才需要完整类型。
template <typename T>
class ComPtr {
public:
    ComPtr() noexcept = default;
    explicit ComPtr(T* pointer) noexcept : m_ptr(pointer) {}
    ~ComPtr() { Reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    // 取地址用于接收出参（例如 CoCreateInstance 的最后一个参数），先释放旧指针
    T** Put() noexcept {
        Reset();
        return &m_ptr;
    }

    void Reset() noexcept {
        if (m_ptr != nullptr) {
            m_ptr->Release();
            m_ptr = nullptr;
        }
    }

    // 接管一个"已持有的引用"（例如 new 出来、引用计数为 1 的对象）
    void Attach(T* pointer) noexcept {
        Reset();
        m_ptr = pointer;
    }

    // 交还所有权，调用方负责释放
    T* Detach() noexcept {
        T* pointer = m_ptr;
        m_ptr = nullptr;
        return pointer;
    }

    T* Get() const noexcept { return m_ptr; }
    T* operator->() const noexcept { return m_ptr; }
    bool IsValid() const noexcept { return m_ptr != nullptr; }

private:
    T* m_ptr = nullptr;
};

} // namespace GuardDog