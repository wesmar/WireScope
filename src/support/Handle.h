// WireScope - RAII owners for Win32 resources (Modern C++23).
// Every handle the program opens is owned by one of these types.
#pragma once
#include <Windows.h>
#include <type_traits>
#include <utility>

namespace WS {

// Generic owner. Traits supplies the handle type, its "no handle" value and how to close it.
template <class Traits>
class Unique {
public:
    using Type = typename Traits::Type;

    Unique() noexcept = default;
    explicit Unique(Type value) noexcept : m_value(value) {}
    Unique(const Unique&) = delete;
    Unique& operator=(const Unique&) = delete;
    Unique(Unique&& other) noexcept : m_value(std::exchange(other.m_value, Traits::Invalid())) {}
    Unique& operator=(Unique&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.m_value, Traits::Invalid()));
        }
        return *this;
    }
    ~Unique() { reset(); }

    [[nodiscard]] Type get() const noexcept { return m_value; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_value != Traits::Invalid(); }
    [[nodiscard]] Type* put() noexcept { reset(); return &m_value; }
    Type release() noexcept { return std::exchange(m_value, Traits::Invalid()); }
    void reset(Type value = Traits::Invalid()) noexcept {
        if (m_value != Traits::Invalid()) {
            Traits::Close(m_value);
        }
        m_value = value;
    }

private:
    Type m_value = Traits::Invalid();
};

namespace traits {

struct KernelHandle {
    using Type = HANDLE;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

struct FileHandle {
    using Type = HANDLE;
    static Type Invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void Close(Type h) noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

struct FindHandle {
    using Type = HANDLE;
    static Type Invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void Close(Type h) noexcept { if (h && h != INVALID_HANDLE_VALUE) FindClose(h); }
};

struct ServiceHandle {
    using Type = SC_HANDLE;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { if (h) CloseServiceHandle(h); }
};

struct RegistryKey {
    using Type = HKEY;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { if (h) RegCloseKey(h); }
};

struct DeviceContext {
    using Type = HDC;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { if (h) DeleteDC(h); }
};

struct GdiObject {
    using Type = HGDIOBJ;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { if (h) DeleteObject(h); }
};

template <class T, auto CloseFn>
struct NullIsInvalid {
    using Type = T;
    static Type Invalid() noexcept { return nullptr; }
    static void Close(Type h) noexcept { CloseFn(h); }
};

inline void DeleteGdi(HGDIOBJ h) noexcept { DeleteObject(h); }
inline void DestroyMenuHandle(HMENU h) noexcept { DestroyMenu(h); }
inline void DestroyAccel(HACCEL h) noexcept { DestroyAcceleratorTable(h); }
inline void Unhook(HHOOK h) noexcept { UnhookWindowsHookEx(h); }
inline void DestroyIconHandle(HICON h) noexcept { DestroyIcon(h); }

} // namespace traits

using Handle = Unique<traits::KernelHandle>;
using FileHandle = Unique<traits::FileHandle>;
using FindHandle = Unique<traits::FindHandle>;        // FindFirstFile
using ServiceHandle = Unique<traits::ServiceHandle>;  // OpenSCManager, OpenService
using RegKey = Unique<traits::RegistryKey>;
using DeviceContextHandle = Unique<traits::DeviceContext>;
using MemoryDc = DeviceContextHandle;  // CreateCompatibleDC
using GdiHandle = Unique<traits::GdiObject>;
template <class T>
using Gdi = Unique<traits::NullIsInvalid<T, traits::DeleteGdi>>;  // HBRUSH, HFONT, HBITMAP ...
using MenuHandle = Unique<traits::NullIsInvalid<HMENU, traits::DestroyMenuHandle>>;
using AccelHandle = Unique<traits::NullIsInvalid<HACCEL, traits::DestroyAccel>>;
using HookHandle = Unique<traits::NullIsInvalid<HHOOK, traits::Unhook>>;
using IconHandle = Unique<traits::NullIsInvalid<HICON, traits::DestroyIconHandle>>;

// BeginPaint / EndPaint.
class PaintScope {
public:
    explicit PaintScope(HWND window) noexcept : m_window(window) { BeginPaint(window, &m_ps); }
    PaintScope(const PaintScope&) = delete;
    PaintScope& operator=(const PaintScope&) = delete;
    ~PaintScope() { EndPaint(m_window, &m_ps); }
    [[nodiscard]] HDC dc() const noexcept { return m_ps.hdc; }
    [[nodiscard]] const RECT& area() const noexcept { return m_ps.rcPaint; }

private:
    HWND m_window;
    PAINTSTRUCT m_ps{};
};

// Runs a callable on scope exit, for one-off cleanups that have no handle type.
template <class F>
class [[nodiscard]] ScopeExit {
public:
    explicit ScopeExit(F f) noexcept(std::is_nothrow_move_constructible_v<F>) : m_f(std::move(f)) {}
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    ~ScopeExit() { if (m_active) m_f(); }
    void dismiss() noexcept { m_active = false; }

private:
    F m_f;
    bool m_active = true;
};

} // namespace WS
