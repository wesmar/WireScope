#include "core/DriverPackage.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Handle.h"
#include "support/Language.h"
#include "support/Text.h"
#include <fdi.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>

#pragma comment(lib, "cabinet.lib")

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

namespace WS::DriverPackage {

namespace {

constexpr int kMaxInputHandles = 8;
constexpr int kMaxOutputs = 8;
constexpr INT_PTR kOutputHandleBase = 0x100;

// XOR mask applied to the 4-byte cabinet magic header at offset 0..3 ('M','S','C','F').
constexpr BYTE kHeaderMask[4] = {0xA5, 0x5A, 0xF0, 0x0F};
constexpr BYTE kMaskedMagic[4] = {0xE8, 0x09, 0xB3, 0x49};

struct InputHandle {
    bool active{false};
    size_t offset{0};
};

struct OutputHandle {
    bool active{false};
    bool complete{false};
    std::wstring name;
    std::vector<BYTE> data;
    size_t position{0};
    size_t logicalSize{0};
};

struct CabExtractionState {
    const BYTE* cabData{nullptr};
    size_t cabSize{0};
    InputHandle inputs[kMaxInputHandles]{};
    OutputHandle outputs[kMaxOutputs]{};
};

thread_local CabExtractionState* t_state = nullptr;

bool IsInputHandle(INT_PTR handle) noexcept {
    return handle >= 1 && handle <= kMaxInputHandles;
}

bool IsOutputHandle(INT_PTR handle) noexcept {
    const INT_PTR index = handle - kOutputHandleBase;
    return index >= 0 && index < kMaxOutputs && t_state && t_state->outputs[index].active;
}

std::wstring MapSlotName(const char* rawName) {
    if (!rawName) return {};
    const char* base = rawName;
    for (const char* p = rawName; *p; ++p) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    if (std::strcmp(base, "1") == 0 || _stricmp(base, "wsddntf.inf") == 0) return L"wsddntf.inf";
    if (std::strcmp(base, "2") == 0 || _stricmp(base, "wsddntf.cat") == 0) return L"wsddntf.cat";
    if (std::strcmp(base, "3") == 0 || _stricmp(base, "wsddntf.sys") == 0) return L"wsddntf.sys";
    return {};
}

LPVOID DIAMONDAPI FdiAlloc(ULONG size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void DIAMONDAPI FdiFree(LPVOID memory) {
    if (memory) HeapFree(GetProcessHeap(), 0, memory);
}

INT_PTR DIAMONDAPI FdiOpen(LPSTR, int, int) {
    if (!t_state) return -1;
    for (int i = 0; i < kMaxInputHandles; ++i) {
        if (!t_state->inputs[i].active) {
            t_state->inputs[i].active = true;
            t_state->inputs[i].offset = 0;
            return i + 1;
        }
    }
    return -1;
}

UINT DIAMONDAPI FdiRead(INT_PTR handle, void* destination, UINT requested) {
    if (!t_state || !IsInputHandle(handle)) return 0;

    InputHandle& input = t_state->inputs[handle - 1];
    if (!input.active || input.offset >= t_state->cabSize) return 0;

    const size_t available = t_state->cabSize - input.offset;
    const UINT toRead = (requested < available) ? requested : static_cast<UINT>(available);
    if (toRead == 0) return 0;

    std::memcpy(destination, t_state->cabData + input.offset, toRead);

    // Unmask the 4-byte cabinet signature in-flight when reading offset 0..3.
    if (input.offset < 4) {
        const size_t limit = (std::min)(static_cast<size_t>(4) - input.offset, static_cast<size_t>(toRead));
        auto* bytes = static_cast<BYTE*>(destination);
        for (size_t i = 0; i < limit; ++i) {
            bytes[i] ^= kHeaderMask[input.offset + i];
        }
    }

    input.offset += toRead;
    return toRead;
}

UINT DIAMONDAPI FdiWrite(INT_PTR handle, void* source, UINT byteCount) {
    if (!t_state || byteCount == 0 || !IsOutputHandle(handle)) return 0;

    OutputHandle& output = t_state->outputs[handle - kOutputHandleBase];
    const size_t endPosition = output.position + byteCount;
    if (endPosition > output.data.size()) output.data.resize(endPosition);

    std::memcpy(output.data.data() + output.position, source, byteCount);
    output.position = endPosition;
    if (output.position > output.logicalSize) output.logicalSize = output.position;
    return byteCount;
}

int DIAMONDAPI FdiClose(INT_PTR handle) {
    if (!t_state) return -1;
    if (IsInputHandle(handle)) {
        t_state->inputs[handle - 1].active = false;
        return 0;
    }
    if (IsOutputHandle(handle)) {
        OutputHandle& output = t_state->outputs[handle - kOutputHandleBase];
        output.data.resize(output.logicalSize);
        output.position = output.logicalSize;
        output.complete = true;
        return 0;
    }
    return -1;
}

long DIAMONDAPI FdiSeek(INT_PTR handle, long distance, int origin) {
    if (!t_state) return -1;

    if (IsInputHandle(handle)) {
        InputHandle& input = t_state->inputs[handle - 1];
        if (!input.active) return -1;

        LONGLONG newOffset = 0;
        switch (origin) {
        case SEEK_SET: newOffset = distance; break;
        case SEEK_CUR: newOffset = static_cast<LONGLONG>(input.offset) + distance; break;
        case SEEK_END: newOffset = static_cast<LONGLONG>(t_state->cabSize) + distance; break;
        default: return -1;
        }
        if (newOffset < 0 || static_cast<size_t>(newOffset) > t_state->cabSize) return -1;
        input.offset = static_cast<size_t>(newOffset);
        return static_cast<long>(input.offset);
    }

    if (IsOutputHandle(handle)) {
        OutputHandle& output = t_state->outputs[handle - kOutputHandleBase];
        LONGLONG newOffset = 0;
        switch (origin) {
        case SEEK_SET: newOffset = distance; break;
        case SEEK_CUR: newOffset = static_cast<LONGLONG>(output.position) + distance; break;
        case SEEK_END: newOffset = static_cast<LONGLONG>(output.logicalSize) + distance; break;
        default: return -1;
        }
        if (newOffset < 0) return -1;
        output.position = static_cast<size_t>(newOffset);
        if (output.position > output.logicalSize) {
            output.logicalSize = output.position;
            output.data.resize(output.logicalSize);
        }
        return static_cast<long>(output.position);
    }

    return -1;
}

INT_PTR DIAMONDAPI FdiNotify(FDINOTIFICATIONTYPE type, PFDINOTIFICATION notification) {
    if (!t_state || !notification) return -1;

    if (type == fdintCOPY_FILE) {
        const std::wstring mapped = MapSlotName(notification->psz1);
        if (mapped.empty()) return -1;

        int index = -1;
        for (int i = 0; i < kMaxOutputs; ++i) {
            if (!t_state->outputs[i].active) {
                index = i;
                break;
            }
        }
        if (index < 0) return -1;

        OutputHandle& output = t_state->outputs[index];
        output.active = true;
        output.complete = false;
        output.name = mapped;
        output.position = 0;
        output.logicalSize = 0;
        output.data.clear();
        if (notification->cb > 0) output.data.reserve(static_cast<size_t>(notification->cb));
        return kOutputHandleBase + index;
    }

    if (type == fdintCLOSE_FILE_INFO) {
        if (!IsOutputHandle(notification->hf)) return FALSE;
        OutputHandle& output = t_state->outputs[notification->hf - kOutputHandleBase];
        output.data.resize(output.logicalSize);
        output.position = output.logicalSize;
        output.complete = true;
        return TRUE;
    }

    return 0;
}

struct BmpCabinetSlice {
    const BYTE* data{nullptr};
    size_t size{0};
};

std::optional<BmpCabinetSlice> LocateEmbeddedCabinet() noexcept {
    const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_DRIVER_IMAGE), RT_BITMAP);
    if (!resource) return std::nullopt;

    const DWORD resourceSize = SizeofResource(nullptr, resource);
    if (resourceSize < 40) return std::nullopt;

    const HGLOBAL loaded = LoadResource(nullptr, resource);
    if (!loaded) return std::nullopt;

    const auto* raw = static_cast<const BYTE*>(LockResource(loaded));
    if (!raw) return std::nullopt;

    DWORD cabSize = 0;
    size_t offBits = 0;
    if (resourceSize >= 54 && raw[0] == 0x42 && raw[1] == 0x4D) {
        DWORD fileOffBits = 0;
        std::memcpy(&cabSize, raw + 6, sizeof(DWORD));   // bfReserved1 + bfReserved2
        std::memcpy(&fileOffBits, raw + 10, sizeof(DWORD));  // bfOffBits
        offBits = fileOffBits;
    } else {
        DWORD dibSize = 0, colorsUsed = 0;
        WORD bitsPerPixel = 0;
        std::memcpy(&dibSize, raw, sizeof(DWORD));
        std::memcpy(&bitsPerPixel, raw + 14, sizeof(WORD));
        std::memcpy(&cabSize, raw + 36, sizeof(DWORD));  // biClrImportant
        std::memcpy(&colorsUsed, raw + 32, sizeof(DWORD));
        if (dibSize < 40 || dibSize > resourceSize || bitsPerPixel != 24 ||
            colorsUsed > (resourceSize - dibSize) / 4) {
            return std::nullopt;
        }
        offBits = static_cast<size_t>(dibSize) + static_cast<size_t>(colorsUsed) * 4;
    }

    if (cabSize < 4 || offBits > resourceSize || cabSize > resourceSize - offBits) {
        return std::nullopt;
    }
    if (std::memcmp(raw + offBits, kMaskedMagic, 4) != 0) return std::nullopt;

    return BmpCabinetSlice{raw + offBits, cabSize};
}

}  // namespace

bool HasEmbeddedPackage() noexcept {
    return LocateEmbeddedCabinet().has_value();
}

std::expected<std::vector<File>, std::wstring> Extract() {
    const auto slice = LocateEmbeddedCabinet();
    if (!slice) return std::unexpected(Text::Get(IDS_DRV_NO_PACKAGE_FOLDER));

    CabExtractionState state;
    state.cabData = slice->data;
    state.cabSize = slice->size;
    t_state = &state;

    ERF errorInfo{};
    const HFDI fdi = FDICreate(FdiAlloc, FdiFree, FdiOpen, FdiRead, FdiWrite, FdiClose, FdiSeek, cpuUNKNOWN, &errorInfo);
    if (!fdi) {
        t_state = nullptr;
        return std::unexpected(Text::Format(IDS_DRV_API, L"FDICreate", std::to_wstring(errorInfo.erfOper)));
    }

    char cabName[] = "package.cab";
    char cabPath[] = "";
    const BOOL extracted = FDICopy(fdi, cabName, cabPath, 0, FdiNotify, nullptr, nullptr);
    FDIDestroy(fdi);
    t_state = nullptr;

    if (!extracted) {
        return std::unexpected(Text::Format(IDS_DRV_API, L"FDICopy", std::to_wstring(errorInfo.erfOper)));
    }

    std::vector<File> files;
    for (OutputHandle& out : state.outputs) {
        if (out.active && out.complete && !out.name.empty() && !out.data.empty()) {
            files.push_back({std::move(out.name), std::move(out.data)});
        }
    }

    for (const wchar_t* required : {L"wsddntf.inf", L"wsddntf.cat", L"wsddntf.sys"}) {
        const bool found = std::ranges::any_of(files, [&](const File& f) { return f.name == required; });
        if (!found) return std::unexpected(Text::Format(IDS_DRV_NO_PACKAGE, required));
    }
    return files;
}

StagedFolder::~StagedFolder() {
    Cleanup();
}

StagedFolder::StagedFolder(StagedFolder&& other) noexcept : m_folder(std::move(other.m_folder)) {
    other.m_folder.clear();
}

StagedFolder& StagedFolder::operator=(StagedFolder&& other) noexcept {
    if (this != &other) {
        Cleanup();
        m_folder = std::move(other.m_folder);
        other.m_folder.clear();
    }
    return *this;
}

void StagedFolder::Cleanup() noexcept {
    if (m_folder.empty()) return;
    for (const wchar_t* name : {L"wsddntf.inf", L"wsddntf.cat", L"wsddntf.sys"}) {
        const std::wstring path = m_folder + L"\\" + name;
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(path.c_str());
    }
    RemoveDirectoryW(m_folder.c_str());
    m_folder.clear();
}

std::expected<StagedFolder, std::wstring> StagedFolder::Create() {
    auto files = Extract();
    if (!files) return std::unexpected(files.error());

    wchar_t tempBase[MAX_PATH]{};
    const DWORD len = GetTempPathW(MAX_PATH, tempBase);
    if (len == 0 || len >= MAX_PATH) {
        return std::unexpected(Text::Format(IDS_DRV_API, L"GetTempPath", FormatError()));
    }

    static std::atomic<uint32_t> s_seq{0};
    const std::wstring folder = std::format(L"{}WireScope_pkg_{}_{}_{}", tempBase, GetCurrentProcessId(), GetTickCount64(), ++s_seq);
    if (!CreateDirectoryW(folder.c_str(), nullptr)) {
        return std::unexpected(Text::Format(IDS_DRV_API, L"CreateDirectory", FormatError()));
    }

    StagedFolder staged(folder);
    for (const File& file : *files) {
        const std::wstring path = folder + L"\\" + file.name;
        const FileHandle h(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) return std::unexpected(Text::Format(IDS_DRV_API, L"CreateFile", FormatError()));

        DWORD written = 0;
        const auto size = static_cast<DWORD>(file.data.size());
        if (!WriteFile(h.get(), file.data.data(), size, &written, nullptr) || written != size) {
            return std::unexpected(Text::Format(IDS_DRV_API, L"WriteFile", FormatError()));
        }
    }
    return staged;
}

}  // namespace WS::DriverPackage
