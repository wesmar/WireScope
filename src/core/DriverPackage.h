// WireScope - Extracts the embedded driver package (wsddntf.inf, wsddntf.cat, wsddntf.sys) from the
// 24-bit RT_BITMAP resource WireScope.bmp (IDR_DRIVER_IMAGE). The DIB pixel array holds an LZX:21
// cabinet with its MSCF magic masked; cabinet.dll (FDICopy) unpacks it in memory.
#pragma once
#include <Windows.h>
#include <expected>
#include <string>
#include <vector>

namespace WS::DriverPackage {

struct File {
    std::wstring name;
    std::vector<BYTE> data;
};

[[nodiscard]] bool HasEmbeddedPackage() noexcept;
[[nodiscard]] std::expected<std::vector<File>, std::wstring> Extract();

// Stages the embedded package into a unique temporary folder for SetupAPI / WinVerifyTrust and
// deletes the files and folder again when destroyed.
class StagedFolder {
public:
    StagedFolder() = default;
    ~StagedFolder();
    StagedFolder(const StagedFolder&) = delete;
    StagedFolder& operator=(const StagedFolder&) = delete;
    StagedFolder(StagedFolder&& other) noexcept;
    StagedFolder& operator=(StagedFolder&& other) noexcept;

    [[nodiscard]] static std::expected<StagedFolder, std::wstring> Create();

    [[nodiscard]] const std::wstring& Folder() const noexcept { return m_folder; }
    [[nodiscard]] std::wstring InfPath() const { return m_folder.empty() ? std::wstring() : m_folder + L"\\wsddntf.inf"; }
    [[nodiscard]] std::wstring CatPath() const { return m_folder.empty() ? std::wstring() : m_folder + L"\\wsddntf.cat"; }

private:
    explicit StagedFolder(std::wstring folder) noexcept : m_folder(std::move(folder)) {}
    void Cleanup() noexcept;
    std::wstring m_folder;
};

}  // namespace WS::DriverPackage
