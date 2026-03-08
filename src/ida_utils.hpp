#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <utility>

#include <ida.hpp>
#include <typeinf.hpp>
#include <nlohmann/json.hpp>

struct settings_t;

namespace ida_utils
{
    using GetCodeCallbackT = std::function<void(const std::pair<std::string, std::string>&)>;

    std::pair<std::string, std::string> GetFunctionCode(ea_t ea, size_t max_len = 0, bool force_assembly = false);
    void GetFunctionCode(ea_t ea, GetCodeCallbackT callback, size_t max_len = 0, bool force_assembly = false);
    std::string GetCodeXrefsTo(ea_t ea, const settings_t& settings);
    std::string GetCodeXrefsFrom(ea_t ea, const settings_t& settings);
    std::string GetStructUsageContext(ea_t ea);
    std::string GetDataXrefsForStruct(const tinfo_t& struct_tif, const settings_t& settings);
    nlohmann::json GetContextForPrompt(ea_t ea, bool include_struct_context = false, size_t max_len = 0);

    std::string MarkupTextWithAddresses(const std::string& text);
    std::string FormatContextForClipboard(const nlohmann::json& context);
    std::string FormatPrompt(const char* prompt_template, const nlohmann::json& context);

    bool SetClipboardText(const qstring& text);
    void ApplyStructFromCpp(const std::string& cpp_code, ea_t ea);
    qstring ApplyRenamesFromAi(ea_t func_ea, const std::string& cpp_code);

    bool IsWordChar(char c);
    func_t* GetFunctionForItem(ea_t ea);
    qstring QStringToLower(const qstring& s);
    bool GetAddressFromLinePos(ea_t* out_ea, const char* line, int x);
}