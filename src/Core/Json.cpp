#include "Core/Json.h"

#include <windows.h>

#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <sstream>

namespace GuardDog {

namespace {

// 限制嵌套深度：配置文件是人为编辑的，正常的防护规则不会嵌套 64 层，
// 限制深度可以避免畸形文件把解析器压爆栈（递归下降的固有风险）。
constexpr size_t kMaxDepth = 64;

bool ReadFileBytes(const std::wstring& path, std::string& out, std::wstring* error) {
    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file.is_open()) {
        if (error != nullptr) {
            *error = L"无法打开文件（可能不存在或无访问权限）";
        }
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

std::wstring ToWide(const std::string& bytes, UINT codePage) {
    if (bytes.empty()) {
        return std::wstring();
    }

    const DWORD flags = (codePage == CP_UTF8) ? MB_ERR_INVALID_CHARS : 0;
    const int length = MultiByteToWideChar(codePage, flags, bytes.data(),
                                           static_cast<int>(bytes.size()), nullptr, 0);
    if (length <= 0) {
        return std::wstring();
    }

    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(codePage, flags, bytes.data(), static_cast<int>(bytes.size()), result.data(),
                        length);
    return result;
}

} // namespace

// 递归下降解析器。所有失败路径都通过 m_errorText 上报带行列号的信息，
// 便于用户直接在编辑器里定位配置写错的位置。
// 注意：它必须位于 GuardDog 命名空间（不能塞进匿名命名空间），
// 因为 JsonValue 用 friend 声明了 GuardDog::JsonParser 来访问私有成员。
class JsonParser {
public:
    explicit JsonParser(const std::wstring& text) : m_text(text) {}

    bool Parse(JsonValue& root, std::wstring& error) {
        SkipWhitespace();
        if (m_pos >= m_text.size()) {
            error = MakeError(L"内容为空");
            return false;
        }

        if (!ParseValue(root, 0)) {
            error = MakeError(m_errorText);
            return false;
        }

        SkipWhitespace();
        if (m_pos < m_text.size()) {
            error = MakeError(L"顶层值之后存在多余内容");
            return false;
        }
        return true;
    }

private:
    void SkipWhitespace() {
        while (m_pos < m_text.size()) {
            const wchar_t ch = m_text[m_pos];
            if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n') {
                ++m_pos;
                continue;
            }
            break;
        }
    }

    bool Fail(const wchar_t* message) {
        if (m_errorText.empty()) {
            m_errorText = message;
        }
        return false;
    }

    std::wstring MakeError(const std::wstring& message) const {
        size_t line = 1;
        size_t column = 1;
        for (size_t i = 0; i < m_pos && i < m_text.size(); ++i) {
            if (m_text[i] == L'\n') {
                ++line;
                column = 1;
            } else {
                ++column;
            }
        }
        wchar_t prefix[64] = {};
        swprintf_s(prefix, L"第 %llu 行第 %llu 列：", static_cast<unsigned long long>(line),
                   static_cast<unsigned long long>(column));
        return std::wstring(prefix) + message;
    }

    bool ParseValue(JsonValue& out, size_t depth) {
        if (depth > kMaxDepth) {
            return Fail(L"嵌套层级过深");
        }

        SkipWhitespace();
        if (m_pos >= m_text.size()) {
            return Fail(L"内容意外结束");
        }

        switch (const wchar_t ch = m_text[m_pos]) {
            case L'{':
                return ParseObject(out, depth);
            case L'[':
                return ParseArray(out, depth);
            case L'"': {
                std::wstring text;
                if (!ParseString(text)) {
                    return false;
                }
                out.m_type = JsonValue::Type::String;
                out.m_string = std::move(text);
                return true;
            }
            case L't':
                return ParseLiteral(L"true", true, out);
            case L'f':
                return ParseLiteral(L"false", false, out);
            case L'n':
                return ParseLiteral(L"null", false, out, true);
            default:
                if (ch == L'-' || ch == L'+' || (ch >= L'0' && ch <= L'9')) {
                    return ParseNumber(out);
                }
                return Fail(L"无法识别的值（期望对象、数组、字符串、数字、true/false/null）");
        }
    }

    bool ParseLiteral(const wchar_t* literal, bool boolValue, JsonValue& out,
                      bool isNull = false) {
        const size_t length = wcslen(literal);
        if (m_text.compare(m_pos, length, literal) != 0) {
            return Fail(L"无效的字面量（期望 true / false / null）");
        }
        m_pos += length;

        out.m_type = isNull ? JsonValue::Type::Null : JsonValue::Type::Bool;
        out.m_bool = boolValue;
        return true;
    }

    bool ParseObject(JsonValue& out, size_t depth) {
        ++m_pos;  // 跳过 '{'

        out.m_type = JsonValue::Type::Object;
        out.m_object.clear();

        SkipWhitespace();
        if (m_pos < m_text.size() && m_text[m_pos] == L'}') {
            ++m_pos;
            return true;
        }

        for (;;) {
            SkipWhitespace();
            if (m_pos >= m_text.size() || m_text[m_pos] != L'"') {
                return Fail(L"对象的键必须是双引号字符串");
            }

            std::wstring key;
            if (!ParseString(key)) {
                return false;
            }

            SkipWhitespace();
            if (m_pos >= m_text.size() || m_text[m_pos] != L':') {
                return Fail(L"对象键之后缺少冒号");
            }
            ++m_pos;

            JsonValue value;
            if (!ParseValue(value, depth + 1)) {
                return false;
            }
            out.m_object.emplace_back(std::move(key), std::move(value));

            SkipWhitespace();
            if (m_pos >= m_text.size()) {
                return Fail(L"对象未闭合");
            }
            if (m_text[m_pos] == L',') {
                ++m_pos;
                continue;
            }
            if (m_text[m_pos] == L'}') {
                ++m_pos;
                return true;
            }
            return Fail(L"对象成员之间缺少逗号或右花括号");
        }
    }

    bool ParseArray(JsonValue& out, size_t depth) {
        ++m_pos;  // 跳过 '['

        out.m_type = JsonValue::Type::Array;
        out.m_array.clear();

        SkipWhitespace();
        if (m_pos < m_text.size() && m_text[m_pos] == L']') {
            ++m_pos;
            return true;
        }

        for (;;) {
            JsonValue value;
            if (!ParseValue(value, depth + 1)) {
                return false;
            }
            out.m_array.push_back(std::move(value));

            SkipWhitespace();
            if (m_pos >= m_text.size()) {
                return Fail(L"数组未闭合");
            }
            if (m_text[m_pos] == L',') {
                ++m_pos;
                continue;
            }
            if (m_text[m_pos] == L']') {
                ++m_pos;
                return true;
            }
            return Fail(L"数组元素之间缺少逗号或右方括号");
        }
    }

    bool ParseString(std::wstring& out) {
        if (m_pos >= m_text.size() || m_text[m_pos] != L'"') {
            return Fail(L"期望字符串");
        }
        ++m_pos;

        out.clear();
        while (m_pos < m_text.size()) {
            const wchar_t ch = m_text[m_pos++];
            if (ch == L'"') {
                return true;
            }
            if (ch != L'\\') {
                if (ch < 0x20) {
                    return Fail(L"字符串中存在未转义的控制字符");
                }
                out.push_back(ch);
                continue;
            }

            if (m_pos >= m_text.size()) {
                return Fail(L"转义序列不完整");
            }

            switch (const wchar_t escape = m_text[m_pos++]) {
                case L'"':  out.push_back(L'"');  break;
                case L'\\': out.push_back(L'\\'); break;
                case L'/':  out.push_back(L'/');  break;
                case L'b':  out.push_back(L'\b'); break;
                case L'f':  out.push_back(L'\f'); break;
                case L'n':  out.push_back(L'\n'); break;
                case L'r':  out.push_back(L'\r'); break;
                case L't':  out.push_back(L'\t'); break;
                case L'u': {
                    unsigned int code = 0;
                    if (!ParseHex4(code)) {
                        return false;
                    }
                    // 处理 UTF-16 代理对（\uD83D\uDE00 这类需要合并的字符）
                    if (code >= 0xD800 && code <= 0xDBFF && m_pos + 1 < m_text.size() &&
                        m_text[m_pos] == L'\\' && m_text[m_pos + 1] == L'u') {
                        const size_t savedPos = m_pos;
                        m_pos += 2;
                        unsigned int low = 0;
                        if (!ParseHex4(low)) {
                            return false;
                        }
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            const unsigned int codePoint =
                                0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            out.push_back(static_cast<wchar_t>(0xD800 + ((codePoint - 0x10000) >> 10)));
                            out.push_back(static_cast<wchar_t>(0xDC00 + ((codePoint - 0x10000) & 0x3FF)));
                            break;
                        }
                        // 不是合法的低位代理：按原样保留两个码元
                        m_pos = savedPos;
                        out.push_back(static_cast<wchar_t>(code));
                        break;
                    }
                    out.push_back(static_cast<wchar_t>(code));
                    break;
                }
                default:
                    return Fail(L"未知的转义字符");
            }
        }
        return Fail(L"字符串未闭合");
    }

    bool ParseHex4(unsigned int& value) {
        if (m_pos + 4 > m_text.size()) {
            return Fail(L"\\u 转义需要 4 位十六进制数字");
        }

        unsigned int result = 0;
        for (int i = 0; i < 4; ++i) {
            const wchar_t ch = m_text[m_pos++];
            unsigned int digit = 0;
            if (ch >= L'0' && ch <= L'9') {
                digit = static_cast<unsigned int>(ch - L'0');
            } else if (ch >= L'a' && ch <= L'f') {
                digit = static_cast<unsigned int>(ch - L'a') + 10;
            } else if (ch >= L'A' && ch <= L'F') {
                digit = static_cast<unsigned int>(ch - L'A') + 10;
            } else {
                return Fail(L"\\u 转义包含非法的十六进制字符");
            }
            result = (result << 4) | digit;
        }
        value = result;
        return true;
    }

    bool ParseNumber(JsonValue& out) {
        const size_t start = m_pos;

        if (m_text[m_pos] == L'-' || m_text[m_pos] == L'+') {
            ++m_pos;
        }
        while (m_pos < m_text.size()) {
            const wchar_t ch = m_text[m_pos];
            if ((ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L'e' || ch == L'E' || ch == L'-' ||
                ch == L'+') {
                ++m_pos;
                continue;
            }
            break;
        }

        const std::wstring token = m_text.substr(start, m_pos - start);
        wchar_t* end = nullptr;
        const double value = wcstod(token.c_str(), &end);
        if (end == token.c_str() || *end != L'\0') {
            return Fail(L"无效的数字");
        }

        out.m_type = JsonValue::Type::Number;
        out.m_number = value;
        return true;
    }

    const std::wstring& m_text;
    size_t m_pos = 0;
    std::wstring m_errorText;
};

const JsonValue& JsonValue::NullValue() noexcept {
    static const JsonValue nullValue;
    return nullValue;
}

bool JsonValue::AsBool(bool fallback) const noexcept {
    return m_type == Type::Bool ? m_bool : fallback;
}

double JsonValue::AsNumber(double fallback) const noexcept {
    return m_type == Type::Number ? m_number : fallback;
}

int JsonValue::AsInt(int fallback) const noexcept {
    return m_type == Type::Number ? static_cast<int>(m_number) : fallback;
}

std::wstring JsonValue::AsString(const std::wstring& fallback) const {
    return m_type == Type::String ? m_string : fallback;
}

size_t JsonValue::GetSize() const noexcept {
    if (m_type == Type::Array) {
        return m_array.size();
    }
    if (m_type == Type::Object) {
        return m_object.size();
    }
    return 0;
}

const JsonValue& JsonValue::At(size_t index) const noexcept {
    if (m_type != Type::Array || index >= m_array.size()) {
        return NullValue();
    }
    return m_array[index];
}

bool JsonValue::Has(const std::wstring& key) const noexcept {
    if (m_type != Type::Object) {
        return false;
    }
    for (const auto& member : m_object) {
        if (member.first == key) {
            return true;
        }
    }
    return false;
}

const JsonValue& JsonValue::Find(const std::wstring& key) const noexcept {
    if (m_type != Type::Object) {
        return NullValue();
    }
    for (const auto& member : m_object) {
        if (member.first == key) {
            return member.second;
        }
    }
    return NullValue();
}

JsonValue JsonValue::ParseUtf8(const std::string& text, std::wstring* error) {
    std::string bytes = text;

    // 跳过 UTF-8 BOM（记事本、VS Code 另存为时都可能带上）
    if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB && static_cast<unsigned char>(bytes[2]) == 0xBF) {
        bytes.erase(0, 3);
    }

    std::wstring wide = ToWide(bytes, CP_UTF8);
    if (wide.empty() && !bytes.empty()) {
        // 兼容用户用记事本存成 ANSI(GBK) 的情况：UTF-8 解不出来时退回系统代码页
        wide = ToWide(bytes, CP_ACP);
        if (wide.empty()) {
            if (error != nullptr) {
                *error = L"文件编码无法识别（既不是 UTF-8 也不是系统本地编码）";
            }
            return JsonValue();
        }
    }

    JsonParser parser(wide);
    JsonValue root;
    std::wstring parseError;
    if (!parser.Parse(root, parseError)) {
        if (error != nullptr) {
            *error = parseError;
        }
        return JsonValue();
    }
    return root;
}

JsonValue JsonValue::ParseFile(const std::wstring& path, std::wstring* error) {
    std::string bytes;
    if (!ReadFileBytes(path, bytes, error)) {
        return JsonValue();
    }
    return ParseUtf8(bytes, error);
}

// ---------------------------------------------------------------------------
// 写侧实现
// ---------------------------------------------------------------------------

namespace {

std::string ToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }

    // 不传 WC_ERR_INVALID_CHARS：对未配对的代理码元按替换字符处理，
    // 而不是让整次转换失败——配置文本出现个别异常字符时仍应能写出去。
    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return std::string();
    }

    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length,
                        nullptr, nullptr);
    return result;
}

void AppendEscapedString(const std::wstring& text, std::string& out) {
    out.push_back('"');

    // 先转 UTF-8 再逐字节转义：多字节序列的每个字节都 >= 0x80，
    // 不会与控制字符 / 引号 / 反斜杠的判定冲突，转义逻辑因此可以按字节做。
    const std::string utf8 = ToUtf8(text);
    for (const char rawByte : utf8) {
        const unsigned char byte = static_cast<unsigned char>(rawByte);
        switch (byte) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (byte < 0x20) {
                    // 其余控制字符走 \u00XX 形式（JSON 规范不允许裸控制字符）
                    char buffer[8] = {};
                    sprintf_s(buffer, "\\u%04x", byte);
                    out += buffer;
                } else {
                    out.push_back(rawByte);
                }
                break;
        }
    }

    out.push_back('"');
}

void AppendNumber(double number, std::string& out) {
    char buffer[40] = {};

    // 整数值按整数输出：500 写成 "500" 而不是 "500.0"，
    // 配置回写后看起来和用户手写的一致。
    if (number > -1e15 && number < 1e15 && number == static_cast<double>(static_cast<long long>(number))) {
        sprintf_s(buffer, "%lld", static_cast<long long>(number));
    } else {
        sprintf_s(buffer, "%.10g", number);
    }
    out += buffer;
}

void SerializeValue(const JsonValue& value, int indentSpaces, int depth, std::string& out) {
    switch (value.GetType()) {
        case JsonValue::Type::Null:
            out += "null";
            return;
        case JsonValue::Type::Bool:
            out += value.AsBool() ? "true" : "false";
            return;
        case JsonValue::Type::Number:
            AppendNumber(value.AsNumber(), out);
            return;
        case JsonValue::Type::String:
            AppendEscapedString(value.AsString(), out);
            return;
        case JsonValue::Type::Array: {
            const std::vector<JsonValue>& items = value.GetArray();
            if (items.empty()) {
                out += "[]";
                return;
            }
            out.push_back('[');
            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) {
                    out.push_back(',');
                }
                if (indentSpaces > 0) {
                    out += "\r\n";
                    out.append(static_cast<size_t>((depth + 1) * indentSpaces), ' ');
                }
                SerializeValue(items[i], indentSpaces, depth + 1, out);
            }
            if (indentSpaces > 0) {
                out += "\r\n";
                out.append(static_cast<size_t>(depth * indentSpaces), ' ');
            }
            out.push_back(']');
            return;
        }
        case JsonValue::Type::Object: {
            const std::vector<std::pair<std::wstring, JsonValue>>& members = value.GetMembers();
            if (members.empty()) {
                out += "{}";
                return;
            }
            out.push_back('{');
            for (size_t i = 0; i < members.size(); ++i) {
                if (i > 0) {
                    out.push_back(',');
                }
                if (indentSpaces > 0) {
                    out += "\r\n";
                    out.append(static_cast<size_t>((depth + 1) * indentSpaces), ' ');
                }
                AppendEscapedString(members[i].first, out);
                out += (indentSpaces > 0) ? ": " : ":";
                SerializeValue(members[i].second, indentSpaces, depth + 1, out);
            }
            if (indentSpaces > 0) {
                out += "\r\n";
                out.append(static_cast<size_t>(depth * indentSpaces), ' ');
            }
            out.push_back('}');
            return;
        }
    }
}

} // namespace

JsonValue JsonValue::MakeObject() {
    JsonValue value;
    value.m_type = Type::Object;
    return value;
}

JsonValue JsonValue::MakeArray() {
    JsonValue value;
    value.m_type = Type::Array;
    return value;
}

JsonValue JsonValue::MakeString(std::wstring text) {
    JsonValue value;
    value.m_type = Type::String;
    value.m_string = std::move(text);
    return value;
}

JsonValue JsonValue::MakeNumber(double number) {
    JsonValue value;
    value.m_type = Type::Number;
    value.m_number = number;
    return value;
}

JsonValue JsonValue::MakeBool(bool state) {
    JsonValue value;
    value.m_type = Type::Bool;
    value.m_bool = state;
    return value;
}

void JsonValue::Set(const std::wstring& key, JsonValue value) {
    if (m_type != Type::Object) {
        return;
    }
    for (std::pair<std::wstring, JsonValue>& member : m_object) {
        if (member.first == key) {
            member.second = std::move(value);
            return;
        }
    }
    m_object.emplace_back(key, std::move(value));
}

void JsonValue::PushBack(JsonValue value) {
    if (m_type != Type::Array) {
        return;
    }
    m_array.push_back(std::move(value));
}

std::string JsonValue::SerializeUtf8(int indentSpaces) const {
    std::string out;
    out.reserve(2048);
    SerializeValue(*this, indentSpaces < 0 ? 0 : indentSpaces, 0, out);
    return out;
}

} // namespace GuardDog