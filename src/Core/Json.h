#pragma once

#include <string>
#include <utility>
#include <vector>

namespace GuardDog {

// 极简 JSON 解析器 + 最小序列化器。
//
// 为什么自实现而不用第三方库：本项目定位是"零外部依赖、离线可编译"，
// 而 GuardDog 配置的语法复杂度很低（对象 / 数组 / 字符串 / 数字 / 布尔 / null），
// 自实现的代码量与审计成本都低于引入一个几百 KB 的头文件库。
// 写侧只实现规则编辑界面所需的最小集合（构造、覆写、追加、序列化），
// 不做完整的文档模型——保留原始树 + 覆写目标字段即可，避免回写时丢掉未知字段。
class JsonValue {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    JsonValue() = default;

    Type GetType() const noexcept { return m_type; }
    bool IsNull() const noexcept { return m_type == Type::Null; }
    bool IsBool() const noexcept { return m_type == Type::Bool; }
    bool IsNumber() const noexcept { return m_type == Type::Number; }
    bool IsString() const noexcept { return m_type == Type::String; }
    bool IsArray() const noexcept { return m_type == Type::Array; }
    bool IsObject() const noexcept { return m_type == Type::Object; }

    // 宽松取值：类型不符时返回 fallback，避免配置里少写一个字段就让服务启动失败
    bool AsBool(bool fallback = false) const noexcept;
    double AsNumber(double fallback = 0.0) const noexcept;
    int AsInt(int fallback = 0) const noexcept;
    std::wstring AsString(const std::wstring& fallback = std::wstring()) const;

    // 数组元素个数 / 对象成员个数
    size_t GetSize() const noexcept;

    // 数组下标访问，越界返回 Null 值（不会抛异常）
    const JsonValue& At(size_t index) const noexcept;
    // 对象成员访问，不存在返回 Null 值
    const JsonValue& Find(const std::wstring& key) const noexcept;
    bool Has(const std::wstring& key) const noexcept;

    const std::vector<JsonValue>& GetArray() const noexcept { return m_array; }
    // 注意：刻意不叫 GetObject——windows.h 把 GetObject 定义成了宏（GDI 的 GetObjectW），
    // 任何包含 windows.h 的翻译单元调用该名字都会被宏展开成 GetObjectW
    const std::vector<std::pair<std::wstring, JsonValue>>& GetMembers() const noexcept {
        return m_object;
    }

    // 解析 UTF-8 文本；失败返回 Null 并写入 error（含行列号）
    static JsonValue ParseUtf8(const std::string& text, std::wstring* error);
    // 读文件并解析：自动处理 UTF-8 BOM，UTF-8 解码失败时回退系统代码页（兼容记事本存成 ANSI 的情况）
    static JsonValue ParseFile(const std::wstring& path, std::wstring* error);

    // ---- 写侧：构造与修改（供规则编辑界面回写配置）----
    static JsonValue MakeObject();
    static JsonValue MakeArray();
    static JsonValue MakeString(std::wstring text);
    static JsonValue MakeNumber(double number);
    static JsonValue MakeBool(bool value);

    // 对象：同名成员存在则替换，不存在则追加。
    // 追加而非重建整个对象，是为了尽量保留用户手工写在配置里的未知字段。
    void Set(const std::wstring& key, JsonValue value);
    // 数组：追加元素；非数组类型时忽略（宽松处理，避免调用方到处判类型）
    void PushBack(JsonValue value);

    // 序列化为 UTF-8 文本（带缩进、CRLF 换行，方便用户直接用记事本查看）。
    // indentSpaces 为每层缩进空格数，0 表示紧凑输出。
    std::string SerializeUtf8(int indentSpaces = 2) const;

private:
    static const JsonValue& NullValue() noexcept;

    Type m_type = Type::Null;
    bool m_bool = false;
    double m_number = 0.0;
    std::wstring m_string;
    std::vector<JsonValue> m_array;
    std::vector<std::pair<std::wstring, JsonValue>> m_object;

    friend class JsonParser;
};

} // namespace GuardDog