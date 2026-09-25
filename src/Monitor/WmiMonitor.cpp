#include "Monitor/WmiMonitor.h"

#include "Core/Logger.h"

#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace GuardDog {

namespace {

// 从 WMI 对象里读一个整数属性。
// 不直接取 variant 的某个联合体成员，是因为不同系统版本返回的 vt 不一样
// （VT_I4 / VT_UI4 / VT_BSTR 都实际出现过）。
bool ReadDword(IWbemClassObject* object, const wchar_t* name, DWORD& value) {
    VARIANT variant;
    VariantInit(&variant);

    bool ok = false;
    DWORD result = 0;

    if (SUCCEEDED(object->Get(name, 0, &variant, nullptr, nullptr))) {
        switch (variant.vt) {
            case VT_I1:   result = static_cast<DWORD>(variant.cVal);    ok = true; break;
            case VT_UI1:  result = static_cast<DWORD>(variant.bVal);    ok = true; break;
            case VT_I2:   result = static_cast<DWORD>(variant.iVal);    ok = true; break;
            case VT_UI2:  result = static_cast<DWORD>(variant.uiVal);   ok = true; break;
            case VT_I4:   result = static_cast<DWORD>(variant.lVal);    ok = true; break;
            case VT_UI4:  result = static_cast<DWORD>(variant.ulVal);   ok = true; break;
            case VT_INT:  result = static_cast<DWORD>(variant.intVal);  ok = true; break;
            case VT_UINT: result = static_cast<DWORD>(variant.uintVal); ok = true; break;
            case VT_I8:   result = static_cast<DWORD>(variant.llVal);   ok = true; break;
            case VT_UI8:  result = static_cast<DWORD>(variant.ullVal);  ok = true; break;
            case VT_BSTR:
                if (variant.bstrVal != nullptr) {
                    result = static_cast<DWORD>(wcstoul(variant.bstrVal, nullptr, 10));
                    ok = true;
                }
                break;
            default:
                break;
        }
    }

    VariantClear(&variant);
    if (ok) {
        value = result;
    }
    return ok;
}

bool ReadString(IWbemClassObject* object, const wchar_t* name, std::wstring& value) {
    VARIANT variant;
    VariantInit(&variant);

    bool ok = false;
    if (SUCCEEDED(object->Get(name, 0, &variant, nullptr, nullptr)) && variant.vt == VT_BSTR &&
        variant.bstrVal != nullptr) {
        value.assign(variant.bstrVal, SysStringLen(variant.bstrVal));
        ok = true;
    }

    VariantClear(&variant);
    return ok;
}

// 取事件对象的 TargetInstance（Win32_Process 实例）。
// 部分系统上 Win32_ProcessStartTrace 的 ProcessID 直接从事件对象读不到，
// 需要退回从 TargetInstance 里取 ProcessId。
ComPtr<IWbemClassObject> QueryTargetInstance(IWbemClassObject* eventObject) {
    ComPtr<IWbemClassObject> target;

    VARIANT variant;
    VariantInit(&variant);
    if (SUCCEEDED(eventObject->Get(L"TargetInstance", 0, &variant, nullptr, nullptr)) &&
        variant.vt == VT_UNKNOWN && variant.punkVal != nullptr) {
        variant.punkVal->QueryInterface(IID_IWbemClassObject,
                                        reinterpret_cast<void**>(target.Put()));
    }
    VariantClear(&variant);

    return target;
}

} // namespace

// IWbemObjectSink 实现：WMI 会从自己的线程池回调这里。
// 回调里只做"解析 + 投递"，绝不执行挂起/终止等耗时动作，否则会拖慢后续事件投递。
class ProcessStartSink final : public IWbemObjectSink {
public:
    explicit ProcessStartSink(WmiMonitor* owner) : m_owner(owner) {}

    // ---- IUnknown ----
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const LONG remaining = InterlockedDecrement(&m_refCount);
        if (remaining == 0) {
            delete this;
        }
        return static_cast<ULONG>(remaining);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (ppvObject == nullptr) {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppvObject = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    // ---- IWbemObjectSink ----
    HRESULT STDMETHODCALLTYPE Indicate(LONG objectCount, IWbemClassObject** objects) override {
        if (objects == nullptr) {
            return WBEM_E_INVALID_PARAMETER;
        }

        for (LONG i = 0; i < objectCount; ++i) {
            if (objects[i] != nullptr) {
                HandleEvent(objects[i]);
            }
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(LONG flags, HRESULT result, BSTR /*strParam*/,
                                        IWbemClassObject* /*objParam*/) override {
        // WBEM_STATUS_COMPLETE + 失败 = 订阅已经结束（例如 WMI 服务重启）。
        // 此时必须让上层知道，否则会以为"事件监控还在工作"而放松轮询。
        if ((flags & WBEM_STATUS_COMPLETE) != 0 && FAILED(result)) {
            m_owner->OnSubscriptionBroken(result);
        }
        return WBEM_S_NO_ERROR;
    }

private:
    void HandleEvent(IWbemClassObject* eventObject) {
        DWORD processId = 0;
        std::wstring processName;

        if (!ReadDword(eventObject, L"ProcessID", processId)) {
            const ComPtr<IWbemClassObject> target = QueryTargetInstance(eventObject);
            if (target.IsValid()) {
                ReadDword(target.Get(), L"ProcessId", processId);
                ReadString(target.Get(), L"Name", processName);
            }
        } else {
            ReadString(eventObject, L"ProcessName", processName);
        }

        if (processId == 0) {
            return;
        }

        m_owner->OnProcessStarted(processId, processName);
    }

    volatile LONG m_refCount = 1;
    WmiMonitor* m_owner = nullptr;
};

WmiMonitor::WmiMonitor() = default;

WmiMonitor::~WmiMonitor() {
    Stop();
}

void WmiMonitor::OnProcessStarted(DWORD processId, const std::wstring& processName) {
    GD_LOG_DEBUG(L"WMI 事件：进程创建 pid=%lu 名称=%s", processId,
                 processName.empty() ? L"(未知)" : processName.c_str());

    if (m_callback) {
        m_callback(processId, processName);
    }
}

void WmiMonitor::OnSubscriptionBroken(HRESULT result) {
    GD_LOG_WARN(L"WMI 订阅已中断（0x%08X）：期间仅靠轮询兜底，稍后将尝试重建订阅", result);
    m_running.store(false);
    m_needsReconnect.store(true);
}

HRESULT WmiMonitor::Start(const ProcessCallback& callback) {
    if (m_running.load()) {
        return S_OK;
    }

    m_callback = callback;

    // 必须按 MTA 初始化：异步订阅的回调由 RPC 线程池投递，
    // 若用 STA 就需要消息泵，而服务进程没有消息循环。
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (comResult == S_OK || comResult == S_FALSE) {
        m_comInitialized = true;
    } else if (comResult == RPC_E_CHANGED_MODE) {
        // 当前线程已按其他套间模式初始化过 COM；订阅仍然可用，继续尝试
        GD_LOG_WARN(L"当前线程的 COM 套间模式与 MTA 不一致，WMI 订阅可能受限");
    } else {
        GD_LOG_ERROR(L"CoInitializeEx 失败：0x%08X", comResult);
        return comResult;
    }

    // 进程级安全设置，必须在首次 COM 调用之前生效。
    // 返回 RPC_E_TOO_LATE 说明别处已经设置过，属于正常情况。
    const HRESULT securityResult =
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(securityResult) && securityResult != RPC_E_TOO_LATE) {
        GD_LOG_WARN(L"CoInitializeSecurity 返回 0x%08X，可能影响 WMI 访问权限", securityResult);
    }

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                                  reinterpret_cast<void**>(m_locator.Put()));
    if (FAILED(hr)) {
        GD_LOG_ERROR(L"创建 IWbemLocator 失败：0x%08X", hr);
        Stop();
        return hr;
    }

    BSTR nameSpace = SysAllocString(L"ROOT\\CIMV2");
    hr = m_locator->ConnectServer(nameSpace, nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                                  reinterpret_cast<IWbemServices**>(m_service.Put()));
    SysFreeString(nameSpace);
    if (FAILED(hr)) {
        GD_LOG_ERROR(L"连接 WMI 命名空间 ROOT\\CIMV2 失败：0x%08X", hr);
        Stop();
        return hr;
    }

    // 不设置代理安全级别的话，后续异步回调会因权限不足而收不到事件
    hr = CoSetProxyBlanket(m_service.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        GD_LOG_WARN(L"CoSetProxyBlanket 返回 0x%08X", hr);
    }

    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM Win32_ProcessStartTrace");

    ProcessStartSink* sink = new ProcessStartSink(this);
    hr = m_service->ExecNotificationQueryAsync(language, query, WBEM_FLAG_SEND_STATUS, nullptr, sink);

    SysFreeString(language);
    SysFreeString(query);

    if (FAILED(hr)) {
        // 订阅未生效，COM 不会持有引用，释放我们自己这一份
        sink->Release();
        GD_LOG_ERROR(L"订阅 Win32_ProcessStartTrace 失败：0x%08X", hr);
        Stop();
        return hr;
    }

    m_sink.Attach(sink);
    m_running.store(true);
    m_needsReconnect.store(false);
    GD_LOG_INFO(L"WMI 订阅已建立：Win32_ProcessStartTrace（进程创建即时通知，作为主监控手段）");
    return S_OK;
}

void WmiMonitor::Stop() {
    if (m_service.IsValid() && m_sink.IsValid()) {
        const HRESULT hr = m_service->CancelAsyncCall(m_sink.Get());
        if (FAILED(hr) && hr != WBEM_E_INVALID_OPERATION) {
            GD_LOG_WARN(L"取消 WMI 订阅失败：0x%08X", hr);
        }
    }

    m_sink.Reset();
    m_service.Reset();
    m_locator.Reset();
    m_callback = nullptr;
    m_running.store(false);

    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }
}

} // namespace GuardDog