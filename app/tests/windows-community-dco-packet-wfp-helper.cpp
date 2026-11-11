// QA-only Microsoft WFP packet-layer IPv4 filter on a disposable hosted Windows VM.
// Never ship this test helper. A dynamic session is fail-open if its owner exits:
// it proves only packet-layer filter feasibility, NOT a persistent kill switch.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <string>
#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")

static bool Env(const wchar_t* key, const wchar_t* value) {
    wchar_t buffer[160] = {};
    DWORD n = GetEnvironmentVariableW(key, buffer, 160);
    return n > 0 && n < 160 && wcscmp(buffer, value) == 0;
}
static bool Hosted() {
    return Env(L"GITHUB_ACTIONS", L"true") &&
           Env(L"RUNNER_OS", L"Windows") &&
           Env(L"RUNNER_ENVIRONMENT", L"github-hosted") &&
           Env(L"GITHUB_REPOSITORY", L"GOD13emad/OpenInternetGateway") &&
           Env(L"GITHUB_HEAD_REF", L"qa/v2.5.20-operator-safety-20261019") &&
           Env(L"OIG_HOSTED_DCO_PACKET_QA", L"1");
}
static bool UInt(const wchar_t* text, unsigned long& value) {
    if (!text || !*text || *text == L'-') return false;
    wchar_t* end = nullptr;
    value = wcstoul(text, &end, 10);
    return end != text && end && *end == 0 && value > 0;
}
static bool IP(const wchar_t* text, UINT32& hostOrder) {
    in_addr addr = {};
    if (InetPtonW(AF_INET, text, &addr) != 1) return false;
    hostOrder = ntohl(addr.S_un.S_addr); // FWP_UINT32 IPv4 uses HOST order.
    return hostOrder != 0 && hostOrder != 0xffffffff;
}
static DWORD OpenEngine(HANDLE* h, bool dynamic) {
    FWPM_SESSION0 s = {};
    s.displayData.name = const_cast<wchar_t*>(L"OIG isolated DCO QA session");
    s.flags = dynamic ? FWPM_SESSION_FLAG_DYNAMIC : 0;
    return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &s, h);
}
static bool Matches(FWPM_FILTER0* f, unsigned long index, UINT32 destination) {
    if (!f || !IsEqualGUID(f->layerKey, FWPM_LAYER_OUTBOUND_IPPACKET_V4) ||
        f->action.type != FWP_ACTION_BLOCK || f->numFilterConditions != 2)
        return false;
    bool seenIface = false, seenDestination = false;
    for (UINT32 i = 0; i < f->numFilterConditions; ++i) {
        const auto& c = f->filterCondition[i];
        if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_INTERFACE_INDEX) &&
            c.matchType == FWP_MATCH_EQUAL &&
            c.conditionValue.type == FWP_UINT32 &&
            c.conditionValue.uint32 == static_cast<UINT32>(index))
            seenIface = true;
        else if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS) &&
                 c.matchType == FWP_MATCH_EQUAL &&
                 c.conditionValue.type == FWP_UINT32 &&
                 c.conditionValue.uint32 == destination)
            seenDestination = true;
        else return false;
    }
    return seenIface && seenDestination;
}
int wmain(int argc, wchar_t** argv) {
    if (!Hosted()) return 30;
    const bool arm = argc == 4 && wcscmp(argv[1], L"arm") == 0;
    const bool inspect = argc == 5 && wcscmp(argv[1], L"inspect") == 0;
    if (!arm && !inspect) return 31;
    unsigned long ifindex = 0;
    UINT32 destination = 0;
    if (arm) {
        if (!UInt(argv[2], ifindex) || !IP(argv[3], destination)) return 32;
    } else {
        // inspect <filter_id> <ifindex> <destination>
        if (!UInt(argv[3], ifindex) || !IP(argv[4], destination)) return 33;
    }
    HANDLE engine = nullptr;
    DWORD rc = OpenEngine(&engine, arm);
    if (rc != ERROR_SUCCESS) return 34;

    if (inspect) {
        wchar_t* end = nullptr;
        UINT64 id = _wcstoui64(argv[2], &end, 10);
        if (end == argv[2] || !end || *end || id == 0) {
            FwpmEngineClose0(engine);
            return 35;
        }
        FWPM_FILTER0* found = nullptr;
        rc = FwpmFilterGetById0(engine, id, &found);
        bool valid = rc == ERROR_SUCCESS && Matches(found, ifindex, destination);
        if (found) FwpmFreeMemory0(reinterpret_cast<void**>(&found));
        FwpmEngineClose0(engine);
        if (!valid) return 36;
        std::cout << "MATCH" << std::endl;
        return 0;
    }

    // Strictly session-scoped: automatically removed on process termination
    // even on exceptions/crash. This is intentionally NOT persistent policy.
    FWPM_SUBLAYER0 sub = {};
    RPC_STATUS uuidStatus = UuidCreate(&sub.subLayerKey);
    if (uuidStatus != RPC_S_OK && uuidStatus != RPC_S_UUID_LOCAL_ONLY) {
        FwpmEngineClose0(engine); return 37;
    }
    sub.displayData.name = const_cast<wchar_t*>(L"OIG QA temporary per-interface WFP sublayer");
    sub.weight = 0x5500;
    rc = FwpmSubLayerAdd0(engine, &sub, nullptr);
    if (rc != ERROR_SUCCESS) { FwpmEngineClose0(engine); return 38; }

    FWPM_FILTER_CONDITION0 conditions[2] = {};
    conditions[0].fieldKey = FWPM_CONDITION_INTERFACE_INDEX;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_UINT32;
    conditions[0].conditionValue.uint32 = static_cast<UINT32>(ifindex);
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT32;
    conditions[1].conditionValue.uint32 = destination;

    FWPM_FILTER0 filter = {};
    filter.displayData.name = const_cast<wchar_t*>(L"OIG disposable one-destination packet-layer block");
    filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
    filter.subLayerKey = sub.subLayerKey;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 2;
    filter.filterCondition = conditions;
    filter.weight.type = FWP_EMPTY;
    UINT64 id = 0;
    rc = FwpmFilterAdd0(engine, &filter, nullptr, &id);
    if (rc != ERROR_SUCCESS) { FwpmEngineClose0(engine); return 39; }
    // READY only after exact installed-filter contract succeeds.
    FWPM_FILTER0* installed = nullptr;
    rc = FwpmFilterGetById0(engine, id, &installed);
    bool valid = rc == ERROR_SUCCESS && Matches(installed, ifindex, destination);
    if (installed) FwpmFreeMemory0(reinterpret_cast<void**>(&installed));
    if (!valid) { FwpmEngineClose0(engine); return 40; }
    std::cout << "READY:" << id << std::endl;
    std::string line;
    std::getline(std::cin, line);
    // Never interpret any input as a command to add or broaden a filter.
    if (line != "STOP") { FwpmEngineClose0(engine); return 41; }
    DWORD delFilter = FwpmFilterDeleteById0(engine, id);
    DWORD delSub = FwpmSubLayerDeleteByKey0(engine, &sub.subLayerKey);
    DWORD close = FwpmEngineClose0(engine);
    if (delFilter != ERROR_SUCCESS || delSub != ERROR_SUCCESS ||
        close != ERROR_SUCCESS) return 42;
    std::cout << "REMOVED" << std::endl;
    return 0;
}
