#include <VMProtectSDK.h>

#if defined(VMP_WIN) || defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wchar.h>
#endif

#if defined(__APPLE__)
#include <mach/mach_time.h>
#include <mach-o/dyld.h>
#endif

#if defined(__unix__) || defined(__linux__)
#include <sys/time.h>
#include <unistd.h>
#endif

#if defined(__linux__)
#include <linux/limits.h>
#endif

#include <cctype>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <array>
#include <cstdlib>
#include <ctime>
#include <algorithm>

#ifndef _countof
#define _countof(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef VMP_GNU
#define strcmpi strcasecmp
#define INI_MAX_LINE 1024
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#elif defined(WIN_DRIVER)

void DriverUnload(PDRIVER_OBJECT driver_object)
{
    driver_object;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    pRegistryPath;
    pDriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

#elif defined(VMP_WIN) || defined(_WIN32)

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    hModule;
    dwReason;
    lpReserved;
    return TRUE;
}
#endif

bool VMP_API VMProtectIsProtected()
{
    return false;
}

void VMP_API VMProtectBegin(const char*)
{
}

void VMP_API VMProtectBeginMutation(const char*)
{
}

void VMP_API VMProtectBeginVirtualization(const char*)
{
}

void VMP_API VMProtectBeginUltra(const char*)
{
}

void VMP_API VMProtectBeginVirtualizationLockByKey(const char*)
{
}

void VMP_API VMProtectBeginUltraLockByKey(const char*)
{
}

void VMP_API VMProtectEnd()
{
}

bool VMP_API VMProtectIsDebuggerPresent(bool)
{
#ifdef VMP_GNU
    return false;
#elif defined(WIN_DRIVER)
    return false;
#else
    return ::IsDebuggerPresent() != FALSE;
#endif
}

bool VMP_API VMProtectIsVirtualMachinePresent()
{
    return false;
}

bool VMP_API VMProtectIsValidImageCRC()
{
    return true;
}

const char* VMP_API VMProtectDecryptStringA(const char* value)
{
    return value;
}

const VMP_WCHAR* VMP_API VMProtectDecryptStringW(const VMP_WCHAR* value)
{
    return value;
}

bool VMP_API VMProtectFreeString(void*)
{
    return true;
}

int VMP_API VMProtectGetOfflineActivationString(const char*, char*, int)
{
    return ACTIVATION_OK;
}

int VMP_API VMProtectGetOfflineDeactivationString(const char*, char*, int)
{
    return ACTIVATION_OK;
}

namespace
{
#if defined(__APPLE__)
    unsigned long GetTickCount()
    {
        constexpr int64_t one_million = 1000 * 1000;
        mach_timebase_info_data_t timebase_info;
        mach_timebase_info(&timebase_info);

        // mach_absolute_time() returns platform ticks.
        // Convert to milliseconds.
        return static_cast<uint32_t>((mach_absolute_time() * timebase_info.numer) /
                                     (one_million * timebase_info.denom));
    }
#endif

#if defined(__unix__) || defined(__linux__)
    unsigned long GetTickCount()
    {
        timeval tv{};
        gettimeofday(&tv, nullptr);
        return static_cast<unsigned long>(tv.tv_sec * 1000UL + tv.tv_usec / 1000UL);
    }
#endif

#ifndef WIN_DRIVER
    bool g_serial_is_correct = false;
    bool g_serial_is_blacklisted = false;
    uint32_t g_time_of_start = static_cast<uint32_t>(GetTickCount());
#endif

#ifdef VMP_GNU

    size_t strnlen_local(const char* text, const size_t max_len)
    {
        const auto last = static_cast<const char*>(std::memchr(text, '\0', max_len));
        return last ? static_cast<size_t>(last - text) : max_len;
    }

    /* Strip whitespace chars off end of given string, in place. Return s. */
    char* rstrip(char* s)
    {
        char* p = s + std::strlen(s);
        while (p > s && std::isspace(static_cast<unsigned char>(*--p)))
            *p = '\0';
        return s;
    }

    /* Return pointer to first non-whitespace char in given string. */
    char* lskip(const char* s)
    {
        while (*s && std::isspace(static_cast<unsigned char>(*s)))
            s++;
        return const_cast<char*>(s);
    }

    /* Return pointer to first char c or ';' comment in given string, or pointer to
       null at end of string if neither found. ';' must be prefixed by a whitespace
       character to register as a comment. */
    char* find_char_or_comment(const char* s, char c)
    {
        int was_whitespace = 0;
        while (*s && *s != c && !(was_whitespace && *s == ';'))
        {
            was_whitespace = std::isspace(static_cast<unsigned char>(*s));
            s++;
        }
        return const_cast<char*>(s);
    }

    /* See documentation in header file. */
    int GetPrivateProfileString(const char* section_name, const char* key_name, char* buffer, size_t size,
                                const char* file_name)
    {
        if (!buffer || !size)
            return 0;

        FILE* file = std::fopen(file_name, "r");
        if (!file)
            return 0;

        char line[INI_MAX_LINE];
        char* end;
        int lineno = 0;
        int res = 0;
        bool section_found = false;

        /* Scan through file line by line */
        while (std::fgets(line, INI_MAX_LINE, file) != nullptr)
        {
            lineno++;

            char* start = line;
            if (lineno == 1 && static_cast<unsigned char>(start[0]) == 0xEF &&
                static_cast<unsigned char>(start[1]) == 0xBB &&
                static_cast<unsigned char>(start[2]) == 0xBF)
            {
                start += 3;
            }
            start = lskip(rstrip(start));

            if (*start == ';' || *start == '#')
            {
                /* Per Python ConfigParser, allow '#' comments at start of line */
            }
            else if (*start == '[')
            {
                /* A "[section]" line */
                end = find_char_or_comment(start + 1, ']');
                if (*end == ']')
                {
                    *end = '\0';
                    if (section_found)
                        break;

                    section_found = (strcmpi(start + 1, section_name) == 0);
                }
            }
            else if (section_found && *start && *start != ';')
            {
                /* Not a comment, must be a name[=:]value pair */
                end = find_char_or_comment(start, '=');
                if (*end != '=')
                {
                    end = find_char_or_comment(start, ':');
                }
                if (*end == '=' || *end == ':')
                {
                    *end = '\0';
                    char* name = rstrip(start);
                    char* value = lskip(end + 1);
                    end = find_char_or_comment(value, '\0');
                    if (*end == ';')
                        *end = '\0';
                    rstrip(value);

                    if (strcmpi(name, key_name) == 0)
                    {
                        std::strncpy(buffer, value, size);
                        if (size > 0)
                            buffer[size - 1] = '\0';
                        res = static_cast<int>(strnlen_local(buffer, size));
                        break;
                    }
                }
            }
        }

        std::fclose(file);
        return res;
    }

    bool GetIniValue(const char* value_name, char* buffer, size_t size)
    {
        char file_name[PATH_MAX];
        file_name[0] = '\0';

#if defined(__APPLE__)
        uint32_t name_size = static_cast<uint32_t>(sizeof(file_name));
        if (_NSGetExecutablePath(file_name, &name_size) != 0)
        {
            if (buffer && size)
                buffer[0] = '\0';
            return false;
        }
#else
        const auto cap = static_cast<size_t>(sizeof(file_name));
        const ssize_t sz = readlink("/proc/self/exe", file_name, cap - 1);
        if (sz > 0)
            file_name[static_cast<size_t>(sz)] = '\0';
#endif

        char* p = std::strrchr(file_name, '/');
        if (p)
            *(p + 1) = '\0';

        const size_t len = std::strlen(file_name);
        if (len < sizeof(file_name) - 1)
            std::strncat(file_name, "VMProtectLicense.ini", sizeof(file_name) - len - 1);

        return GetPrivateProfileString("TestLicense", value_name, buffer, size, file_name) != 0;
    }

    void ConvertUTF8ToUnicode(const uint8_t* src, size_t len, VMP_WCHAR* dest, size_t dest_size)
    {
        if (!dest || dest_size == 0)
            return; // nothing to do

        size_t pos = 0;
        size_t dest_pos = 0;

        while (pos < len && dest_pos < dest_size)
        {
            constexpr std::array<uint8_t, 5> utf8_limits = {0xC0, 0xE0, 0xF0, 0xF8, 0xFC};
            uint8_t b = src[pos++];

            if (b < 0x80)
            {
                dest[dest_pos++] = b;
                continue;
            }

            size_t val_len = 0;
            for (; val_len < utf8_limits.size(); ++val_len)
            {
                if (b < utf8_limits[val_len])
                    break;
            }

            // Invalid lead byte or unsupported length (>4 bytes)
            if (val_len == 0 || val_len > 4)
                continue;

            uint32_t value = b - utf8_limits[val_len - 1];
            bool ok = true;

            for (size_t i = 0; i < val_len; i++)
            {
                if (pos == len)
                {
                    ok = false;
                    break;
                }
                b = src[pos++];
                if (b < 0x80 || b >= 0xC0)
                {
                    ok = false;
                    break;
                }
                value <<= 6;
                value |= (b - 0x80);
            }

            if (!ok)
                continue;

            if (value < 0x10000)
            {
                if (dest_pos < dest_size)
                    dest[dest_pos++] = static_cast<uint16_t>(value);
            }
            else if (value <= 0x10FFFF)
            {
                // Need 2 UTF-16 code units (surrogate pair)
                if (dest_pos + 1 < dest_size)
                {
                    value -= 0x10000;
                    dest[dest_pos++] = static_cast<uint16_t>(0xD800 + (value >> 10));
                    dest[dest_pos++] = static_cast<uint16_t>(0xDC00 + (value & 0x3FF));
                }
            }
        }

        if (dest_pos == 0)
        {
            dest[0] = 0;
        }
        else if (dest_pos < dest_size)
        {
            dest[dest_pos] = 0;
        }
        else
        {
            dest[dest_size - 1] = 0;
        }
    }

    bool GetIniValue(const char* value_name, VMP_WCHAR* buffer, size_t size)
    {
        char value[INI_MAX_LINE];
        if (GetIniValue(value_name, value, sizeof(value)))
        {
            ConvertUTF8ToUnicode(reinterpret_cast<const uint8_t*>(value), std::strlen(value), buffer, size);
            return true;
        }
        if (buffer && size)
            buffer[0] = 0;
        return false;
    }

#elif defined(WIN_DRIVER)

// No INI loading in driver mode.

#else

    bool GetIniValue(const char* value_name, wchar_t* buffer, size_t size)
    {
        if (!buffer || size == 0)
            return false;

        wchar_t file_name[MAX_PATH] = {0};
        if (::GetModuleFileNameW(nullptr, file_name, static_cast<DWORD>(_countof(file_name))) == 0)
            return false;

        wchar_t* p = std::wcsrchr(file_name, L'\\');
        if (p)
            *(p + 1) = L'\0';

        wcscat_s(file_name, _countof(file_name), L"VMProtectLicense.ini");

        wchar_t key_name[1024] = {0};
        ::MultiByteToWideChar(CP_ACP, 0, value_name, -1, key_name, static_cast<int>(_countof(key_name)));

        return ::GetPrivateProfileStringW(L"TestLicense", key_name, L"", buffer, static_cast<DWORD>(size), file_name)
               != 0;
    }

    bool GetIniValue(const char* value_name, char* buffer, size_t size)
    {
        if (!buffer || size == 0)
            return false;

        wchar_t value[2048] = {0};
        if (GetIniValue(value_name, value, _countof(value)))
        {
            ::WideCharToMultiByte(CP_ACP, 0, value, -1, buffer, static_cast<int>(size), nullptr, nullptr);
            return true;
        }

        buffer[0] = 0;
        return false;
    }

#endif
} // namespace

#define MAKEDATE(y, m, d) (DWORD)((y << 16) + (m << 8) + d)

int VMP_API VMProtectGetSerialNumberState()
{
#ifdef WIN_DRIVER
    return SERIAL_STATE_FLAG_INVALID;
#else
    if (!g_serial_is_correct)
        return SERIAL_STATE_FLAG_INVALID;
    if (g_serial_is_blacklisted)
        return SERIAL_STATE_FLAG_BLACKLISTED;

    int res = 0;

    char buf[256];
    if (GetIniValue("TimeLimit", buf, std::size(buf)))
    {
        int running_time = std::atoi(buf);
        if (running_time >= 0 && running_time <= 255)
        {
            uint32_t dw = static_cast<uint32_t>(GetTickCount());
            int d = static_cast<int>((dw - g_time_of_start) / 1000 / 60); // minutes
            if (running_time <= d)
                res |= SERIAL_STATE_FLAG_RUNNING_TIME_OVER;
        }
    }

    if (GetIniValue("ExpDate", buf, sizeof(buf)))
    {
        int y, m, d;
        if (std::sscanf(buf, "%04d%02d%02d", &y, &m, &d) == 3)
        {
            uint32_t ini_date =
                (static_cast<uint32_t>(y) << 16) + (static_cast<uint8_t>(m) << 8) + static_cast<uint8_t>(d);
            uint32_t cur_date;
#ifdef VMP_GNU
            std::time_t rawtime;
            std::time(&rawtime);
            std::tm local_tm{};
#if defined(_POSIX_VERSION)
            std::tm* timeinfo = localtime_r(&rawtime, &local_tm);
#else
            std::tm* timeinfo = std::localtime(&rawtime);
#endif
            cur_date = (static_cast<uint32_t>(timeinfo->tm_year + 1900) << 16) +
                       (static_cast<uint8_t>(timeinfo->tm_mon + 1) << 8) + static_cast<uint8_t>(timeinfo->tm_mday);
#else
            SYSTEMTIME st{};
            ::GetLocalTime(&st);
            cur_date = (static_cast<uint32_t>(st.wYear) << 16) + (static_cast<uint8_t>(st.wMonth) << 8) +
                       static_cast<uint8_t>(st.wDay);
#endif
            if (cur_date > ini_date)
                res |= SERIAL_STATE_FLAG_DATE_EXPIRED;
        }
    }

    if (GetIniValue("MaxBuildDate", buf, sizeof(buf)))
    {
        int y, m, d;
        if (std::sscanf(buf, "%04d%02d%02d", &y, &m, &d) == 3)
        {
            uint32_t ini_date =
                (static_cast<uint32_t>(y) << 16) + (static_cast<uint8_t>(m) << 8) + static_cast<uint8_t>(d);
            uint32_t cur_date;
#ifdef VMP_GNU
            std::time_t rawtime;
            std::time(&rawtime);
            std::tm local_tm{};
#if defined(_POSIX_VERSION)
            std::tm* timeinfo = localtime_r(&rawtime, &local_tm);
#else
            std::tm* timeinfo = std::localtime(&rawtime);
#endif
            cur_date = (static_cast<uint32_t>(timeinfo->tm_year + 1900) << 16) +
                       (static_cast<uint8_t>(timeinfo->tm_mon + 1) << 8) + static_cast<uint8_t>(timeinfo->tm_mday);
#else
            SYSTEMTIME st{};
            ::GetLocalTime(&st);
            cur_date = (static_cast<uint32_t>(st.wYear) << 16) + (static_cast<uint8_t>(st.wMonth) << 8) +
                       static_cast<uint8_t>(st.wDay);
#endif
            if (cur_date > ini_date)
                res |= SERIAL_STATE_FLAG_MAX_BUILD_EXPIRED;
        }
    }

    if (GetIniValue("KeyHWID", buf, sizeof(buf)))
    {
        char buf2[256];
        GetIniValue("MyHWID", buf2, sizeof(buf2));
        if (std::strcmp(buf, buf2) != 0)
            res |= SERIAL_STATE_FLAG_BAD_HWID;
    }

    return res;
#endif
}

int VMP_API VMProtectSetSerialNumber(const char* serial)
{
#ifdef WIN_DRIVER
    serial;
    return SERIAL_STATE_FLAG_INVALID;
#else
    g_serial_is_correct = false;
    g_serial_is_blacklisted = false;
    if (!serial || !serial[0])
        return SERIAL_STATE_FLAG_INVALID;

    char buf_serial[2048];
    const char* src = serial;
    char* dst = buf_serial;
    while (*src)
    {
        char c = *src;
        // check against base64 alphabet
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' ||
            c == '=')
            *dst++ = c;
        src++;
    }
    *dst = 0;

    char ini_serial[2048];
    if (!GetIniValue("AcceptedSerialNumber", ini_serial, sizeof(ini_serial)))
        std::strcpy(ini_serial, "serialnumber");
    g_serial_is_correct = std::strcmp(buf_serial, ini_serial) == 0;

    if (GetIniValue("BlackListedSerialNumber", ini_serial, sizeof(ini_serial)))
        g_serial_is_blacklisted = std::strcmp(buf_serial, ini_serial) == 0;

    return VMProtectGetSerialNumberState();
#endif
}

bool VMP_API VMProtectGetSerialNumberData(VMProtectSerialNumberData* data, int size)
{
#ifdef WIN_DRIVER
    data;
    size;
    return false;
#else
    if (!data || size != static_cast<int>(sizeof(VMProtectSerialNumberData)))
        return false;
    std::memset(data, 0, sizeof(VMProtectSerialNumberData));

    data->nState = VMProtectGetSerialNumberState();
    if (data->nState & (SERIAL_STATE_FLAG_INVALID | SERIAL_STATE_FLAG_BLACKLISTED))
        return true; // do not need to read the rest

    GetIniValue("UserName", data->wUserName, _countof(data->wUserName));
    GetIniValue("EMail", data->wEMail, _countof(data->wEMail));

    char buf[2048];
    if (GetIniValue("TimeLimit", buf, sizeof(buf)))
    {
        int running_time = std::atoi(buf);
        if (running_time < 0)
            running_time = 0;
        else if (running_time > 255)
            running_time = 255;
        data->bRunningTime = static_cast<unsigned char>(running_time);
    }

    if (GetIniValue("ExpDate", buf, sizeof(buf)))
    {
        int y, m, d;
        if (std::sscanf(buf, "%04d%02d%02d", &y, &m, &d) == 3)
        {
            data->dtExpire.wYear = static_cast<unsigned short>(y);
            data->dtExpire.bMonth = static_cast<unsigned char>(m);
            data->dtExpire.bDay = static_cast<unsigned char>(d);
        }
    }

    if (GetIniValue("MaxBuildDate", buf, sizeof(buf)))
    {
        int y, m, d;
        if (std::sscanf(buf, "%04d%02d%02d", &y, &m, &d) == 3)
        {
            data->dtMaxBuild.wYear = static_cast<unsigned short>(y);
            data->dtMaxBuild.bMonth = static_cast<unsigned char>(m);
            data->dtMaxBuild.bDay = static_cast<unsigned char>(d);
        }
    }

    if (GetIniValue("UserData", buf, sizeof(buf)))
    {
        const size_t len = std::strlen(buf);
        if (len > 0 && len % 2 == 0 && len <= 255 * 2) // otherwise UserData is empty or has bad length
        {
            for (size_t src = 0, dst = 0; src < len; src++)
            {
                int v = 0;
                const char c = buf[src];

                if (c >= '0' && c <= '9')
                    v = c - '0';
                else if (c >= 'a' && c <= 'f')
                    v = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F')
                    v = c - 'A' + 10;
                else
                {
                    data->nUserDataLength = 0;
                    std::memset(data->bUserData, 0, sizeof(data->bUserData));
                    break;
                }

                if (src % 2 == 0)
                {
                    data->bUserData[dst] = static_cast<unsigned char>(v << 4);
                }
                else
                {
                    data->bUserData[dst] |= static_cast<unsigned char>(v);
                    dst++;
                    data->nUserDataLength = static_cast<unsigned char>(dst);
                }
            }
        }
    }

    return true;
#endif
}

int VMP_API VMProtectGetCurrentHWID(char* hwid, int size)
{
#ifdef WIN_DRIVER
    hwid;
    size;
    return 0;
#else
    if (hwid && size <= 0)
        return 0;

    char buf[1024];
    if (!GetIniValue("MyHWID", buf, sizeof(buf)))
        std::strcpy(buf, "myhwid");

    int res = static_cast<int>(std::strlen(buf));
    if (hwid && size > 0)
    {
        if (size - 1 < res)
            res = size - 1;
        std::memcpy(hwid, buf, static_cast<size_t>(res));
        hwid[res] = 0;
    }
    return res + 1;
#endif
}

int VMP_API VMProtectActivateLicense(const char* code, char* serial, int size)
{
#ifdef WIN_DRIVER
    code;
    serial;
    size;
    return ACTIVATION_NOT_AVAILABLE;
#else
    if (!code)
        return ACTIVATION_BAD_CODE;
    if (!serial || size <= 0)
        return ACTIVATION_SMALL_BUFFER;

    char buf[2048];
    if (!GetIniValue("AcceptedActivationCode", buf, sizeof(buf)))
        std::strcpy(buf, "activationcode");
    if (std::strcmp(code, buf) != 0)
        return ACTIVATION_BAD_CODE;

    if (!GetIniValue("AcceptedSerialNumber", buf, sizeof(buf)))
        std::strcpy(buf, "serialnumber");

    int need = static_cast<int>(std::strlen(buf));
    if (need > size - 1)
        return ACTIVATION_SMALL_BUFFER;

    std::strcpy(serial, buf);
    return ACTIVATION_OK;
#endif
}

int VMP_API VMProtectDeactivateLicense(const char*)
{
#ifdef WIN_DRIVER
    return ACTIVATION_NOT_AVAILABLE;
#else
    return ACTIVATION_OK;
#endif
}