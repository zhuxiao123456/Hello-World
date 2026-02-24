#pragma once

// 包含 Windows IOCTL 宏定义 (如果是驱动项目可能需要替换为 <ntddk.h> 或 <ntifs.h>)
#ifndef CTL_CODE
#include <winioctl.h>
#endif

// ===========================================================================
// 定义控制码 (IOCTL Codes)
// ===========================================================================
#define IOCTL_GET_PROCESS_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_VERDICT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ===========================================================================
// 通信数据结构
// ===========================================================================

// 事件结构体：驱动 -> 用户态
typedef struct _PROCESS_EVENT {
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR CommandLine[1024]; // 提取到的真实启动命令行
} PROCESS_EVENT, * PPROCESS_EVENT;

// 裁决结构体：用户态 -> 驱动
typedef struct _PROCESS_VERDICT {
    ULONG ProcessId;
    BOOLEAN BlockProcess;    // TRUE 为拦截，FALSE 为放行
} PROCESS_VERDICT, * PPROCESS_VERDICT;
