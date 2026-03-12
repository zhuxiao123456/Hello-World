// ===========================================================================
// 环境适配：自动区分是编译驱动还是编译 EXE
// ===========================================================================
#ifdef _KERNEL_MODE
	// 内核态编译环境 (PebMonitor.sys)
#include <ntifs.h> 
#else
	// 用户态编译环境 (detect.exe)
#include <windows.h>
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
} PROCESS_EVENT, *PPROCESS_EVENT;

// 裁决结构体：用户态 -> 驱动
typedef struct _PROCESS_VERDICT {
	ULONG ProcessId;
	BOOLEAN BlockProcess;    // TRUE 为拦截，FALSE 为放行
} PROCESS_VERDICT, *PPROCESS_VERDICT;
