#pragma once
// 使用 ntifs.h 替代 ntddk.h，它包含了更全的进程和内存管理结构（包含 KAPC_STATE）
#include <ntifs.h> 
//extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(IN PEPROCESS Process);
// ---------------------------------------------------------------------------
// 微软未完全文档化的结构体定义 (基于 Windows 10/11 64位)
// ---------------------------------------------------------------------------

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UCHAR           Reserved1[16];
	PVOID           Reserved2[10];
	UNICODE_STRING  ImagePathName;
	UNICODE_STRING  CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// 注意：ntifs.h 中可能已经定义了不完整的 PEB，我们需要补充我们需要的字段
typedef struct _MY_PEB {
	UCHAR           Reserved1[2];
	UCHAR           BeingDebugged;
	UCHAR           Reserved2[1];
	PVOID           Reserved3[2];
	PVOID           Ldr; // 简化处理，避免引入更多未定义结构
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} MY_PEB, *PMY_PEB;

// 如果编译时提示 PsGetProcessPeb 找不到，再取消下面这行的注释。
// 在大多数现代 WDK + ntifs.h 环境中，它已经被声明过了。
// extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(IN PEPROCESS Process);

// 回调函数声明
void ProcessNotifyCallbackEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);
