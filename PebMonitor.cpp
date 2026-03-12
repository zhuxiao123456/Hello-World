#include "PebMonitor.h"
#include <ntifs.h>
#include "Shared.h" // 确保你已经创建了这个头文件，里面定义了 IOCTL 控制码和结构体
#include <ntstrsafe.h> // [新增] 用于内核安全的字符串格式化
#include <stdarg.h>    // [新增] 用于可变参数处理

// ===========================================================================
// 全局变量与核心数据结构
// ===========================================================================

PDEVICE_OBJECT g_DeviceObject = NULL;
typedef PVOID(*FN_PsGetProcessPeb)(IN PEPROCESS Process);

// 待处理进程事件的链表节点
typedef struct _PROCESS_EVENT_NODE {
	LIST_ENTRY ListEntry;           // 链表节点
	PROCESS_EVENT EventData;        // 发送给用户态的数据 (PID, PPID, CmdLine)
	KEVENT WaitEvent;               // 用于阻塞当前线程，等待用户态判决
	BOOLEAN IsSentToUser;           // 标记是否已经发送给 detect.exe
	BOOLEAN BlockVerdict;           // 用户态返回的最终判决结果 (TRUE为拦截)
} PROCESS_EVENT_NODE, *PPROCESS_EVENT_NODE;

// 全局事件队列与同步锁
LIST_ENTRY g_EventQueue;
KSPIN_LOCK g_QueueLock;

// 挂起的 IRP (detect.exe 发来等待拿数据的请求)
PIRP g_PendingEventIrp = NULL;

// 【新增 1】定义队列深度限制和当前事件计数器
#define MAX_EVENT_COUNT 1000
ULONG g_EventCount = 0;


// ===========================================================================
// 前置声明
// ===========================================================================
VOID CancelPendingEventIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ===========================================================================
// [新增] 内核态写日志辅助函数
// ===========================================================================
void WriteLogToFile(const char* format, ...) {
	// 1. 确保当前处于 PASSIVE_LEVEL，否则写文件会蓝屏
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return;
	}

	// 2. 格式化日志字符串
	char logBuffer[512];
	va_list args;
	va_start(args, format);
	NTSTATUS status = RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), format, args);
	va_end(args);

	if (!NT_SUCCESS(status)) {
		return; // 格式化失败则放弃
	}

	// 3. 设置内核文件路径 (注意：C:\log 文件夹必须已存在！)
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, L"\\DosDevices\\C:\\log\\pebmonitor.log");

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE hFile;
	IO_STATUS_BLOCK ioStatusBlock;

	// 4. 打开或创建文件 (FILE_APPEND_DATA 确保追加写入，不覆盖老日志)
	status = ZwCreateFile(&hFile,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF, // 文件存在则打开，不存在则创建
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (NT_SUCCESS(status)) {
		// 5. 写入文件
		size_t len = 0;
		RtlStringCbLengthA(logBuffer, sizeof(logBuffer), &len);

		ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, logBuffer, (ULONG)len, NULL, NULL);
		ZwClose(hFile);
	}
}

// ===========================================================================
// IRP 派遣函数：处理 detect.exe 的请求
// ===========================================================================

// 处理 CreateFile 和 CloseHandle
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 处理 DeviceIoControl 通信
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
	ULONG outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	switch (ioControlCode) {
	case IOCTL_GET_PROCESS_EVENT: {
		// detect.exe 想要获取一个新进程事件
		if (outBufLength < sizeof(PROCESS_EVENT)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_QueueLock, &oldIrql);

		// 1. 遍历队列，看看有没有还没发给用户态的新事件
		PLIST_ENTRY entry = g_EventQueue.Flink;
		PPROCESS_EVENT_NODE pendingNode = NULL;
		while (entry != &g_EventQueue) {
			PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
			if (!node->IsSentToUser) {
				pendingNode = node;
				break;
			}
			entry = entry->Flink;
		}

		if (pendingNode) {
			// 2A. 发现有新事件！立刻拷贝给 detect.exe
			pendingNode->IsSentToUser = TRUE;
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &pendingNode->EventData, sizeof(PROCESS_EVENT));
			KeReleaseSpinLock(&g_QueueLock, oldIrql);

			Irp->IoStatus.Information = sizeof(PROCESS_EVENT);
			status = STATUS_SUCCESS;
		}
		else {
			// 2B. 当前没有新进程创建，挂起这个 IRP 等待
			if (g_PendingEventIrp != NULL) {
				// 已经有一个在等了，拒绝多线程并发等待 (为简化逻辑)
				KeReleaseSpinLock(&g_QueueLock, oldIrql);
				status = STATUS_DEVICE_BUSY;
				break;
			}

			// 设置取消例程 (如果 detect.exe 被强杀，内核能安全取消这个 IRP 不蓝屏)
			IoSetCancelRoutine(Irp, CancelPendingEventIrp);
			if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL)) {
				// IRP 已经被取消了
				KeReleaseSpinLock(&g_QueueLock, oldIrql);
				status = STATUS_CANCELLED;
				break;
			}

			IoMarkIrpPending(Irp);
			g_PendingEventIrp = Irp;
			KeReleaseSpinLock(&g_QueueLock, oldIrql);
			return STATUS_PENDING; // 告诉 I/O 管理器我们要异步完成
		}
		break;
	}

	case IOCTL_SEND_VERDICT: {
		// detect.exe 传回了判决结果
		if (inBufLength < sizeof(PROCESS_VERDICT)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PPROCESS_VERDICT verdict = (PPROCESS_VERDICT)Irp->AssociatedIrp.SystemBuffer;

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_QueueLock, &oldIrql);

		// 查找对应的事件节点并设置结果
		PLIST_ENTRY entry = g_EventQueue.Flink;
		while (entry != &g_EventQueue) {
			PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
			if (node->EventData.ProcessId == verdict->ProcessId) {
				// 找到了！设置结果，并唤醒正在回调中阻塞的线程
				node->BlockVerdict = verdict->BlockProcess;
				KeSetEvent(&node->WaitEvent, IO_NO_INCREMENT, FALSE);
				break;
			}
			entry = entry->Flink;
		}

		KeReleaseSpinLock(&g_QueueLock, oldIrql);
		status = STATUS_SUCCESS;
		break;
	}
	}

	if (status != STATUS_PENDING) {
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	return status;
}

// IRP 取消例程：如果 detect.exe 意外退出，内核安全清理挂起的 IRP
VOID CancelPendingEventIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	IoReleaseCancelSpinLock(Irp->CancelIrql);

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);
	if (g_PendingEventIrp == Irp) {
		g_PendingEventIrp = NULL;
	}
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}


// ===========================================================================
// 核心监控回调：提取 PEB -> 丢入队列 -> 阻塞等待判决
// ===========================================================================
void ProcessNotifyCallbackEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
	if (CreateInfo == NULL) return; // 忽略进程退出

	// 使用 RtlZeroMemory 彻底清空，并记录实际提取的长度
	WCHAR extractedCmdLine[1024];
	RtlZeroMemory(extractedCmdLine, sizeof(extractedCmdLine));
	USHORT extractedLen = 0; // 记录实际读取到的字节数
	BOOLEAN gotCmdLine = FALSE;
	// 直接读取系统原生提供的 CommandLine
	if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
		KdPrint(("[PebMonitor] Info: Start get cmd!\n"));
		WriteLogToFile("[PebMonitor] Info: Start get cmd!\r\n");
		USHORT cmdLen = CreateInfo->CommandLine->Length;
		if (cmdLen > 0 && cmdLen < sizeof(extractedCmdLine) - sizeof(WCHAR)) {
			RtlCopyMemory(extractedCmdLine, CreateInfo->CommandLine->Buffer, cmdLen);
			extractedLen = cmdLen;
			gotCmdLine = TRUE;
		}
	}

	if (!gotCmdLine) {
		KAPC_STATE apcState;
		PMY_PEB pPeb = NULL;
		PRTL_USER_PROCESS_PARAMETERS pProcessParams = NULL;
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");

		// 从内核中动态拿取函数指针
		FN_PsGetProcessPeb pfnPsGetProcessPeb = (FN_PsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);

		if (pfnPsGetProcessPeb == NULL) {
			KdPrint(("[PebMonitor] Failed to resolve PsGetProcessPeb address!\n"));
			WriteLogToFile("[PebMonitor] ERROR: Failed to resolve PsGetProcessPeb address!\r\n");
			return;
		}

		// 1. 附加进程，提取 PEB (带 __try 保护)
		pPeb = (PMY_PEB)pfnPsGetProcessPeb(Process);
		if (pPeb) {
			KeStackAttachProcess(Process, &apcState);
			__try {
				pProcessParams = pPeb->ProcessParameters;
				if (pProcessParams && pProcessParams->CommandLine.Buffer) {
					USHORT cmdLen = pProcessParams->CommandLine.Length;
					if (cmdLen > 0 && cmdLen < sizeof(extractedCmdLine) - sizeof(WCHAR)) {
						RtlCopyMemory(extractedCmdLine, pProcessParams->CommandLine.Buffer, cmdLen);
						extractedLen = cmdLen; // 记录真实长度
						gotCmdLine = TRUE;
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				KdPrint(("[PebMonitor] Exception reading PEB.\n"));
				WriteLogToFile("[PebMonitor] Exception reading PEB.\r\n");
			}
			KeUnstackDetachProcess(&apcState);
		}
	}
	
	// 如果没拿到命令行，为了安全起见默认放行
	if (!gotCmdLine) return;

#pragma warning(push)
#pragma warning(disable: 4996)
	PPROCESS_EVENT_NODE node = (PPROCESS_EVENT_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_EVENT_NODE), 'ndPM');
#pragma warning(pop)
	if (!node) return;

	RtlZeroMemory(node, sizeof(PROCESS_EVENT_NODE));
	node->EventData.ProcessId = HandleToULong(ProcessId);
	node->EventData.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

	// 【修复 2】只拷贝实际提取到的长度，不全量拷贝，消除静态分析警告
	RtlCopyMemory(node->EventData.CommandLine, extractedCmdLine, extractedLen);

	// 初始化事件，设为未触发状态
	KeInitializeEvent(&node->WaitEvent, NotificationEvent, FALSE);
	node->IsSentToUser = FALSE;
	node->BlockVerdict = FALSE;

	// 3. 插入全局队列，并检查是否有挂起的 IRP 需要唤醒
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);

	if (g_EventCount >= MAX_EVENT_COUNT) {
		// 如果队列深度达到阈值 (1000)，直接释放锁和内存并放行进程
		KeReleaseSpinLock(&g_QueueLock, oldIrql);
		ExFreePoolWithTag(node, 'ndPM');

		// 记录系统遭到大量并发请求的日志
		WriteLogToFile("[PebMonitor] WARNING: Queue is FULL (%d). Auto-allowed PID: %d to prevent BSOD.\r\n", MAX_EVENT_COUNT, node->EventData.ProcessId);
		return;
	}

	// 将节点挂入链表并增加计数
	InsertTailList(&g_EventQueue, &node->ListEntry);
	g_EventCount++; // 深度 +1

	PIRP irpToComplete = NULL;
	if (g_PendingEventIrp != NULL) {
		if (IoSetCancelRoutine(g_PendingEventIrp, NULL)) {
			irpToComplete = g_PendingEventIrp;
			g_PendingEventIrp = NULL;
			node->IsSentToUser = TRUE;
			RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(PROCESS_EVENT));
			irpToComplete->IoStatus.Information = sizeof(PROCESS_EVENT);
			irpToComplete->IoStatus.Status = STATUS_SUCCESS;
		}
		else {
			g_PendingEventIrp = NULL;
		}
	}
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	// 完成 IRP (必须在自旋锁外部调用！)
	if (irpToComplete) {
		IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
	}

	// 4. 内核线程进入阻塞等待！最长等 1 秒
	LARGE_INTEGER timeout;
	// -10000000 代表相对时间 1 秒 (10,000,000 个 100纳秒单位)
	timeout.QuadPart = -10000000;

	NTSTATUS waitStatus = KeWaitForSingleObject(&node->WaitEvent, Executive, KernelMode, FALSE, &timeout);

	if (waitStatus == STATUS_TIMEOUT) {
		KdPrint(("[PebMonitor] User-mode verdict TIMEOUT. Defaulting to ALLOW.\n"));
		WriteLogToFile("[PebMonitor] User-mode verdict TIMEOUT. Defaulting to ALLOW.!\r\n");

	}

	// 5. 等待结束，从链表中摘除
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);
	RemoveEntryList(&node->ListEntry);
	g_EventCount--; // 深度 -1，释放队列名额
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	// 6. 执行最终裁判
	if (node->BlockVerdict == TRUE) {
		KdPrint(("[PebMonitor] Malicious process BLOCKED! PID: %d\n", node->EventData.ProcessId));
		WriteLogToFile("[PebMonitor] Malicious process BLOCKED! PID: %d\r\n", node->EventData.ProcessId);
		CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
	}

	ExFreePoolWithTag(node, 'ndPM');
}

// ===========================================================================
// 驱动加载与卸载入口
// ===========================================================================
void UnloadDriver(PDRIVER_OBJECT DriverObject) {
	// 【修复新增】告诉编译器我们故意不使用这个参数，消除报错
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);
	if (g_PendingEventIrp) {
		if (IoSetCancelRoutine(g_PendingEventIrp, NULL)) {
			g_PendingEventIrp->IoStatus.Status = STATUS_CANCELLED;
			g_PendingEventIrp->IoStatus.Information = 0;
			IoCompleteRequest(g_PendingEventIrp, IO_NO_INCREMENT);
		}
		g_PendingEventIrp = NULL;
	}
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
	IoDeleteSymbolicLink(&symLink);
	if (g_DeviceObject) {
		IoDeleteDevice(g_DeviceObject);
	}
	KdPrint(("[PebMonitor] INFO: Driver Unloaded.\n"));
	WriteLogToFile("[PebMonitor] INFO: Driver Unloaded.\r\n");
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = UnloadDriver;

	InitializeListHead(&g_EventQueue);
	KeInitializeSpinLock(&g_QueueLock);
	g_EventCount = 0; // 【新增】初始化计数器

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PebMonitor");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[PebMonitor] ERROR: Failed to create device. Status: 0x%X\n", status));
		WriteLogToFile("[PebMonitor] ERROR: Failed to create device. Status: 0x%X\r\n", status);
		return status;
	}
	KdPrint(("[PebMonitor] success to create device. Status: 0x%X\n", status));
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_DeviceObject);
		return status;
	}
	KdPrint(("[PebMonitor] success to create symbol. Status: 0x%X\n", status));
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

	status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(g_DeviceObject);
		KdPrint(("[PebMonitor] ERROR: Failed to register callback. Status: 0x%X\n", status));
		WriteLogToFile("[PebMonitor] ERROR: Failed to register callback. Status: 0x%X\r\n", status);
		return status;
	}
	KdPrint(("[PebMonitor] INFO: Driver Loaded Successfully.\n"));
	WriteLogToFile("[PebMonitor] INFO: Driver Loaded Successfully.\r\n");
	return STATUS_SUCCESS;
}
