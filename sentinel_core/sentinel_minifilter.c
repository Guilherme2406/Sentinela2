// sentinel_driver/sentinel_minifilter.c
#include <dontuse.h>
#include <fltKernel.h>


#pragma prefast(disable : 28101, "Initialization annotation")

// Protótipos das funções do Driver
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);
NTSTATUS SentinelUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS
SentinelPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

// Estrutura de registro do Minifilter
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, SentinelPreCreate, NULL}, {IRP_MJ_OPERATION_END}};

const FLT_REGISTRATION FilterRegistration = {sizeof(FLT_REGISTRATION),
                                             FLT_REGISTRATION_VERSION,
                                             0,
                                             NULL,
                                             Callbacks,
                                             SentinelUnload,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL};

PFLT_FILTER gFilterHandle = NULL;

// Instalação / Carregamento do Driver no Ring 0
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  NTSTATUS status;

  KdPrint(
      ("SentinelaXDR: Inicializando Driver Kernel Minifilter (Ring 0)...\n"));

  status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
  if (NT_SUCCESS(status)) {
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
      FltUnregisterFilter(gFilterHandle);
    }
  }

  return status;
}

// Descarregamento seguro do Driver
NTSTATUS SentinelUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
  UNREFERENCED_PARAMETER(Flags);
  KdPrint(("SentinelaXDR: Descarregando Driver Minifilter...\n"));
  FltUnregisterFilter(gFilterHandle);
  return STATUS_SUCCESS;
}

// Callback de Pre-Operação de Arquivo (Intercepta I/O antes da gravação no
// disco)
FLT_PREOP_CALLBACK_STATUS
SentinelPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(CompletionContext);

  // Validação de segurança / Auditoria Ring 0 de acesso a arquivos sensíveis
  if (Data->RequestorMode == UserMode) {
    // Exemplo: Bloqueio ou Log de acesso não autorizado a diretórios protegidos
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
