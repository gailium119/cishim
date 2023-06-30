#include<wdm.h>
#include <minwindef.h>
#include"ci.h"
#include "mincrypt.h"
__int64 __fastcall CiValidateFileAsImageType(int a1, unsigned __int64 a2, unsigned __int64 a3) {
    return 0;
}
__int64 __fastcall CiRegisterSigningInformation(
    unsigned __int8 a1,
    void* a2,
    unsigned int a3,
    int a4,
    __int64 a5,
    unsigned int a6,
    long long *a7) {
    return 0;
}
__int64 g_CipRuntimeSignersLock; 
__int64 g_CipRuntimeSignersCount;
__int64 __fastcall CiUnregisterSigningInformation(long long* P)
{
    return 0;
}
NTSTATUS CiCheckSignedFile(_In_ const PVOID digestBuffer, _In_ int digestSize, _In_ int digestIdentifier, _In_ const LPWIN_CERTIFICATE winCert, _In_ int sizeOfSecurityDirectory, _Out_ PolicyInfo* policyInfoForSigner, _Out_ LARGE_INTEGER* signingTime, _Out_ PolicyInfo* policyInfoForTimestampingAuthority) {
    return STATUS_SUCCESS;
}
__int64 __fastcall CiFindPageHashesInCatalog(
    void* a1,
    unsigned int a2,
    unsigned int a3,
    int a4,
    int a5,
    int a6,
    long long* a7,
    long long* a8,
    struct _UNICODE_STRING* a9) {
    return 0;
}
__int64 __fastcall CiFindPageHashesInSignedFile(
    __int64 a1,
    void* a2,
    unsigned int a3,
    unsigned int a4,
    unsigned int* a5,
    __int64 a6,
    __int64 a7) {
    return 0;
}

PVOID _stdcall CiFreePolicyInfo(PolicyInfo* policyInfo){
    
    return 0;
}
__int64 __fastcall CiGetPEInformation(DWORD* a1, unsigned int a2, unsigned int a3)
{
    return 0;
}
NTSTATUS _stdcall CiValidateFileObject(
    struct _FILE_OBJECT* fileObject,
    int a2,
    int a3,
    PolicyInfo* policyInfoForSigner,
    PolicyInfo* policyInfoForTimestampingAuthority,
    LARGE_INTEGER* signingTime,
    BYTE* digestBuffer,
    int* digestSize,
    int* digestIdentifier
) {
    return 0;
}
NTSTATUS __fastcall CiVerifyHashInCatalog(
    _In_ PCUCHAR digest,      // pointer to the digest itself
    _In_ int digestSize,		// 14h for SHA1
    _In_ int digestIdentifier,	// 8004h for SHA1
    _In_ int a4,			// system context?
    _In_ int a5,			// always 0
    _In_ int a6,			// always 2007Fh
    _Out_ PolicyInfo* policyInfo,
    _Out_opt_ UNICODE_STRING* catalogName,
    _Out_ LARGE_INTEGER* signingTime,
    _Out_ PolicyInfo* policyInfo2
) {
    return 0;
}
__int64 __fastcall CiValidateImageHeader(
    __int64 a1,
    __int64 a2,
    __int64 a3,
    __int64 a4,
    int a5,
    __int64 a6,
    char a7,
    BYTE* a8)
{
    return 0i64;
}
__int64 CiValidateImageData()
{
    return 0i64;
}

WORD g_CiOptions=0;
PRKPROCESS g_CiSystemProcess;
LIST_ENTRY g_BootDriverList;
int g_CiInitLock;
int g_CiMinimumHashAlgorithm = 0x8004;
int g_CiExclusionListCount;
int g_CiPrivateNtosApis;
char g_CiUpgradeInProgress;
char g_CiVslHvciInterface[104];
__int64  g_CipRuntimeSignersList, g_CiWimListLock;
short g_CiDeveloperMode = 0;
int* g_CiProtectedContent[] = { &g_CiOptions,0x4,&g_CiDeveloperMode,0x4,&g_CiSystemProcess,0x8,&g_CiMinimumHashAlgorithm,0x4,&g_CiExclusionListCount,0x4,&g_CiPrivateNtosApis,0x10,
&g_CiUpgradeInProgress,0x1,&g_CiVslHvciInterface,0x68
}; 
int __stdcall CiQueryInformation(DWORD* SystemInformation, unsigned int SystemInformationLength, int IsUmciEnabled, unsigned int* ReturnLength)
{
    *ReturnLength = 8;
    if (SystemInformationLength < 8)
        return 0xC0000004;
    if (*SystemInformation != 8 || SystemInformationLength != 8)
        return 0xC0000004;
    SystemInformation[1] = 0;
    SystemInformation[1] |= 0x200u;
    SystemInformation[1] |= 0x40u;
    return 0;
}
void __fastcall CiSetFileCache(
    int a1,
    KPROCESSOR_MODE a2,
    unsigned __int8 a3,
    unsigned __int8 a4,
    HANDLE* a5,
    unsigned int a6,
    HANDLE Handle)
{
    return 0;
}
__int64 __fastcall CiGetFileCache(__int64 a1, char* a2, DWORD* a3, void* a4, __int64 a5, __int64 a6) {
    return 0;
}
__int64 __fastcall CiHashMemory(
    IN ALG_ID HashAlgId,
    IN void* rgBlob,
    IN DWORD cBlob,
    OUT BYTE rgbHash[MINCRYPT_MAX_HASH_LEN],
    OUT DWORD* pcbHash)
{

    return MinCryptHashMemory(HashAlgId, rgBlob, cBlob, rgbHash, pcbHash);
    
}
__int64 __fastcall KappxIsPackageFile(__int64 a1, BYTE* a2, BYTE* a3) {
    return 1;
}
__int64 __fastcall CiCompareSigningLevels(char a1, char a2)
{
    return 1;
}

__int64 __fastcall CiInitializePolicy(DWORD* a1, DWORD* a2, DWORD* a3, DWORD* a4) {
    if (a1 != 0) {
        *a1 = &g_CiProtectedContent;
        *a2 = 0;
    }
    else if (a2 != 0) {
        *a2 = &g_CiProtectedContent;
        *a3 = 0;
    }
    else {
        *a3 = &g_CiProtectedContent;
        *a4 = 0;
    }
    return 0;
}
__int64 __fastcall CiGetStrongImageReference(__int64 a1, unsigned long long* a2)
{
    if (!a1)
        return 3221225711i64;
    if ((*(DWORD*)a1 & 2) != 0)
        *a2 = *(unsigned long long*)(a1 + 8);
    else
        *a2 = 0i64;
    return 0i64;
}
__int64 __fastcall CiReleaseContext(DWORD* a1)
{
    return 0i64;
}
__int64 __fastcall CiHvciSetImageBaseAddress(__int64 a1, __int64 a2)
{

    return 0;
}
__int64 __fastcall SIPolicyQueryPolicyInformation(int* a1, int a2, DWORD* a3) {
    return 0;
}
__int64 CiQuerySecurityPolicy(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING a2,
    PCUNICODE_STRING a3,
    __int64 a4,
    __int64 a5) {
    return 0;
}
__int64 __fastcall CiRevalidateImage(char a1, char a2, char a3, int a4, __int64 a5, PFILE_OBJECT FileObject) {
    return 1;
}
__int64 __fastcall CiSetInformation(int a1, void* a2, ULONG a3) {
    return 0;
}
__int64 __fastcall CiSetInformationProcess(void* a1, int a2) {
    return 0;
}
__int64 __fastcall CiGetBuildExpiryTime(unsigned long long* a1) {
    *a1 = 0;
    return 0;
}
char __fastcall CiCheckProcessDebugAccessPolicy(__int64 a1, struct _KPROCESS* a2) {
    return 0;
}
__int64 __fastcall CiGetCodeIntegrityOriginClaimForFileObject(__int64 a1, __int64 a2) {
    return 0;
}
void __fastcall CiDeleteCodeIntegrityOriginClaimMembers(__int64 a1) {

}
void __fastcall CiDeleteCodeIntegrityOriginClaimForFileObject(__int64 a1) {

}
__int64 __fastcall CiCompareExistingSePool(unsigned int* Buf1, unsigned __int64 Buf2) {
    return 0;
}
__int64 __fastcall CiSetCachedOriginClaim(KPROCESSOR_MODE a1, void* a2, size_t a3, const void* a4) {
    return 0;
}
__int64 __fastcall CiHvciReportMmIncompatibility(int a1, int a2, int a3) {
    return 0;
}
__int64 __fastcall CipInitialize(unsigned int OptionFlags, LIST_ENTRY* BootDriverListHead, __int64 a3, __int64* a4) {
    g_CiOptions = 0;
    g_CiSystemProcess = NULL;
    g_CipRuntimeSignersLock = 0i64;
    g_CiWimListLock = 0i64;
    int num = *(DWORD*)a3 ;
    if (num >= 16)*(unsigned long long*)(a3 + 8) = CiSetFileCache;
    if (num >= 24)*(unsigned long long*)(a3 + 16) = CiGetFileCache;
    if (num >= 32)*(unsigned long long*)(a3 + 24) = CiQueryInformation;
    if (num >= 40)*(unsigned long long*)(a3 + 32) = CiValidateImageHeader;
    if (num >= 48)*(unsigned long long*)(a3 + 40) = CiValidateImageData;
    if (num >= 56)*(unsigned long long*)(a3 + 48) = CiHashMemory;
    if (num >= 64)*(unsigned long long*)(a3 + 56) = KappxIsPackageFile;
    if (num >= 72)*(unsigned long long*)(a3 + 64) = CiCompareSigningLevels;
    if (num >= 80)*(unsigned long long*)(a3 + 72) = CiValidateFileAsImageType;
    if (num >= 88)*(unsigned long long*)(a3 + 80) = CiRegisterSigningInformation;
    if (num >= 96)*(unsigned long long*)(a3 + 88) = CiUnregisterSigningInformation;
    if (num >= 104)*(unsigned long long*)(a3 + 96) = CiInitializePolicy;
    if (num >= 112)*(unsigned long long*)(a3 + 104) = CiReleaseContext;
    if (num >= 128)*(unsigned long long*)(a3 + 120) = CiGetStrongImageReference;
    if (num >= 136)*(unsigned long long*)(a3 + 128) = CiHvciSetImageBaseAddress;
    if (num >= 144)*(unsigned long long*)(a3 + 136) = SIPolicyQueryPolicyInformation;
    if (num >= 152)*(unsigned long long*)(a3 + 144) = CiQuerySecurityPolicy;
    if (num >= 160)*(unsigned long long*)(a3 + 152) = CiRevalidateImage;
    if (num >= 168)*(unsigned long long*)(a3 + 160) = CiSetInformation;
    if (num >= 176)*(unsigned long long*)(a3 + 168) = CiSetInformationProcess;
    if (num >= 184)*(unsigned long long*)(a3 + 176) = CiGetBuildExpiryTime;
    if (num >= 192)*(unsigned long long*)(a3 + 184) = CiCheckProcessDebugAccessPolicy;
    if (num >= 200)*(unsigned long long*)(a3 + 192) = CiGetCodeIntegrityOriginClaimForFileObject;
    if (num >= 208)*(unsigned long long*)(a3 + 200) = CiDeleteCodeIntegrityOriginClaimMembers;
    if (num >= 216)*(unsigned long long*)(a3 + 208) = CiDeleteCodeIntegrityOriginClaimForFileObject;
    if (num >= 224)*(unsigned long long*)(a3 + 216) = CiHvciReportMmIncompatibility;
    if (num >= 232)*(unsigned long long*)(a3 + 224) = CiCompareExistingSePool;
    if (num >= 240)*(unsigned long long*)(a3 + 232) = CiSetCachedOriginClaim;
    return 0;
}
__int64 CiInitialize(int a1, __int64** a2, __int64 a3, __int64* a4)
{

    return CipInitialize(0, a2, a3,a4);
}
