/*
 * 模块：数字证书检测
 * 指标：签名有效性、文件篡改检测、时间戳、序列号、使用者、颁发者、有效期、证书链
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <imagehlp.h>
#include <string>
#include <vector>
#include "../common/Utils.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")

/* ============================================================
 *  内部辅助：二进制转十六进制字符串
 * ============================================================ */
static std::string BinToHex(const BYTE* data, DWORD len)
{
    if (!data || len == 0) return "";
    std::string result;
    result.reserve(len * 2);
    static const char hex[] = "0123456789ABCDEF";
    for (DWORD i = 0; i < len; i++)
    {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0x0F];
    }
    return result;
}

/* ============================================================
 *  内部辅助：FILETIME → "YYYY-MM-DD HH:MM:SS UTC"
 * ============================================================ */
static std::string CertFileTimeToUtcStr(const FILETIME& ft)
{
    SYSTEMTIME st = {0};
    FileTimeToSystemTime(&ft, &st);
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d UTC",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

/* ============================================================
 *  内部辅助：CERT_NAME_BLOB → 可读字符串（DN 格式）
 * ============================================================ */
static std::string CertNameToStr(const CERT_NAME_BLOB* pName, DWORD dwType)
{
    if (!pName || pName->cbData == 0) return "";
    DWORD needed = CertNameToStrW(X509_ASN_ENCODING,
        const_cast<CERT_NAME_BLOB*>(pName), dwType, NULL, 0);
    if (needed == 0) return "";
    /* 使用 malloc 替代 wstring 初始化以兼容 VS2010/2017 */
    wchar_t* wbuf = (wchar_t*)malloc(needed * sizeof(wchar_t));
    if (!wbuf) return "";
    CertNameToStrW(X509_ASN_ENCODING,
        const_cast<CERT_NAME_BLOB*>(pName), dwType, wbuf, needed);
    /* 去掉末尾 \0 */
    DWORD len = needed;
    while (len > 0 && wbuf[len - 1] == L'\0') len--;
    std::string result = WideToUtf8(wbuf);
    free(wbuf);
    return result;
}

/* ============================================================
 *  内部辅助：计算文件 SHA-1 / SHA-256 指纹
 * ============================================================ */
static std::string HashFile(const wchar_t* filePath, ALG_ID algId)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    const DWORD BUF_SIZE = 65536;
    BYTE* buf = (BYTE*)malloc(BUF_SIZE);
    if (buf)
    {
        DWORD bytesRead = 0;
        while (ReadFile(hFile, buf, BUF_SIZE, &bytesRead, NULL) && bytesRead > 0)
            CryptHashData(hHash, buf, bytesRead, 0);
        free(buf);
    }
    CloseHandle(hFile);

    DWORD hashLen = 0, cbLen = sizeof(DWORD);
    CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &cbLen, 0);
    if (hashLen > 0 && hashLen <= 64)
    {
        BYTE hashBuf[64] = {0};
        CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0);
        result = BinToHex(hashBuf, hashLen);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

/* ============================================================
 *  内部辅助：从证书上下文构建单个证书 JSON 对象
 * ============================================================ */
static cJSON* BuildCertObject(PCCERT_CONTEXT pCert)
{
    if (!pCert) return cJSON_CreateNull();
    cJSON* obj = cJSON_CreateObject();

    cJSON_AddStringToObject(obj, "subject",
        CertNameToStr(&pCert->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG).c_str());
    cJSON_AddStringToObject(obj, "issuer",
        CertNameToStr(&pCert->pCertInfo->Issuer,
            CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG).c_str());

    /* 序列号（大端十六进制） */
    CRYPT_INTEGER_BLOB& sn = pCert->pCertInfo->SerialNumber;
    BYTE* snReversed = (BYTE*)malloc(sn.cbData);
    if (snReversed)
    {
        for (DWORD i = 0; i < sn.cbData; i++)
            snReversed[i] = sn.pbData[sn.cbData - 1 - i];
        cJSON_AddStringToObject(obj, "serial_number",
            BinToHex(snReversed, sn.cbData).c_str());
        free(snReversed);
    }

    cJSON_AddStringToObject(obj, "not_before",
        CertFileTimeToUtcStr(pCert->pCertInfo->NotBefore).c_str());
    cJSON_AddStringToObject(obj, "not_after",
        CertFileTimeToUtcStr(pCert->pCertInfo->NotAfter).c_str());

    SYSTEMTIME stNow;
    GetSystemTime(&stNow);
    FILETIME ftNow;
    SystemTimeToFileTime(&stNow, &ftNow);
    bool notExpired =
        (CompareFileTime(&ftNow, &pCert->pCertInfo->NotBefore) >= 0) &&
        (CompareFileTime(&ftNow, &pCert->pCertInfo->NotAfter)  <= 0);
    cJSON_AddBoolToObject(obj, "not_expired", notExpired ? 1 : 0);

    PCCRYPT_OID_INFO pOidInfo = CryptFindOIDInfo(
        CRYPT_OID_INFO_OID_KEY,
        pCert->pCertInfo->SignatureAlgorithm.pszObjId, 0);
    if (pOidInfo && pOidInfo->pwszName)
        cJSON_AddStringToObject(obj, "signature_algorithm",
            WideToUtf8(pOidInfo->pwszName).c_str());
    else
        cJSON_AddStringToObject(obj, "signature_algorithm",
            pCert->pCertInfo->SignatureAlgorithm.pszObjId
            ? pCert->pCertInfo->SignatureAlgorithm.pszObjId : "");

    BYTE sha1[20] = {0};
    DWORD sha1Len = sizeof(sha1);
    if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID,
        sha1, &sha1Len))
        cJSON_AddStringToObject(obj, "thumbprint_sha1",
            BinToHex(sha1, sha1Len).c_str());

    {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            {
                CryptHashData(hHash, pCert->pbCertEncoded, pCert->cbCertEncoded, 0);
                DWORD hashLen = 32;
                BYTE hashBuf[32] = {0};
                CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0);
                cJSON_AddStringToObject(obj, "thumbprint_sha256",
                    BinToHex(hashBuf, hashLen).c_str());
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
    }

    /* 是否为 CA 证书 */
    DWORD bcLen = 0;
    bool isCA = false;
    if (CertGetCertificateContextProperty(pCert,
        CERT_BASIC_CONSTRAINTS2_INFO_PROP_ID, NULL, &bcLen) && bcLen > 0)
    {
        BYTE* bcBuf = (BYTE*)malloc(bcLen);
        if (bcBuf)
        {
            if (CertGetCertificateContextProperty(pCert,
                CERT_BASIC_CONSTRAINTS2_INFO_PROP_ID, bcBuf, &bcLen))
            {
                DWORD cbDecoded = 0;
                CERT_BASIC_CONSTRAINTS2_INFO* pInfo = NULL;
                if (CryptDecodeObjectEx(X509_ASN_ENCODING,
                    szOID_BASIC_CONSTRAINTS2,
                    bcBuf, bcLen,
                    CRYPT_DECODE_ALLOC_FLAG, NULL,
                    &pInfo, &cbDecoded) && pInfo)
                {
                    isCA = pInfo->fCA ? true : false;
                    LocalFree(pInfo);
                }
            }
            free(bcBuf);
        }
    }
    cJSON_AddBoolToObject(obj, "is_ca", isCA ? 1 : 0);

    return obj;
}

/* ============================================================
 *  内部辅助：从 PKCS#7 消息中提取时间戳
 * ============================================================ */
static std::string ExtractTimestamp(HCRYPTMSG hMsg, DWORD signerIndex)
{
    static const char* tsOids[] = {
        "1.3.6.1.4.1.311.3.3.1",
        szOID_RSA_counterSign,
        NULL
    };

    for (int oi = 0; tsOids[oi]; oi++)
    {
        DWORD cbAttr = 0;
        if (!CryptMsgGetParam(hMsg,
            CMSG_SIGNER_UNAUTH_ATTR_PARAM,
            signerIndex, NULL, &cbAttr) || cbAttr == 0)
            continue;

        BYTE* attrBuf = (BYTE*)malloc(cbAttr);
        if (!attrBuf) continue;
        if (!CryptMsgGetParam(hMsg,
            CMSG_SIGNER_UNAUTH_ATTR_PARAM,
            signerIndex, attrBuf, &cbAttr))
        {
            free(attrBuf);
            continue;
        }

        CRYPT_ATTRIBUTES* pAttrs = (CRYPT_ATTRIBUTES*)attrBuf;
        for (DWORD i = 0; i < pAttrs->cAttr; i++)
        {
            CRYPT_ATTRIBUTE& attr = pAttrs->rgAttr[i];
            if (!attr.pszObjId) continue;
            if (strcmp(attr.pszObjId, tsOids[oi]) != 0) continue;
            if (attr.cValue == 0) continue;

            if (strcmp(attr.pszObjId, "1.3.6.1.4.1.311.3.3.1") == 0)
            {
                PCRYPT_TIMESTAMP_CONTEXT pTsCtx = NULL;
                if (CryptVerifyTimeStampSignature(
                    attr.rgValue[0].pbData,
                    attr.rgValue[0].cbData,
                    NULL, 0, NULL, &pTsCtx, NULL) && pTsCtx)
                {
                    FILETIME ft;
                    SystemTimeToFileTime(&pTsCtx->pTimeStamp->Time, &ft);
                    std::string ts = CertFileTimeToUtcStr(ft);
                    CryptMemFree(pTsCtx);
                    free(attrBuf);
                    return ts;
                }
            }

            {
                DWORD cbSI = 0;
                CMSG_SIGNER_INFO* pSI = NULL;
                if (CryptDecodeObjectEx(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    PKCS7_SIGNER_INFO,
                    attr.rgValue[0].pbData,
                    attr.rgValue[0].cbData,
                    CRYPT_DECODE_ALLOC_FLAG, NULL,
                    &pSI, &cbSI) && pSI)
                {
                    for (DWORD j = 0; j < pSI->AuthAttrs.cAttr; j++)
                    {
                        CRYPT_ATTRIBUTE& a2 = pSI->AuthAttrs.rgAttr[j];
                        if (!a2.pszObjId) continue;
                        if (strcmp(a2.pszObjId, szOID_RSA_signingTime) != 0) continue;
                        if (a2.cValue == 0) continue;

                        FILETIME ft = {0};
                        DWORD cbFt = sizeof(ft);
                        if (CryptDecodeObjectEx(
                            X509_ASN_ENCODING,
                            szOID_RSA_signingTime,
                            a2.rgValue[0].pbData,
                            a2.rgValue[0].cbData,
                            0, NULL, &ft, &cbFt))
                        {
                            LocalFree(pSI);
                            free(attrBuf);
                            return CertFileTimeToUtcStr(ft);
                        }
                    }
                    LocalFree(pSI);
                }
            }
        }
        free(attrBuf);
    }
    return "";
}

/* ============================================================
 *  内部辅助：Authenticode 验证（局部版，不与 Utils.h 冲突）
 * ============================================================ */
static std::string CertVerifyAuthenticode(
    const wchar_t* filePath,
    bool checkRevocation,
    LONG& outHResult)
{
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct     = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {0};
    trustData.cbStruct       = sizeof(trustData);
    trustData.dwUIChoice     = WTD_UI_NONE;
    trustData.fdwRevocationChecks = checkRevocation
        ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    trustData.dwUnionChoice  = WTD_CHOICE_FILE;
    trustData.pFile          = &fileInfo;
    trustData.dwStateAction  = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags    = WTD_SAFER_FLAG |
        (checkRevocation ? 0 : WTD_CACHE_ONLY_URL_RETRIEVAL);

    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);
    outHResult  = result;

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    switch (result)
    {
    case ERROR_SUCCESS:               return "Valid";
    case TRUST_E_NOSIGNATURE:         return "NoSignature";
    case TRUST_E_EXPLICIT_DISTRUST:   return "ExplicitDistrust";
    case TRUST_E_SUBJECT_NOT_TRUSTED: return "NotTrusted";
    case CERT_E_EXPIRED:              return "CertExpired";
    case CERT_E_REVOKED:              return "CertRevoked";
    case CERT_E_UNTRUSTEDROOT:        return "UntrustedRoot";
    case CERT_E_CHAINING:             return "ChainError";
    case TRUST_E_BAD_DIGEST:          return "BadDigest(FileTampered)";
    case CRYPT_E_SECURITY_SETTINGS:   return "SecuritySettings";
    default:
    {
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Unknown(0x%08X)", (unsigned)result);
        return buf;
    }
    }
}

/* ============================================================
 *  内部辅助：判断文件是否被篡改
 * ============================================================ */
static bool IsFileTampered(LONG verifyHResult)
{
    if (verifyHResult == TRUST_E_BAD_DIGEST) return true;
    if (verifyHResult != ERROR_SUCCESS &&
        verifyHResult != TRUST_E_NOSIGNATURE &&
        verifyHResult != CERT_E_EXPIRED &&
        verifyHResult != CERT_E_REVOKED &&
        verifyHResult != CERT_E_UNTRUSTEDROOT &&
        verifyHResult != CERT_E_CHAINING &&
        verifyHResult != TRUST_E_EXPLICIT_DISTRUST &&
        verifyHResult != TRUST_E_SUBJECT_NOT_TRUSTED &&
        verifyHResult != (LONG)CRYPT_E_SECURITY_SETTINGS)
        return true;
    return false;
}

/* ============================================================
 *  内部核心：解析 PKCS#7 签名消息
 * ============================================================ */
static cJSON* ParseSignatureDetails(
    const wchar_t* filePath,
    bool includeChain)
{
    cJSON* sigObj = cJSON_CreateObject();

    HCERTSTORE hStore  = NULL;
    HCRYPTMSG  hMsg    = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, NULL);

    if (!ok || !hMsg)
    {
        cJSON_AddStringToObject(sigObj, "parse_error",
            "No embedded PKCS#7 signature found");
        return sigObj;
    }

    DWORD cbSI = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbSI);
    if (cbSI > 0)
    {
        BYTE* siBuf = (BYTE*)malloc(cbSI);
        if (siBuf)
        {
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, siBuf, &cbSI))
            {
                CMSG_SIGNER_INFO* pSI = (CMSG_SIGNER_INFO*)siBuf;

                CERT_INFO certInfo = {0};
                certInfo.Issuer       = pSI->Issuer;
                certInfo.SerialNumber = pSI->SerialNumber;

                PCCERT_CONTEXT pSignerCert = CertFindCertificateInStore(
                    hStore,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0, CERT_FIND_SUBJECT_CERT,
                    &certInfo, NULL);

                if (pSignerCert)
                {
                    cJSON* signerCert = BuildCertObject(pSignerCert);
                    cJSON_AddItemToObject(sigObj, "signer_certificate", signerCert);
                    CertFreeCertificateContext(pSignerCert);
                }

                std::string ts = ExtractTimestamp(hMsg, 0);
                cJSON_AddStringToObject(sigObj, "timestamp",
                    ts.empty() ? "N/A" : ts.c_str());

                if (pSI->HashAlgorithm.pszObjId)
                {
                    PCCRYPT_OID_INFO pOid = CryptFindOIDInfo(
                        CRYPT_OID_INFO_OID_KEY,
                        pSI->HashAlgorithm.pszObjId, 0);
                    cJSON_AddStringToObject(sigObj, "hash_algorithm",
                        (pOid && pOid->pwszName)
                        ? WideToUtf8(pOid->pwszName).c_str()
                        : pSI->HashAlgorithm.pszObjId);
                }
            }
            free(siBuf);
        }
    }

    if (includeChain)
    {
        cJSON* chainArr = cJSON_CreateArray();
        PCCERT_CONTEXT pCert = NULL;
        DWORD certIdx = 0;
        while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL)
        {
            cJSON* certObj = BuildCertObject(pCert);
            cJSON_AddNumberToObject(certObj, "chain_index", (double)certIdx++);
            cJSON_AddItemToArray(chainArr, certObj);
        }
        cJSON_AddItemToObject(sigObj, "certificate_chain", chainArr);
    }

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg)   CryptMsgClose(hMsg);

    return sigObj;
}

/* ============================================================
 *  导出接口：GetCertInfo
 * ============================================================ */
extern "C" __declspec(dllexport)
char* GetCertInfo(const char* paramsJson)
{
    std::string filePath = GetStringParam(paramsJson, "file_path", "");
    bool checkRevocation = GetBoolParam(paramsJson, "check_revocation", false);
    bool includeChain    = GetBoolParam(paramsJson, "include_chain", true);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "cert_info");

    if (filePath.empty())
    {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error",
            "Parameter 'file_path' is required");
        return SerializeJson(root);
    }

    std::wstring wFilePath = Utf8ToWstr(filePath);
    cJSON_AddStringToObject(root, "file_path", filePath.c_str());

    DWORD attrs = GetFileAttributesW(wFilePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error", "File not found");
        return SerializeJson(root);
    }

    cJSON* fileHash = cJSON_CreateObject();
    cJSON_AddStringToObject(fileHash, "sha1",
        HashFile(wFilePath.c_str(), CALG_SHA1).c_str());
    cJSON_AddStringToObject(fileHash, "sha256",
        HashFile(wFilePath.c_str(), CALG_SHA_256).c_str());
    cJSON_AddItemToObject(root, "file_hash", fileHash);

    LONG hResult = 0;
    std::string verifyResult = CertVerifyAuthenticode(
        wFilePath.c_str(), checkRevocation, hResult);

    cJSON_AddStringToObject(root, "verify_result", verifyResult.c_str());

    char hrBuf[16];
    _snprintf_s(hrBuf, sizeof(hrBuf), _TRUNCATE, "0x%08X", (unsigned)hResult);
    cJSON_AddStringToObject(root, "verify_hresult", hrBuf);

    bool hasSig = (hResult != TRUST_E_NOSIGNATURE);
    cJSON_AddBoolToObject(root, "has_signature", hasSig ? 1 : 0);

    bool sigValid = (hResult == ERROR_SUCCESS);
    cJSON_AddBoolToObject(root, "signature_valid", sigValid ? 1 : 0);

    bool tampered = IsFileTampered(hResult);
    cJSON_AddBoolToObject(root, "file_tampered", tampered ? 1 : 0);
    if (tampered)
        cJSON_AddStringToObject(root, "tamper_detail",
            "File content does not match the embedded signature digest");

    if (hasSig)
    {
        cJSON* sigDetails = ParseSignatureDetails(
            wFilePath.c_str(), includeChain);
        cJSON_AddItemToObject(root, "signature_details", sigDetails);
    }

    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/* ============================================================
 *  导出接口：BatchGetCertInfo
 * ============================================================ */
extern "C" __declspec(dllexport)
char* BatchGetCertInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "cert_info_batch");

    bool checkRevocation = GetBoolParam(paramsJson, "check_revocation", false);
    bool includeChain    = GetBoolParam(paramsJson, "include_chain", false);

    cJSON* results = cJSON_CreateArray();

    if (paramsJson)
    {
        cJSON* parsed = cJSON_Parse(paramsJson);
        if (parsed)
        {
            cJSON* filesArr = cJSON_GetObjectItem(parsed, "files");
            if (filesArr && cJSON_IsArray(filesArr))
            {
                cJSON* fileItem = NULL;
                cJSON_ArrayForEach(fileItem, filesArr)
                {
                    if (!cJSON_IsString(fileItem)) continue;
                    const char* fp = fileItem->valuestring;

                    cJSON* singleParam = cJSON_CreateObject();
                    cJSON_AddStringToObject(singleParam, "file_path", fp);
                    cJSON_AddBoolToObject(singleParam, "check_revocation",
                        checkRevocation ? 1 : 0);
                    cJSON_AddBoolToObject(singleParam, "include_chain",
                        includeChain ? 1 : 0);
                    char* singleParamStr = cJSON_PrintUnformatted(singleParam);
                    cJSON_Delete(singleParam);

                    char* singleResult = GetCertInfo(singleParamStr);
                    free(singleParamStr);

                    if (singleResult)
                    {
                        cJSON* resultObj = cJSON_Parse(singleResult);
                        free(singleResult);
                        if (resultObj)
                            cJSON_AddItemToArray(results, resultObj);
                    }
                }
            }
            cJSON_Delete(parsed);
        }
    }

    cJSON_AddItemToObject(root, "results", results);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
