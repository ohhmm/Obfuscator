#pragma once

#define MAX_SECTION_NUM         20

class PE 
{
    DWORD					ReservedHeaderSize;
    DWORD					ReservedHeaderRO;
    bool					OCXType;
    DWORD					dwRO_first_section;
    DWORD					dwDepackCodeVirtualSize;
    IMAGE_DOS_HEADER		image_dos_header;
    char					*pMem;
    char					*reservedheader;
    IMAGE_NT_HEADERS		image_nt_headers;
    IMAGE_SECTION_HEADER	image_section_header[MAX_SECTION_NUM];
    char					*image_section[MAX_SECTION_NUM];
    HANDLE                  hFile;
    DWORD dwFsize;
public:
    void OpenFileName(char* FileName);
    void UpdateHeaders(BOOL bSaveAndValidate);
    void UpdateHeadersSections(BOOL bSaveAndValidate);
    PIMAGE_SECTION_HEADER AddSection();
    void RemoveSection(char* SectionName);
    void RemoveSectionNames();
    void CryptPE();
    void CompressPE();
    void CompressResourceDirectory(char* Base,DWORD dwBaseRVA,DWORD dwRVA);
    void CryptResourceDirectory(char* Base,DWORD dwBaseRVA,DWORD dwRVA);
    void Free();
    bool CheckifProtect();
    bool CheckifSectionName();
    bool CheckifPEvalid();
    bool CheckCOMRuntime();
    DWORD CheckifDLL();
    bool CheckifSYS();
    bool CheckifVCM2();
    void OptimizeDOSHeader();
    void EliminateDOSHeader();
    void EliminateReloc();
    void EliminateDebug();
    DWORD GetSectionNume(char* targetSectionName);
};
