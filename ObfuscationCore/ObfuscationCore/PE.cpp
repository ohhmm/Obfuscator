#include "StdAfx.h"
#include "PE.h"

namespace
{
    //------- ERROR --------

    enum Error
    {
        Ok,
        MemErr,
        PEErr, 
        FileErr,
        NoRoom4SectionErr,
        FsizeErr,
        SecNumErr,
        IIDErr,
        FileISProtect,
        PEnotValid,
        PEisCOMRuntime,
        DLLnotSupport,
        WDMnotSupport,
        TServernotSupport,
        SYSnotSupport,
        NOSEHnotSupport,
        NOBINDnotSupport,
        PackSectionName	
    };

    const wchar_t* ErrorMessages[] =
    {
        L"Ok",
        L"MemErr",
        L"PEErr", 
        L"FileErr",
        L"NoRoom4SectionErr",
        L"FsizeErr",
        L"SecNumErr",
        L"IIDErr",
        L"FileISProtect",
        L"PEnotValid",
        L"PEisCOMRuntime",
        L"DLLnotSupport",
        L"WDMnotSupport",
        L"TServernotSupport",
        L"SYSnotSupport",
        L"NOSEHnotSupport",
        L"NOBINDnotSupport",
        L"PackSectionName"	
    };

    void ShowErr(Error err)
    {
        MessageBox(0, ErrorMessages[err], L"Error", MB_OK);
    }
}

PE::PE(void)
{
}

PE::~PE(void)
{
}

//----------------------------------------------------------------
void PE::OpenFileName(char* FileName)
{
	//LOADED_IMAGE LoadedImage;
	pMem=NULL;

	hFile=CreateFile(FileName,
					 GENERIC_READ,
					 FILE_SHARE_WRITE | FILE_SHARE_READ,
	                 NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		ShowErr(FileErr);
		return;
	}
	dwFsize=GetFileSize(hFile,0);
	if(dwFsize == 0)
	{
		CloseHandle(hFile);
		ShowErr(FsizeErr);
		return;
	}
	dwOutPutSize=dwFsize+IT_SIZE+DEPACKER_CODE_SIZE+ALIGN_CORRECTION;
	pMem=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwOutPutSize);
	if(pMem == NULL)
	{
		CloseHandle(hFile);
		ShowErr(MemErr);
		return;
	}
	ReadFile(hFile,pMem,dwFsize,&dwBytesRead,NULL);
	CloseHandle(hFile);

	CopyMemory(&image_dos_header,pMem,sizeof(IMAGE_DOS_HEADER));
	ReservedHeaderRO=sizeof(IMAGE_DOS_HEADER);

	ReservedHeaderSize=image_dos_header.e_lfanew-sizeof(IMAGE_DOS_HEADER);
	if((ReservedHeaderSize&0x80000000)==0x00000000)
	{
		reservedheader=new TCHAR[ReservedHeaderSize];
	}
	CopyMemory(&image_nt_headers,
		       pMem+image_dos_header.e_lfanew,
			   sizeof(IMAGE_NT_HEADERS));
	dwRO_first_section=image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS);
	UpdateHeadersSections(TRUE);
	//-------------------------------------------------
}
//----------------------------------------------------------------
void PE::UpdateHeaders(BOOL bSaveAndValidate)
{
	if(bSaveAndValidate)//TRUE = data is being retrieved
	{
		DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
		CopyMemory(&image_dos_header,pMem,sizeof(IMAGE_DOS_HEADER));
		ReservedHeaderSize=image_dos_header.e_lfanew-sizeof(IMAGE_DOS_HEADER);
		if((ReservedHeaderSize&0x80000000)==0x00000000)
		{
			CopyMemory(reservedheader,pMem+ReservedHeaderRO,ReservedHeaderSize);
		}
		CopyMemory(&image_nt_headers,
			       pMem+image_dos_header.e_lfanew,
				   sizeof(IMAGE_NT_HEADERS));
		dwRO_first_section=image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS);
		CopyMemory(&image_section_header,pMem+dwRO_first_section,SectionNum*sizeof(IMAGE_SECTION_HEADER));
	}
	else				//FALSE = data is being initialized 
	{
		DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
		CopyMemory(pMem,&image_dos_header,sizeof(IMAGE_DOS_HEADER));
		ReservedHeaderSize=image_dos_header.e_lfanew-sizeof(IMAGE_DOS_HEADER);
		if((ReservedHeaderSize&0x80000000)==0x00000000)
		{
			CopyMemory(pMem+ReservedHeaderRO,reservedheader,ReservedHeaderSize);
		}
		CopyMemory(pMem+image_dos_header.e_lfanew,
			       &image_nt_headers,
				   sizeof(IMAGE_NT_HEADERS));
		dwRO_first_section=image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS);
		CopyMemory(pMem+dwRO_first_section,&image_section_header,SectionNum*sizeof(IMAGE_SECTION_HEADER));
	}
}
//----------------------------------------------------------------
void PE::UpdateHeadersSections(BOOL bSaveAndValidate)
{
	DWORD i;
	if(bSaveAndValidate)//TRUE = data is being retrieved
	{
		DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
		CopyMemory(&image_dos_header,pMem,sizeof(IMAGE_DOS_HEADER));
		ReservedHeaderSize=image_dos_header.e_lfanew-sizeof(IMAGE_DOS_HEADER);
		if((ReservedHeaderSize&0x80000000)==0x00000000)
		{
			CopyMemory(reservedheader,pMem+ReservedHeaderRO,ReservedHeaderSize);
		}
		CopyMemory(&image_nt_headers,
			       pMem+image_dos_header.e_lfanew,
				   sizeof(IMAGE_NT_HEADERS));
		dwRO_first_section=image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS);
		CopyMemory(&image_section_header,pMem+dwRO_first_section,SectionNum*sizeof(IMAGE_SECTION_HEADER));
		for(i=0;i<SectionNum;i++)
		{
			image_section[i]=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,
				PEAlign(image_section_header[i].SizeOfRawData,
				image_nt_headers.OptionalHeader.FileAlignment));
			CopyMemory(image_section[i],
					pMem+image_section_header[i].PointerToRawData,
				   image_section_header[i].SizeOfRawData);
		}
	}
	else				//FALSE = data is being initialized 
	{
		DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
		CopyMemory(pMem,&image_dos_header,sizeof(IMAGE_DOS_HEADER));
		ReservedHeaderSize=image_dos_header.e_lfanew-sizeof(IMAGE_DOS_HEADER);
		if((ReservedHeaderSize&0x80000000)==0x00000000)
		{
			CopyMemory(pMem+ReservedHeaderRO,reservedheader,ReservedHeaderSize);
		}
		CopyMemory(pMem+image_dos_header.e_lfanew,
			       &image_nt_headers,
				   sizeof(IMAGE_NT_HEADERS));
		dwRO_first_section=image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS);
		CopyMemory(pMem+dwRO_first_section,&image_section_header,SectionNum*sizeof(IMAGE_SECTION_HEADER));
		for(i=0;i<SectionNum;i++)
		{
			CopyMemory(pMem+image_section_header[i].PointerToRawData,
				   image_section[i],
				   image_section_header[i].SizeOfRawData);
		}
	}
}
//----------------------------------------------------------------
// Base   = pointer to file memory
// dwMode: 0 - RawCrypt mode
//         1 - VirtualCrypt mode
void PE::CryptPE()
{
	DWORD SectionName1,SectionName2;
	DWORD CryptStart;
	DWORD CryptSize;
	SecDecryptBuff=new TCHAR[SEC_PER_SIZE];
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections;i++)
	{
		// -> do some special sections !
		CopyMemory(&SectionName1,image_section_header[i].Name,4);
		CopyMemory(&SectionName2,image_section_header[i].Name+4,4);
		if((  (SectionName1=='xet.')||				//.text
		      (SectionName1=='EDOC')||				//CODE
		      (SectionName1=='tad.')||				//.data
		      (SectionName1=='ATAD')||				//DATA
		      (SectionName1=='SSB' )||				//BSS
			  (SectionName1=='adr.')||				//.rdata
			 ((SectionName1=='ade.')&&(!OCXType))||	//.edata
			  (SectionName1=='adi.')||				//.idata
			//(SectionName1=='slt.')||				//.tls
			 ((SectionName1=='rsr.')&&(!OCXType))//.rsrc
			)&&
		   (image_section_header[i].PointerToRawData!=0)&&
		   (image_section_header[i].SizeOfRawData!=0))//-> skip also some other sections
		{
			switch(SectionName1)
			{
			case 'xet.':
			case 'EDOC':
				MakePER(SecDecryptBuff,SEC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_CODESectionEncrypt,
						   SecDecryptBuff,
						   SEC_PER_SIZE);
				break;
			case 'tad.':
			case 'ATAD':
				MakePER(SecDecryptBuff,SEC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_DATASectionEncrypt,
						   SecDecryptBuff,
						   SEC_PER_SIZE);
				break;
			case 'adi.':
				MakePER(SecDecryptBuff,SEC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_IDATASectionEncrypt,
						   SecDecryptBuff,
						   SEC_PER_SIZE);
				break;
			case 'ade.':
				MakePER(SecDecryptBuff,SEC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_EDATASectionEncrypt,
						   SecDecryptBuff,
						   SEC_PER_SIZE);
				break;
			case 'rsr.':
				MakePER(SecDecryptBuff,RSRC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_RSRCSectionEncrypt,
						   SecDecryptBuff,
						   RSRC_PER_SIZE);
				break;
			default:
				MakePER(SecDecryptBuff,SEC_PER_SIZE);
				CopyMemory(pDepackerCode+dwRO_SectionEncrypt,
						   SecDecryptBuff,
						   SEC_PER_SIZE);
			}
			//-> en-/decrypt it
			CryptSize=image_section_header[i].SizeOfRawData;
			CryptStart=image_section_header[i].PointerToRawData;
			if(SectionName1!='rsr.')
			{
				EncryptBuff(image_section[i],0,CryptSize);	   
			}
			else
			{
				//EncryptBuff(image_section[i],0,CryptSize);
				ProceedBar=FALSE;
				CryptResourceDirectory(image_section[i],image_section_header[i].VirtualAddress,0);
				ProceedBar=TRUE;
			}
		} 	
	}
}
//----------------------------------------------------------------
//Compress Parameters
#define DICT_LEN		0xbfff
static	lzo_byte		dict [ DICT_LEN ];
static	lzo_uint		dict_len = 0;
static	lzo_uint32		dict_adler32;
int		lzo_err;
int		lzo_level		= 9;
//----------------------------------------------------------------
int rotatorpos = 0;
DWORD infilesize;

int CB_CALLCONV callback(unsigned int inpos, unsigned int outpos)
{
   //printf("\r%c Packing data                 -> %3d%%", rotator[rotatorpos], inpos * 100 / infilesize);
   //rotatorpos = (rotatorpos + 1) & 0x0003;
   SendDlgItemMessage(hwndMain,IDC_PROGRESS1,PBM_SETPOS,DWORD(inpos*100/infilesize),0);
/*#ifdef AP_HAS_CONIO
   // check for ESC-hit
   if (kbhit())
   {
      unsigned char ch = getch();
      if (ch == 0) ch = getch();
      if (ch == 27)
      {
         return (0); // abort packing
      }
   }
#endif*/
   return (1); // continue packing
}
//----------------------------------------------------------------
// Base   = pointer to file memory
// dwMode: 0 - RawCrypt mode
//         1 - VirtualCrypt mode
void PE::CompressPE()
{
	DWORD iSection;
	UCHAR *pIn		= NULL;
	UCHAR *pOut		= NULL;
	UCHAR *wrkmem	= NULL;
	DWORD		dwFsizeIn	= 0;
	DWORD		dwFsizeOut= 0;
	DWORD SectionName1,SectionName2;					
	DWORD SizeVirtualAllocate;
	iSection=0;
	dwDepackCodeVirtualSize=0;
	SendDlgItemMessage(hwndMain,IDC_PROGRESS1,PBM_SETSTEP,1,0);
	SendDlgItemMessage(hwndMain,IDC_PROGRESS1,PBM_SETPOS,0,0);
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections;i++)
	{
		// -> do some special sections !
		CopyMemory(&SectionName1,image_section_header[i].Name,4);
		CopyMemory(&SectionName2,image_section_header[i].Name+4,4);
		if(((SectionName1=='xet.')||				//.text
		    (SectionName1=='EDOC')||				//CODE
		    (SectionName1=='tad.')||				//.data
		    (SectionName1=='ATAD')||				//DATA*/
		    (SectionName1=='SSB' )||				//BSS
			(SectionName1=='adr.')||				//.rdata
		   ((SectionName1=='ade.')&&(!OCXType))||	//.edata
			(SectionName1=='adi.')					//.idata
			//(SectionName1=='slt.')||				//.tls
			//(SectionName1=='rsr.')				//.rsrc
			)&&	
		   (image_section_header[i].PointerToRawData!=0)&&
		   (image_section_header[i].SizeOfRawData!=0))//-> skip also some other sections
		{
			//-> compress it
			if(SectionName1!='rsr.')
			{
				dwFsizeIn=image_section_header[i].SizeOfRawData;
				switch(dwCompressType)
				{
				case 0:
					pIn=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn);
					pOut=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn + dwFsizeIn / 64 + 16 + 3  + 4);
					wrkmem=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,LZO1X_999_MEM_COMPRESS);
					CopyMemory(pIn,image_section[i],dwFsizeIn);
					if((pIn == NULL)||(pOut == NULL)||(wrkmem == NULL))
					{
						//return 0;
					}
					lzo_err = lzo1x_999_compress_level(
										 pIn,dwFsizeIn,
										 pOut,(lzo_uint*)&dwFsizeOut,wrkmem,
								         dict, dict_len, 0, lzo_level);
					FillMemory(image_section[i],dwFsizeIn,0x00);
					CopyMemory(image_section[i]+4,pOut,dwFsizeOut);
					CopyMemory(image_section[i],&dwFsizeIn,4);
					break;

				case 1:
					dwFsizeIn=image_section_header[i].SizeOfRawData;
					pIn=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn);
					pOut=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,aP_max_packed_size(dwFsizeIn));
					wrkmem=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,aP_workmem_size(dwFsizeIn));
					CopyMemory(pIn,image_section[i],dwFsizeIn);
					if((pIn == NULL)||(pOut == NULL)||(wrkmem == NULL))
					{
						//return 0;
					}
					infilesize=dwFsizeIn;
					dwFsizeOut = aPsafe_pack(pIn, pOut, dwFsizeIn, wrkmem, callback);
					FillMemory(image_section[i],dwFsizeIn,0x00);
					CopyMemory(image_section[i],pOut,dwFsizeOut);
					break;
				}
				GlobalFree(wrkmem);
				GlobalFree(pOut);
				GlobalFree(pIn);   
			}
			else
			{
				//EncryptBuff(image_section[i],0,CryptSize);
				dwFsizeOut=dwFsizeIn;
				ProceedBar=FALSE;
				CompressResourceDirectory(image_section[i],image_section_header[i].VirtualAddress,0);
				ProceedBar=TRUE;
			}
			/*if((SectionName1=='xet.')||	//.text
			   (SectionName1=='EDOC'))	//CODE
			{
				CODE_Size=dwFsizeIn;
			}
			if((SectionName1=='tad.')||	//.data
			   (SectionName1=='ATAD'))	//DATA
			{
				DATA_Size=dwFsizeIn;
			}
		    if(SectionName1=='SSB')		//BSS
			{
				BSS_Size=dwFsizeIn;
			}
			if(SectionName1=='adr.')//.rdata
			{
				RDATA_Size=dwFsizeIn;
			}
			if(SectionName1=='adi.')//.idata
			{
				IDATA_Size=dwFsizeIn;
			}
			if(SectionName1=='ade.')//.edata
			{
				EDATA_Size=dwFsizeIn;
			}
			if(SectionName1=='slt.')//.tls
			{
				TLS_Size=dwFsizeIn;
			}
		    if(SectionName1=='rsr.')	//.rsrc
			{
				RSRC_Size=dwFsizeIn;
			}*/
			iSection++;
			image_section_header[i].SizeOfRawData=
				PEAlign(dwFsizeOut+4,
				image_nt_headers.OptionalHeader.FileAlignment);
			SizeVirtualAllocate = image_section_header[i].SizeOfRawData;
			SizeVirtualAllocate = PEAlign(SizeVirtualAllocate + SizeVirtualAllocate / 64 + 16 + 3  + 4,
				image_nt_headers.OptionalHeader.SectionAlignment);
			if(dwDepackCodeVirtualSize<SizeVirtualAllocate) dwDepackCodeVirtualSize=SizeVirtualAllocate;
		}
		if(i!=0)
		{
			DWORD newPointerToRawData=image_section_header[i-1].SizeOfRawData;
			newPointerToRawData=newPointerToRawData+image_section_header[i-1].PointerToRawData;
			//newPointerToRawData=PEAlign(newPointerToRawData,
			//		image_nt_headers.OptionalHeader.SectionsAlignment);
			//		PEAlign(newPointerToRawData,0x100)+image_section_header[i-1].PointerToRawData;
			if(newPointerToRawData!=0)
			{
				image_section_header[i].PointerToRawData=newPointerToRawData;
			}
		}
		else image_section_header[i].PointerToRawData=
			PEAlign(image_section_header[i].PointerToRawData,
			image_nt_headers.OptionalHeader.FileAlignment);
	}
}
//----------------------------------------------------------------

void PE::CryptResourceDirectory(char* Base,DWORD dwBaseRVA,DWORD dwRVA)
{
	DWORD i,dwOffSet;
	IMAGE_RESOURCE_DIRECTORY		directory;
	IMAGE_RESOURCE_DIRECTORY_ENTRY	directory_entries;
	IMAGE_RESOURCE_DATA_ENTRY		data_entry;
	CopyMemory(&directory,
		       Base+dwRVA,
			   sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (i=0;i<directory.NumberOfIdEntries;i++)
	{
		CopyMemory(&directory_entries,
			       Base+dwRVA+sizeof(IMAGE_RESOURCE_DIRECTORY)+i*8,
				   sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
		if(directory_entries.DataIsDirectory)
		{
			if((directory_entries.Id==ID_RT_CURSOR		)||
			   (directory_entries.Id==ID_RT_BITMAP		)||
			   //(directory_entries.Id==ID_RT_ICON		)||
			   (directory_entries.Id==ID_RT_MENU		)||
			   (directory_entries.Id==ID_RT_DIALOG		)||
			   (directory_entries.Id==ID_RT_STRING		)||
			   (directory_entries.Id==ID_RT_FONTDIR		)||
			   (directory_entries.Id==ID_RT_FONT		)||
			   (directory_entries.Id==ID_RT_ACCELERATOR	)||
			   (directory_entries.Id==ID_RT_RCDATA		)||
			   (directory_entries.Id==ID_RT_MESSAGETABLE)||
			   (directory_entries.Id==ID_RT_GROUP_CURSOR)||
			   //(directory_entries.Id==ID_RT_GROUP_ICON)||
			   //(directory_entries.Id==ID_RT_VERSION		)||
			   (directory_entries.Id>32))
			{
				CryptResourceDirectory(Base,dwBaseRVA,directory_entries.OffsetToDirectory);
			}
		}
		else
		{
			CopyMemory(&data_entry,
						Base+directory_entries.OffsetToData,
						sizeof(IMAGE_RESOURCE_DATA_ENTRY));
			dwOffSet=data_entry.OffsetToData-dwBaseRVA;
			EncryptBuff(Base,dwOffSet,data_entry.Size);
			/*for(j=0;j<data_entry.Size;j++)
			{
				UCHAR tmp;
				
				CopyMemory(&tmp,Base+dwOffSet+j,1);
				tmp=tmp^0x55;
				CopyMemory(Base+dwOffSet+j,&tmp,1);
			}*/
		}
	}
}
//----------------------------------------------------------------
void PE::CompressResourceDirectory(char* Base,DWORD dwBaseRVA,DWORD dwRVA)
{
	UCHAR *pIn		= NULL;
	UCHAR *pOut		= NULL;
	UCHAR *wrkmem	= NULL;
	DWORD		dwFsizeIn	= 0;
	DWORD 		dwFsizeOut	= 0;

	DWORD i,dwOffSet;
	IMAGE_RESOURCE_DIRECTORY		directory;
	IMAGE_RESOURCE_DIRECTORY_ENTRY	directory_entries;
	IMAGE_RESOURCE_DATA_ENTRY		data_entry;
	CopyMemory(&directory,
		       Base+dwRVA,
			   sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (i=0;i<directory.NumberOfIdEntries;i++)
	{
		CopyMemory(&directory_entries,
			       Base+dwRVA+sizeof(IMAGE_RESOURCE_DIRECTORY)+i*8,
				   sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
		if(directory_entries.DataIsDirectory)
		{
			if((directory_entries.Id==ID_RT_CURSOR		)||
			   (directory_entries.Id==ID_RT_BITMAP		)||
			   //(directory_entries.Id==ID_RT_ICON		)||
			   (directory_entries.Id==ID_RT_MENU		)||
			   (directory_entries.Id==ID_RT_DIALOG		)||
			   (directory_entries.Id==ID_RT_STRING		)||
			   (directory_entries.Id==ID_RT_FONTDIR		)||
			   (directory_entries.Id==ID_RT_FONT		)||
			   (directory_entries.Id==ID_RT_ACCELERATOR	)||
			   (directory_entries.Id==ID_RT_RCDATA		)||
			   (directory_entries.Id==ID_RT_MESSAGETABLE)||
			   (directory_entries.Id==ID_RT_GROUP_CURSOR)||
			   //(directory_entries.Id==ID_RT_GROUP_ICON)||
			   //(directory_entries.Id==ID_RT_VERSION		)||
			   (directory_entries.Id>32))
			{
				CompressResourceDirectory(Base,dwBaseRVA,directory_entries.OffsetToDirectory);
			}
		}
		else
		{
			CopyMemory(&data_entry,
						Base+directory_entries.OffsetToData,
						sizeof(IMAGE_RESOURCE_DATA_ENTRY));
			dwOffSet=data_entry.OffsetToData-dwBaseRVA;
			//EncryptBuff(Base,dwOffSet,data_entry.Size);
			/*for(j=0;j<data_entry.Size;j++)
			{
				UCHAR tmp;
				
				CopyMemory(&tmp,Base+dwOffSet+j,1);
				tmp=tmp^0x55;
				CopyMemory(Base+dwOffSet+j,&tmp,1);
			}*/
			dwFsizeIn=data_entry.Size;
				switch(dwCompressType)
				{
				case 0:
					pIn=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn);
					pOut=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn + dwFsizeIn / 64 + 16 + 3  + 4);
					wrkmem=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,LZO1X_999_MEM_COMPRESS);
					CopyMemory(pIn,image_section[i],dwFsizeIn);
					if((pIn == NULL)||(pOut == NULL)||(wrkmem == NULL))
					{
						//return 0;
					}
					lzo_err = lzo1x_999_compress_level(
										 pIn,dwFsizeIn,
										 pOut,(lzo_uint*)&dwFsizeOut,wrkmem,
								         dict, dict_len, 0, lzo_level);
					FillMemory(image_section[i],dwFsizeIn,0x00);
					CopyMemory(image_section[i],pOut,dwFsizeOut);
					break;

				case 1:
					dwFsizeIn=image_section_header[i].SizeOfRawData;
					pIn=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwFsizeIn);
					pOut=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,aP_max_packed_size(dwFsizeIn));
					wrkmem=(UCHAR*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,aP_workmem_size(dwFsizeIn));
					CopyMemory(pIn,image_section[i],dwFsizeIn);
					if((pIn == NULL)||(pOut == NULL)||(wrkmem == NULL))
					{
						//return 0;
					}
					dwFsizeOut = aPsafe_pack(pIn, pOut, dwFsizeIn, wrkmem, callback);
					FillMemory(image_section[i],dwFsizeIn,0x00);
					CopyMemory(image_section[i],pOut,dwFsizeOut);
					break;
				}
			GlobalFree(wrkmem);
			GlobalFree(pOut);
			GlobalFree(pIn);   
		}
	}
}
//----------------------------------------------------------------
// return values:
// 0 - no room for a new section
// 1 - file already encrypted
// else: returns a pointer to the IMAGE_SECTION_HEADER struct of the new section
PIMAGE_SECTION_HEADER PE::AddSection()
{
	DWORD newSectionOffset;
	DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
	newSectionOffset=dwRO_first_section
		+image_nt_headers.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);

	// check whether there's room for a new section
	if(image_nt_headers.OptionalHeader.SizeOfHeaders<(newSectionOffset+sizeof(IMAGE_SECTION_HEADER)))
	{
		return NULL;
	}

	// create a new section

	// go to the last section
	for(DWORD i=0;i<SectionNum;i++)
	{
		image_section_header[i].Characteristics=0xC0000040;
			//image_section_header[i].Characteristics | IMAGE_SCN_MEM_WRITE;
	}

	// start to build the new section
	CopyMemory(&image_section_header[SectionNum],
			   &image_section_header[SectionNum-1],
			   sizeof(IMAGE_SECTION_HEADER));

	// VirtualAddress...
	image_section_header[SectionNum].VirtualAddress
		=PEAlign(image_section_header[SectionNum-1].VirtualAddress+
		         image_section_header[SectionNum-1].Misc.VirtualSize,
				 image_nt_headers.OptionalHeader.SectionAlignment);
	image_section_header[SectionNum].Misc.VirtualSize=0x4000;

	// RawSize..
	image_section_header[SectionNum].SizeOfRawData=IT_SIZE+DEPACKER_CODE_SIZE;

	// Section name
	int l=(int)strlen(DEPACKER_SECTION_NAME);
	FillMemory(image_section_header[SectionNum].Name,8,0x00);
	CopyMemory(image_section_header[SectionNum].Name,DEPACKER_SECTION_NAME,l);
	CopyMemory(&dwDEPACKER_SECTION_NAME,DEPACKER_SECTION_NAME,4);

	// Characteristics
	image_section_header[SectionNum].Characteristics=0xC0000040;
		/*IMAGE_SCN_MEM_WRITE|
		IMAGE_SCN_MEM_READ|
		IMAGE_SCN_MEM_EXECUTE|
		IMAGE_SCN_CNT_UNINITIALIZED_DATA |
		IMAGE_SCN_CNT_INITIALIZED_DATA|
		IMAGE_SCN_CNT_CODE;//0xE00000E0;*/

	// RawOffset
	image_section_header[SectionNum].PointerToRawData
		=PEAlign(image_section_header[SectionNum-1].PointerToRawData
				+image_section_header[SectionNum-1].SizeOfRawData,
				image_nt_headers.OptionalHeader.FileAlignment);

	// update the PE header
	image_nt_headers.FileHeader.NumberOfSections++;
	// newsection -> will be returned
	return ((PIMAGE_SECTION_HEADER)&image_section_header[SectionNum]);
}
//----------------------------------------------------------------
// return values:
// 0 - no room for a new section
// 1 - file already encrypted
// else: returns a pointer to the IMAGE_SECTION_HEADER struct of the new section
void PE::RemoveSection(char* SectionName)
{
	// create a new section
	DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
	#ifdef _VC6LINKER
		#ifdef _DEBUG
			char *namesec=new TCHAR[9];
		#else
			char *namesec=new TCHAR[9];
		#endif
	#else
		#ifdef _DEBUG
			char* namesec=(CHAR*)LocalAlloc(LMEM_MOVEABLE|LMEM_ZEROINIT,9);
		#else 
			char namesec[9];
		#endif
	#endif
	DWORD SectionCatch;
	DWORD i;
	namesec[0]=0x00;
	// go to the last section
	for(i=0;i<SectionNum;i++)
	{
		CopyMemory(namesec,image_section_header[i].Name,8);
		namesec[9]=0x00;
		if(strcmp(namesec,SectionName)==0)
		{
			SectionCatch=i;
			break;
		}
		if((SectionNum-1)==i) 
		{
			#ifndef _VC6LINKER
				#ifdef _DEBUG
					LocalFree(namesec);
				#endif
			#endif
			return;
		}
	}
	if(SectionCatch<(SectionNum-1))
	{
		for(i=SectionCatch;i<(SectionNum-1);i++)
		{
			CopyMemory(&image_section_header[i],
				       &image_section_header[i+1],
					   sizeof(IMAGE_SECTION_HEADER));
		}
		FillMemory(&image_section_header[SectionNum-1],
					sizeof(IMAGE_SECTION_HEADER),0x00);
	}
	else
	{
		FillMemory(&image_section_header[SectionCatch],
					sizeof(IMAGE_SECTION_HEADER),0x00);
	}
	image_nt_headers.FileHeader.NumberOfSections--;
	#ifndef _VC6LINKER
		#ifdef _DEBUG
			LocalFree(namesec);
		#endif
	#endif
	SectionNum=image_nt_headers.FileHeader.NumberOfSections;
	for(i=1;i<SectionNum-1;i++)
	{
		image_section[i]=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,
			PEAlign(image_section_header[i].SizeOfRawData,
			image_nt_headers.OptionalHeader.FileAlignment));
		CopyMemory(image_section[i],
				pMem+image_section_header[i].PointerToRawData,
				image_section_header[i].SizeOfRawData);
		image_section_header[i].Misc.VirtualSize=
			image_section_header[i+1].VirtualAddress-
			image_section_header[i].VirtualAddress;
	}
	image_section_header[SectionNum-1].Misc.VirtualSize=
		PEAlign(image_section_header[SectionNum-1].Misc.VirtualSize,
		image_nt_headers.OptionalHeader.SectionAlignment);
	image_nt_headers.OptionalHeader.SizeOfImage=
		image_section_header[SectionNum-1].VirtualAddress+
		image_section_header[SectionNum-1].Misc.VirtualSize;	
	for(i=0;i<SectionNum;i++)
	{
		image_section[i]=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,
			PEAlign(image_section_header[i].SizeOfRawData,
			image_nt_headers.OptionalHeader.FileAlignment));
		CopyMemory(image_section[i],
				pMem+image_section_header[i].PointerToRawData,
				image_section_header[i].SizeOfRawData);
	}
}
//----------------------------------------------------------------
void PE::RemoveSectionNames()
{
	char szName[9];
	int i;
	szName[8]=0;
	for(i=0;i<image_nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&SectionNames[i],image_section_header[i].Name,8);
	}
	for(i=0;i<image_nt_headers.FileHeader.NumberOfSections-1;i++)
	{
		CopyMemory(szName,image_section_header[i].Name,8);
		if(strcmp(szName,".rsrc")!=0)
		{
			FillMemory(image_section_header[i].Name,8,0x00);
		}
	}
}
//----------------------------------------------------------------
void PE::Free()
{
	DWORD SectionNum=image_nt_headers.FileHeader.NumberOfSections;
	for(DWORD i=0;i<SectionNum;i++)
	{
		GlobalFree(image_section[i]);
	}
	GlobalFree(pMem);
	CloseHandle(hFile);
}


//----------------------------------------------------------------
bool PE::CheckifProtect()
{
	DWORD SectionName1,SectionName2;
	int pSec=0;
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections-1;i++)
	{
		CopyMemory(&SectionName1,image_section_header[i].Name,4);
		CopyMemory(&SectionName2,image_section_header[i].Name+4,4);
		if(((SectionName1==0)&&(SectionName2==0))||
		   ((SectionName1=='rsr.')&&(SectionName2=='c')))
		{
			pSec++;
		}
	}
	if(pSec==(image_nt_headers.FileHeader.NumberOfSections-1))
	{
		return(TRUE);
	}
	return(FALSE);
}

//----------------------------------------------------------------
bool PE::CheckifSectionName()
{
	DWORD SectionName1,_SectionName1;
	int pSec=0;
	CopyMemory(&_SectionName1,DEPACKER_SECTION_NAME,4);
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections-1;i++)
	{
		CopyMemory(&SectionName1,image_section_header[i].Name,4);
		if(SectionName1==_SectionName1)
		{
			return(TRUE);
		}
	}
	return(FALSE);
}
//----------------------------------------------------------------
bool PE::CheckifPEvalid()
{
	DWORD SectionName1,SectionName2;
	int pSec=0;
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&SectionName1,image_section_header[i].Name,4);
		CopyMemory(&SectionName2,image_section_header[i].Name+4,4);
		if ((SectionName1=='cra.')||	//.arch	,Alpha architecture information
			(SectionName1=='xet.')||	//.text	,Executable code
		    (SectionName1=='EDOC')||	//CODE	,Executable code
		    (SectionName1=='tad.')||	//.data	,Initialized data
		    (SectionName1=='ATAD')||	//DATA	,Initialized data
			(SectionName1=='ssb.')||	//.bss	,Uninitialized data
		    (SectionName1=='SSB')||		//BSS	,Uninitialized data
			(SectionName1=='ade.')||	//.edata,Export tables
			(SectionName1=='adi.')||	//.idata,Import tables
			(SectionName1=='adp.')||	//.pdata,Exception information
			(SectionName1=='adx.')||	//.xdata,Exception information
			(SectionName1=='adr.')||	//.rdata,Read-only
			(SectionName1=='ler.')||	//.reloc,Image relocations
			(SectionName1=='oler')||	//reloc	,Image relocations
			(SectionName1=='did.')||	//.didat
			(SectionName1=='slt.')||	//.tls	,Thread-local storage
			(SectionName1=='bed.')||	//.debug,Debug information,
			(SectionName1=='rsr.'))		//.rsrc	,Resource directory
		{
			pSec++;
		}
	}
	if(pSec==image_nt_headers.FileHeader.NumberOfSections)
	{
		return(TRUE);
	}
	return(FALSE);
}
//----------------------------------------------------------------
DWORD PE::GetSectionNume(char* targetSectionName)
{
	char SectionName[9];
	SectionName[8]=0;
	DWORD dwSectionNum=0;
	for(int i=0;i<image_nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&SectionName,image_section_header[i].Name,8);
		if(!strcmp(SectionName,targetSectionName))
		{
			dwSectionNum=i;
			break;
		}
	}
	return(dwSectionNum);
}
//----------------------------------------------------------------
bool PE::CheckifSYS()
{
	if((image_nt_headers.FileHeader.Characteristics&IMAGE_FILE_SYSTEM)==IMAGE_FILE_SYSTEM)
	{
		return(TRUE);
	}
	return(FALSE);
}
//----------------------------------------------------------------
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
#define IMAGE_DLLCHARACTERISTICS_NO_SEH      0x0400     // Image does not use SEH.  No SE handler may reside in this image
#endif

#ifndef IMAGE_DLLCHARACTERISTICS_NO_BIND
#define IMAGE_DLLCHARACTERISTICS_NO_BIND     0x0800     // Do not bind this image.
#endif

#ifndef	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000
#endif

DWORD PE::CheckifDLL()
{
	if((image_nt_headers.FileHeader.Characteristics&IMAGE_FILE_DLL)==IMAGE_FILE_DLL)
	{
		DWORD dwDllCharacter=image_nt_headers.OptionalHeader.DllCharacteristics;
		if((dwDllCharacter&IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
			 ==IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
		{
			ShowErr(TServernotSupport);
			return(2);
		}
			
		if((dwDllCharacter&IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
			 ==IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
		{
			ShowErr(WDMnotSupport);
			return(2);
		}

		if((dwDllCharacter&IMAGE_DLLCHARACTERISTICS_NO_SEH)
			 ==IMAGE_DLLCHARACTERISTICS_NO_SEH)
		{
			ShowErr(NOSEHnotSupport);
			return(2);
		}

		if((dwDllCharacter&IMAGE_DLLCHARACTERISTICS_NO_BIND)
			 ==IMAGE_DLLCHARACTERISTICS_NO_BIND)
		{
			ShowErr(NOBINDnotSupport);
			return(2);
		}
		OCXType=TRUE;
		PROTECTION_FLAGS=PROTECTION_FLAGS|OCX_TYPE_FLAG;
		return(1);
	}
	OCXType=FALSE;
	return(0);
}

bool PE::CheckifVCM2()
{
	if((image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress!=0)&&
	   (image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size!=0))
	{
		return(TRUE);
	}
	return(FALSE);
}
//----------------------------------------------------------------
bool PE::CheckCOMRuntime()
{
	if(image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress!=0)
	{
		return(TRUE);
	}
	return(FALSE);
}
//----------------------------------------------------------------
void PE::OptimizeDOSHeader()
{
	UpdateHeaders(TRUE);
	image_dos_header.e_cblp		= 0x0092;
	image_dos_header.e_cp		= 0x0003;
	image_dos_header.e_crlc		= 0x0000;
	image_dos_header.e_cparhdr	= 0x0004;
	image_dos_header.e_minalloc	= 0x0000;
	image_dos_header.e_lfanew	= 0x000C;
	image_nt_headers.OptionalHeader.BaseOfData=image_dos_header.e_lfanew;
	FillMemory(pMem,image_nt_headers.OptionalHeader.SizeOfHeaders,0x00);
	UpdateHeaders(FALSE);
}
//----------------------------------------------------------------
void PE::EliminateDOSHeader()
{
	UpdateHeaders(TRUE);
	image_dos_header.e_cblp		= 0x0040;
	image_dos_header.e_cp		= 0x0001;
	image_dos_header.e_crlc		= 0x0000;
	image_dos_header.e_cparhdr	= 0x0002;
	image_dos_header.e_minalloc	= 0x0004;
	image_dos_header.e_maxalloc	= 0xFFFF;
	image_dos_header.e_ss		= 0x0002;
	image_dos_header.e_sp		= 0x0040;
	image_dos_header.e_csum		= 0x0000;
	image_dos_header.e_ip		= 0x000E;
	image_dos_header.e_cs		= 0x0000;
	image_dos_header.e_lfarlc	= 0x001C;
	image_dos_header.e_ovno		= 0x0000;
	image_dos_header.e_res[0]	= 0x0000;
	image_dos_header.e_res[1]	= 0x0000;
	image_dos_header.e_res[2]	= 0x6957;
	image_dos_header.e_res[3]	= 0x336E;
	image_dos_header.e_oemid	= 0x2032;
	image_dos_header.e_oeminfo	= 0x6E6F;
	image_dos_header.e_res2[0]	= 0x796C;
	image_dos_header.e_res2[1]	= 0x0D21;
	image_dos_header.e_res2[2]	= 0x240A;
	image_dos_header.e_res2[3]	= 0xB40E;
	image_dos_header.e_res2[4]	= 0xBA09;
	image_dos_header.e_res2[5]	= 0x0000;
	image_dos_header.e_res2[6]	= 0xCD1F;
	image_dos_header.e_res2[7]	= 0xB821;
	image_dos_header.e_res2[8]	= 0x4C01;
	image_dos_header.e_res2[9]	= 0x21CD;
	image_dos_header.e_lfanew	= 0x40;
	FillMemory(pMem,image_nt_headers.OptionalHeader.SizeOfHeaders,0x00);
	UpdateHeaders(FALSE);
}
void PE::EliminateReloc()
{
	UpdateHeaders(TRUE);
	image_nt_headers.FileHeader.Characteristics=
	image_nt_headers.FileHeader.Characteristics|IMAGE_FILE_RELOCS_STRIPPED;
	image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=0; 
	image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=0;
	RemoveSection(".reloc");
	RemoveSection("reloc");
	UpdateHeaders(FALSE);
}
void PE::EliminateDebug()
{
	UpdateHeaders(TRUE);
	image_nt_headers.FileHeader.Characteristics=
	image_nt_headers.FileHeader.Characteristics|IMAGE_FILE_DEBUG_STRIPPED;
	image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress=0; 
	image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size=0;
	RemoveSection(".debug");
	UpdateHeaders(FALSE);
}