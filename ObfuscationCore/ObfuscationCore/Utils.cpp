#include "StdAfx.h"
#include "Utils.h"

namespace Utils
{
    // returns aligned value
    DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo)
    {	
        DWORD dwtemp;
        dwtemp=dwTarNum/dwAlignTo;
        if((dwTarNum%dwAlignTo)!=0)
        {
            dwtemp++;
        }
        dwtemp=dwtemp*dwAlignTo;
        return(dwtemp);
    }
}
