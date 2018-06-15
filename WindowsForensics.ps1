#Profile folder from disk
$PList=(Get-ChildItem $env:userprofile\.. | select fullname)
$PList

#SID from registry
get-childitem "HKLM:\SOFTWARE\Microsoft\windows NT\CurrentVersion\ProfileList" | select name

#Terminal Services
Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -Recurse | select PSChildName

$Plist = (Get-ChildItem $env:userprofile\.. | select fullname)
foreach ($pi in $PList)
{
    $d=$pi.FullName
    if ($d -ne $env:userprofile)
    {
        write-host "checking $d.."
        reg load HKLM\TempUserCSI $d\ntuser.dat > $null
        if(Test-Path "HKLM:\TempUserCSI\Software\Microsoft\Terminal Server Client\Servers")
        {
            Get-ChildItem "HKLM:\TempUserCSI\Software\Microsoft\Terminal Server Client\Server" -Recurse | select PSChildName

        }
        [gc]::collect()
        reg unload HKLM\TempUserCSI > $null
     }
}


#Win+R
Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

#mmc
Get-ItemProperty -path "HKCU:\Software\Microsoft\Microsoft Management Console\Recent File List"

#paint
Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List"


#recent files
$d=(Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folder" -name recent
Get-ChildItem $d | $ort-object lastwritetime

#prefetch
$pf=(Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
write-host $pf

#contains files
Get-ChildItem $env:windir\prefetch\

#analyse files
foreach ($file in (dir "C:\Windows\Prefetch\notepa*.pf"))
{
	$cmd="C:\tools\pf64.exe "$file " -v"
	write-host $cmd
	Start-Process -FilePath "cmd.exe" -ArgumentList ("/k "+$cmd)
}



#Windows Indexing shadow copy
$s1 = (gwmi -List Win32_ShadowCopy).Create("C:\","ClientAccessible")
$s2 = gwmi Win32_ShadowCopy | ? { $_.ID -eq $s1.ShadowID }
$d = $s2.DeviceObject + "\"
cmd /c mklink /d C:\shadowcopy "$d"


#Recent internet cache
#StructureStrogeViewer
#C:\user\name\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestination\

#remoteDesktop Cache
#C:\User\name\AppData\Local\Microsoft\Terminal Server Client\Cache\.bin


#IMPmemoryAnalysis
#Handles
#volitility.py pslist/psscan
