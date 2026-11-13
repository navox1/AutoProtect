[Setup]
AppName=Mini Antivirus
AppVersion=1.0
DefaultDirName={autopf}\MiniAntivirus
DefaultGroupName=Mini Antivirus
OutputDir=Output
OutputBaseFilename=setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "dist\antivirus.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "signatures.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\Mini Antivirus (terminal)"; Filename: "{cmd}"; Parameters: "/k cd /d ""{app}"" && antivirus.exe"; WorkingDir: "{app}"
