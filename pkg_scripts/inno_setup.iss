; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{263C2558-FE6F-4DC9-B05E-D01310AB033F}
AppName=Loki
AppVersion=0.3.0
;AppVerName=Loki 0.3.0
AppPublisher=Daniel Mende
AppPublisherURL=http://www.c0decafe.de
AppSupportURL=http://www.c0decafe.de
AppUpdatesURL=http://www.c0decafe.de
DefaultDirName={pf}\Loki
DefaultGroupName=Loki
AllowNoIcons=yes
LicenseFile=C:\loki_temp\trunk\LICENSE
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "C:\loki_temp\out\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "C:\loki_temp\deps\vcredist_x86.exe"; DestDir: "{tmp}"
Source: "C:\loki_temp\deps\WinPcap_4_1_2.exe"; DestDir: "{tmp}"
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\Loki"; Filename: "{app}\loki_gtk.exe"
Name: "{group}\{cm:UninstallProgram,Loki}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\Loki"; Filename: "{app}\loki_gtk.exe"; Tasks: desktopicon

[Run]
Filename: "{tmp}\vcredist_x86.exe"; Parameters: "/qb"
Filename: "{tmp}\WinPcap_4_1_2.exe"
;Filename: "{app}\loki_gtk.exe"; Description: "{cm:LaunchProgram,Loki}"; Flags: nowait postinstall skipifsilent

