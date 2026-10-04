; nScout Windows installer - built with Inno Setup 6
#define MyAppName "nScout"
#define MyAppVersion GetEnv("NSCOUT_VERSION")
#if MyAppVersion == ""
  #define MyAppVersion "0.2.0"
#endif
#define MyAppPublisher "nScout"
#define MyAppExeName "nScout.exe"

[Setup]
AppId={{A41D4A6E-877D-4E44-B957-52F11E39A9B1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\nScout
DefaultGroupName=nScout
DisableProgramGroupPage=yes
OutputDir=..\installer-output
OutputBaseFilename=nScout-Setup-{#MyAppVersion}-windows-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
SetupIconFile=..\frontend\public\favicon.ico
UninstallDisplayIcon={app}\nScout.exe
; Windows file-version metadata must be numeric. Keep the human-readable
; AppVersion above for dev/release labels such as 0.2.0-dev.
VersionInfoVersion=0.2.0.0
VersionInfoProductName=nScout
VersionInfoDescription=nScout Network Monitor
VersionInfoCompany=nScout

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\nScout\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\nScout"; Filename: "{app}\nScout.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\nScout"; Filename: "{app}\nScout.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\nScout.exe"; Description: "Launch nScout"; Flags: nowait postinstall skipifsilent
