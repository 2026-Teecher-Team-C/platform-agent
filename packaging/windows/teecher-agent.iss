; packaging/windows/teecher-agent.iss
; ISCC /DAppVersion=0.1.0 packaging\windows\teecher-agent.iss  →  dist\teecher-agent-setup.exe
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{8C7E3B0E-5F0A-4C55-9B7E-7A1D2C3E4F50}
AppName=Teecher Agent
AppVersion={#AppVersion}
AppPublisher=Teecher Team C
DefaultDirName={autopf}\Teecher Agent
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=teecher-agent-setup
WizardStyle=modern
; 토큰이 매개변수로 넘어가므로 Inno 자체 로그를 끈다. 설치 단계 기록은 teecher-agent의 --log-file이 남긴다
SetupLogging=no
UninstallDisplayName=Teecher Agent
CloseApplications=yes

[Languages]
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"

[Files]
Source: "..\..\dist\teecher-agent\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\agent.conf"; DestDir: "{app}"; Flags: ignoreversion

[UninstallRun]
; 제거기는 관리자 권한으로 돈다. 관리자 계정 본인이 설치한 경우 HKCU·작업·자격 증명도 같은 사용자 것이다(스펙 2.1)
Filename: "{app}\teecher-agent.exe"; Parameters: "uninstall --phase activate"; Flags: runhidden waituntilterminated; RunOnceId: "TeecherActivate"
Filename: "{app}\teecher-agent.exe"; Parameters: "uninstall --phase trust"; Flags: runhidden waituntilterminated; RunOnceId: "TeecherTrust"
Filename: "{app}\teecher-agent.exe"; Parameters: "uninstall --phase prepare"; Flags: runhidden waituntilterminated; RunOnceId: "TeecherPrepare"

[Code]
var
  TokenPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  TokenPage := CreateInputQueryPage(wpSelectDir,
    '에이전트 등록', '관리 콘솔에서 발급한 등록 토큰을 입력하세요.',
    '이미 등록된 PC를 다시 설치하는 경우에는 비워 둬도 됩니다.');
  TokenPage.Add('등록 토큰:', True);
end;

function LogPath: String;
begin
  Result := ExpandConstant('{%TEMP}\teecher-install.log');
end;

function RunPhase(Args: String; AsUser: Boolean): Boolean;
var
  Code: Integer;
  Exe, Params: String;
begin
  Exe := ExpandConstant('{app}\teecher-agent.exe');
  Params := '--log-file "' + LogPath + '" ' + Args;
  if AsUser then
    Result := ExecAsOriginalUser(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code)
  else
    Result := Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Result and (Code = 0);
end;

procedure Rollback;
begin
  RunPhase('uninstall --phase activate', True);
  RunPhase('uninstall --phase trust', False);
  RunPhase('uninstall --phase prepare', True);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { 업그레이드: 실행 중인 에이전트를 먼저 끝내야 파일이 잠기지 않고, 설치 후 새 바이너리로 다시 뜬다. 작업이 없어도 실패는 무시한다 }
  Exec('schtasks', '/End /TN TeecherAgent', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec('taskkill', '/F /IM teecher-agentw.exe /T', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    Exit;
  { 프록시(HKCU)·작업·키체인은 사용자 것이라 원래 사용자로, CA 신뢰(LocalMachine)는 관리자로 부른다 }
  if RunPhase('install --phase prepare --enrollment-token "' + TokenPage.Values[0] + '"', True)
     and RunPhase('install --phase trust', False)
     and RunPhase('install --phase activate', True) then
    Exit;
  Rollback;
  SuppressibleMsgBox('설치를 마치지 못해 시스템 설정을 원래대로 되돌렸습니다.' + #13#10 +
         '기록: ' + LogPath + #13#10 +
         '설정 → 앱에서 Teecher Agent를 제거한 뒤 다시 설치하세요.', mbError, MB_OK, IDOK);
end;
