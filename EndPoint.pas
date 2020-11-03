{*******************************************************}
{                                                       }
{      Copyright(c) 2003-2019 Oamaru Group , Inc.       }
{                                                       }
{   Copyright and license exceptions noted in source    }
{                                                       }
{*******************************************************}
unit EndPoint;

interface

uses
  System.Classes, System.SysUtils, System.IoUtils, System.JSON, WinApi.Windows,
  WinApi.PsAPI, WinApi.TlHelp32, WinApi.Messages, System.Generics.Collections,
  Vcl.Dialogs, WinApi.WinSvc, Vcl.SvcMgr,
  IdServerIOHandler, IdGlobal, IdSSLOpenSSL, IdBaseComponent, IdComponent,
  IdCustomTCPServer, IdTCPServer, IdUDPBase, IdUDPServer,IdSocketHandle,
  IdCustomHTTPServer, IdHTTPServer, IdContext, IdCoderMIME;

const
  PROCESS_NAME_NATIVE = $00000001;

type
  TEndPoint = class
  protected
    { Protected declarations }
    FIP: String;
    FPort: WORD;
    FServer: TIdHttpServer;
    function GetIsStarted: Boolean;
    function GetServices: String;
    function GetServicesFromRegistry: String;
    procedure ProcessGet(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    function WriteToEventLog: String;
  public
    { Public declarations }
    constructor Create(AIP: String; APort: WORD);
    destructor Destroy; override;
    function Start: Boolean;
    procedure Stop;
    property Started: Boolean read GetIsStarted;
  end;

function QueryFullProcessImageName(hProcess: THandle; dwFlags: DWORD; lpExeName: LPWSTR; var lpdwSize: DWORD): BOOL; stdcall;
function SIDToStr(Input:PSID):string;
function GetSID(var UserName, DomainName: String): String;
function GetLoggedInDomain: String;
function GetLoggedInUserName: String;
function GetProcessList: TStrings;
function GetProcessName(PID: DWORD): String;

implementation

function QueryFullProcessImageName(hProcess: THandle; dwFlags: DWORD; lpExeName: LPWSTR; var lpdwSize: DWORD): BOOL; external 'kernel32.dll' name 'QueryFullProcessImageNameW';

var
  LGUidString: String;

function GetProcessName(PID: DWORD): String;
begin
  if (0 = PID) then
  begin
    Result := 'System Process';
    EXIT;
  end;
  var LBuffSize: DWORD := MAX_PATH;

  var LProc := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, FALSE, PID);

  if 0 <> LProc then
  begin
    var LBuffer: PChar := AllocMem((LBuffSize + 1) * Sizeof(Char));
    try
      if FALSE = QueryFullProcessImageName(LProc, PROCESS_NAME_NATIVE, LBuffer, LBuffSize) then
      begin
        var LErr := GetLastError;
        Result := String.Format('%d - %s', [LErr, SysErrorMessage(LErr)]);
      end else
      begin
        Result := String(LBuffer);
      end;
      CloseHandle(LProc);
    finally
      FreeMem(LBuffer);
    end;
  end else
  begin
    var LErr := GetLastError;
    Result := String.Format('%d - %s', [LErr, SysErrorMessage(LErr)]);
  end;
end;

function GetProcessList: TStrings;
var
  dwReturn     : DWORD;
  OS           : TOSVersionInfo;
  // EnumProcesses
  PidProcesses : PDWORD;
  PidWork      : PDWORD;
  BufferSize   : Cardinal;
  Needed       : DWORD;
  cntProcesses : Cardinal;
  // CreateToolhelp32Snapshot
  hProcSnapShot: THandle;
  pe32         : TProcessEntry32;
begin
  Result := TStringList.Create;
  dwReturn := 0;

  // make the snapshot
  //hProcSnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  hProcSnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

  if hProcSnapShot <> INVALID_HANDLE_VALUE then
  begin
    pe32.dwSize := sizeof(TProcessEntry32);

    if Process32First(hProcSnapShot, pe32) then
    begin
      // first process
      Result.Add(String.Format('%s (pid: %d)',[ GetProcessName(pe32.th32ProcessID), pe32.th32ProcessID]));
      // walk the processes
      while Process32Next(hProcSnapShot, pe32) do
        Result.Add(String.Format('%s (pid: %d)',[ String(pe32.szExeFile), pe32.th32ProcessID]));
    end
    else // Process32First = False
      dwReturn := GetLastError;
    CloseHandle(hProcSnapShot);
  end
  else // hSnapShot = INVALID_HANDLE_VALUE
    dwReturn := GetLastError;
end;

function GetLoggedInUserName: String;
var
  pNameBuff: PChar;
  dwNameBuffSize: DWORD;
begin
  dwNameBuffSize := 0;
  GetUserName(nil, dwNameBuffSize);
  if ERROR_INSUFFICIENT_BUFFER = GetLastError then
  begin
    GetMem(pNameBuff, dwNameBuffSize * Sizeof(Char));
    try
      if GetUserName(pNameBuff, dwNameBuffSize) then
        Result := String(pNameBuff)
      else
        RaiseLastOSError;
    finally
      FreeMem(pNameBuff);
    end;
  end
  else
    RaiseLastOSError;
end;

function GetLoggedInDomain: String;
var
  SNU                : SID_NAME_USE;
  SID                : PSID;
  dwSidSize          : DWORD;
  pNameBuff          : array[0..80] of Char;
  dwNameBuffSize     : DWORD;
  pComputerBuff      : array[0..80] of Char;
  dwComputerBuffSize : DWORD;
  pRefDomain         : PChar;
  dwRefDomainSize    : DWORD;
begin
  SID := nil;
  //Get User Name
  dwNameBuffSize := Sizeof(pNameBuff);
  GetUserName(pNameBuff,dwNameBuffSize);
  //Get Computer Name
  dwComputerBuffSize := Sizeof(pComputerBuff);
  GetComputerName(pComputerBuff,dwComputerBuffSize);

  dwSidSize:=0; //Makes LookupAccountNameFail
                //When it fails with ERROR_INSUFFICIENT_BUFFER
                //it load dwSidSize with the correct buffer size
  dwRefDomainSize := SizeOf(pRefDomain);

  //Do the first lookup with an undersized sid buffer
  pRefDomain := nil;
  LookupAccountName(pComputerBuff,pNameBuff,SID,dwSidSize,pRefDomain,dwRefDomainSize,SNU);

  //Raise error if it is other than undersized buffer error we are expecting
  if GetLastError <> ERROR_INSUFFICIENT_BUFFER then RaiseLastOSError;

  GetMem(SID,dwSidSize);//Allocate memory for Sid
  GetMem(pRefDomain,(dwRefDomainSize * 2));

  //Do lookup again with correct account name
  if not LookupAccountName(pComputerBuff,pNameBuff,SID,dwSidSize,pRefDomain,dwRefDomainSize,SNU) then
    RaiseLastOSError
  else begin
    Result := String(pRefDomain);
  end;
  FreeMem(SID);//free up memory used for SID
  FreeMem(pRefDomain)
end;

function GetSID(var UserName, DomainName: String): String;
var
  SNU                : SID_NAME_USE;
  SID                : PSID;
  dwSidSize          : DWORD;
  pNameBuff          : array[0..80] of Char;
  dwNameBuffSize     : DWORD;
  pComputerBuff      : array[0..80] of Char;
  dwComputerBuffSize : DWORD;
  pRefDomain         : PChar;
  dwRefDomainSize    : DWORD;
begin
  SID := nil;
  //Get User Name
  dwNameBuffSize := Sizeof(pNameBuff);
  GetUserName(pNameBuff,dwNameBuffSize);
  UserName := String(pNameBuff);
  //Get Computer Name
  dwComputerBuffSize := Sizeof(pComputerBuff);
  GetComputerName(pComputerBuff,dwComputerBuffSize);

  dwSidSize:=0; //Makes LookupAccountNameFail
                //When it fails with ERROR_INSUFFICIENT_BUFFER
                //it load dwSidSize with the correct buffer size
  dwRefDomainSize := SizeOf(pRefDomain);

  //Do the first lookup with an undersized sid buffer
  pRefDomain := nil;
  LookupAccountName(pComputerBuff,pNameBuff,SID,dwSidSize,pRefDomain,dwRefDomainSize,SNU);

  //Raise error if it is other than undersized buffer error we are expecting
  if GetLastError <> ERROR_INSUFFICIENT_BUFFER then RaiseLastOSError;

  GetMem(SID,dwSidSize);//Allocate memory for Sid
  GetMem(pRefDomain,(dwRefDomainSize * 2));

  //Do lookup again with correct account name
  if not LookupAccountName(pComputerBuff,pNameBuff,SID,dwSidSize,pRefDomain,dwRefDomainSize,SNU) then
    RaiseLastOSError
  else begin
    DomainName := String(pRefDomain);
    Result := SIDToStr(SID);
  end;
  FreeMem(SID);//free up memory used for SID
  FreeMem(pRefDomain)
end;

function SIDToStr(Input:PSID):string;
var
  psia             : PSIDIdentifierAuthority;
  dwSubAuthorities : DWORD;
  dwSidRev         : DWORD;
  dwCounter        : DWORD;
begin
  dwSidRev :=1;// SID_REVISION;
  if IsValidSid(Input) then
  begin
    psia:=GetSidIdentifierAuthority(Input);
    dwSubAuthorities:=GetSidSubAuthorityCount(Input)^;
    Result:=Format('S-%u-',[dwSidRev]);
    if (psia^.Value[0] <> 0) or (psia^.Value[1] <> 0) then
      Result:=Result + Format('0x%02x%02x%02x%02x%02x%02x',[psia^.Value[0],psia^.Value [1],psia^.Value [2],psia^.Value [3],psia^.Value[4],psia^.Value [5]])
    else
      Result:=Result+Format('%u',[DWORD (psia^.Value [5])+DWORD (psia^.Value [4] shl 8)+DWORD (psia^.Value [3] shl 16)+DWORD (psia^.Value [2] shl 24)]);
    for dwCounter := 0 to dwSubAuthorities - 1 do
      Result:=Result+Format ('-%u', [GetSidSubAuthority(Input,dwCounter)^])
  end else
  begin
    Result:='NULL';
    raise Exception.Create ('Invalid Security ID Exception');
  end;
end;

constructor TEndPoint.Create(AIP: String; APort: WORD);
begin
  FIP := AIP;
  FPort := APort;

  FServer := TIdHttpServer.Create(nil);
  FServer.DefaultPort := APort;
  FServer.OnCommandGet := CommandGet;
  var LBinding := FServer.Bindings.Add;
  LBinding.IP := AIP;
  LBinding.Port := APort;
end;

destructor TEndPoint.Destroy;
begin
  FServer.Free;
  inherited Destroy;
end;

function TEndPoint.GetServices: String;
begin
  var LBuilder := TStringBuilder.Create;
  try
    LBuilder.Append('<html>');
    LBuilder.Append('  <head>');
    LBuilder.Append('   <title>ATS Endpoint</title>');
    LBuilder.Append(' </head>');
    LBuilder.Append('  <body>');
    LBuilder.AppendFormat('   <h1>Hello From The Test App : %s</h1><br><br>', [LGuidString]);
    var LUser, LDomain: String;
    var LSID := GetSID(LUser, LDomain);
    LBuilder.AppendFormat('   <h2>User: %s\%s (%s) </h2><br><br>', [LDomain, LUser, LSID]);
    LBuilder.AppendFormat('   <h1>%d Command Line: </h1>', [ParamCount]);
    LBuilder.Append('   <ul>');
    for var i := 1 to ParamCount do
      LBuilder.AppendFormat('   <li>Param[%d]: %s</li>', [i, ParamStr(i)]);
    LBuilder.Append('   </ul>');
    LBuilder.Append('   <br><br><br>');
    LBuilder.Append('   <h1>Processes: </h1>');
    LBuilder.Append('   <ul>');
    var LProcesses := GetProcessList;
    try
      for var i := 0 to (LProcesses.Count -1) do
        LBuilder.AppendFormat('   <li>%s</li>', [LProcesses[i]]);
    finally
      LProcesses.Free;
    end;
    LBuilder.Append('   </ul>');
    LBuilder.Append(' </body>');
    LBuilder.Append('</html>');
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TEndPoint.GetServicesFromRegistry: String;
var
  LSubKeys, LMaxSubKeyLength, LSubKeyNameLength, LMaxClassLength: DWORD;
  LValues, LMaxValueNameLength, LMaxValueDataLength: DWORD;
  LLastWriteTime: FILETIME;
begin
  var LBuilder := TStringBuilder.Create;
  try
    LBuilder.Append('<html>');
    LBuilder.Append('  <head>');
    LBuilder.Append('   <title>ATS Endpoint</title>');
    LBuilder.Append(' </head>');
    LBuilder.Append('  <body>');
    LBuilder.AppendFormat('   <h1>Hello From The Test App : %s</h1><br><br>', [LGuidString]);
    LBuilder.Append('   <h1>Processes: </h1>');
    LBuilder.Append('   <ul>');

    var LKey: HKEY;
    var LERR := RegOpenKeyEx(HKEY_LOCAL_MACHINE, PChar('SYSTEM\CurrentControlSet\Services'), 0, KEY_READ or KEY_ENUMERATE_SUB_KEYS, LKey);
    if ERROR_SUCCESS <> LERR then
    begin
      LBuilder.AppendFormat('   <li>RegOpenKeyEx Error %d: %s</li>', [LErr, SysErrorMessage(LErr)]);
    end else
    begin
      var LDataSize: DWORD := 256 * SizeOf(Char);
      var LData: PChar := AllocMem(LDataSize);
      try
        FillChar(LData, LDataSize, 0);
        LERR := RegQueryInfoKey(LKey, LData, @LDataSize, nil, @LSubKeys, @LMaxSubKeyLength, @LMaxClassLength, @LValues, @LMaxValueNameLength, @LMaxValueDataLength, nil, @LLastWriteTime);
        if ERROR_SUCCESS <> LERR then
        begin
          LBuilder.AppendFormat('   <li>RegQueryInfoKey Error %d: %s</li>', [LErr, SysErrorMessage(LErr)]);
        end else
        begin
          LMaxSubKeyLength := MAX_PATH - 1;
          var LSubKeySize: DWORD := MAX_PATH * SizeOf(Char);
          var LSubKey: PChar := AllocMem(LSubKeySize);
          try
            for var i := 0 to (LSubKeys - 1) do
            begin
              FillChar(LSubKey, LSubKeySize, 0);
              LErr := RegEnumKeyEx(LKey, i, LSubKey, LMaxSubKeyLength, nil, nil, nil, @LLastWriteTime);
              if ERROR_SUCCESS = LErr then
                LBuilder.AppendFormat('   <li>%s</li>', [String(LSubKey)])
              else
                LBuilder.AppendFormat('   <li>RegEnumKeyEx Error %d: %s</li>', [LErr, SysErrorMessage(LErr)]);
            end;
          finally
            FreeMem(LSubKey, LSubKeySize);
          end;
        end;
        RegCloseKey(LKey);
      finally
        FreeMem(LData, LDataSize);
      end;
    end;
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TEndPoint.WriteToEventLog: String;
begin
  var LBuilder := TStringBuilder.Create;
  try
    LBuilder.Append('<html>');
    LBuilder.Append('  <head>');
    LBuilder.Append('   <title>ATS Endpoint</title>');
    LBuilder.Append(' </head>');
    LBuilder.Append('  <body>');
    LBuilder.AppendFormat('   <h1>Hello From The Test App : %s</h1><br><br>', [LGuidString]);
    var LUser, LDomain: String;
    var LSID := GetSID(LUser, LDomain);
    LBuilder.AppendFormat('   <h2>User: %s\%s (%s) </h2><br><br>', [LDomain, LUser, LSID]);

    var LEvtLog := TEventLogger.Create('My Test App Name');
    try
      try
        LEvtLog.LogMessage('This is an error.');
        LEvtLog.LogMessage('This is another error.', EVENTLOG_ERROR_TYPE);
        LEvtLog.LogMessage('This is information.', EVENTLOG_INFORMATION_TYPE);
        LEvtLog.LogMessage('This is a warning.', EVENTLOG_WARNING_TYPE);
        LBuilder.Append('   <p>Events Written!</p>');
      except
        on E:Exception do
        begin
          LBuilder.AppendFormat('   <p>%s</p>', [E.Message]);;
        end;
      end;
    finally
      LEvtLog.Free;
    end;
    LBuilder.Append(' </body>');
    LBuilder.Append('</html>');
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TEndPoint.GetIsStarted: Boolean;
begin
  Result := FServer.Active;
end;

procedure TEndPoint.ProcessGet(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
begin
  if ('/RegUser' = ARequestInfo.URI) then
    AResponseInfo.ContentText := GetServicesFromRegistry
  else if ('/WriteEvents' = ARequestInfo.URI) then
    AResponseInfo.ContentText := WriteToEventLog
  else
    AResponseInfo.ContentText := GetServices;
end;

{$REGION 'Event Handlers'}
function TEndPoint.Start: Boolean;
begin
  Result := FALSE;
  try
    FServer.Active := TRUE;
    Result := TRUE;
  except
     on E:Exception do
     begin
       WriteLn(String.Format('Exception starting REST Endpoint: %s', [E.Message]));
     end;
  end;
end;

procedure TEndPoint.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
begin
  //Each Call to this runs in it's own thread
  try
    case ARequestInfo.CommandType of
      hcGet: ProcessGet(ARequestInfo, AResponseInfo);
      hcHead: ProcessGet(ARequestInfo, AResponseInfo);
      hcPost: ProcessGet(ARequestInfo, AResponseInfo);
      hcTRACE: ProcessGet(ARequestInfo, AResponseInfo);
      hcOPTION: ProcessGet(ARequestInfo, AResponseInfo);
    else
      WriteLn(String.Format('[EndPoint] Got %s Command [%s]', [ARequestInfo.Command, ARequestInfo.URI]));
      AResponseInfo.ResponseNo := 404;
    end;
  except
    on E:Exception do
    begin
      AResponseInfo.ResponseNo := 500;
      AResponseInfo.ResponseText := String.Format('[EndPoint] Error processing %s: %s', [ARequestInfo.Command, E.Message]);
    end;
  end;
end;
{$ENDREGION}

procedure TEndPoint.Stop;
begin
  try
    FServer.Active := FALSE;
  except
    //Suppress any exceptions as sockets are closed off
  end;
end;

initialization
  LGuidString := TGuid.NewGuid.ToString;

end.
