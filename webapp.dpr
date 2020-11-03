program webapp;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  WinAPI.Windows,
  EndPoint in 'EndPoint.pas',
  RegKeyUser in 'RegKeyUser.pas';

function KeyPressed:Boolean;
var
  lpNumberOfEvents     : DWORD;
  lpBuffer             : TInputRecord;
  lpNumberOfEventsRead : DWORD;
  nStdHandle           : THandle;
begin
  Result:=false;
  //get the console handle
  nStdHandle := GetStdHandle(STD_INPUT_HANDLE);
  lpNumberOfEvents:=0;
  //get the number of events
  GetNumberOfConsoleInputEvents(nStdHandle,lpNumberOfEvents);
  if lpNumberOfEvents<> 0 then
  begin
    //retrieve the event
    PeekConsoleInput(nStdHandle,lpBuffer,1,lpNumberOfEventsRead);
    if lpNumberOfEventsRead <> 0 then
    begin
      if lpBuffer.EventType = KEY_EVENT then //is a Keyboard event?
      begin
        if lpBuffer.Event.KeyEvent.bKeyDown then //the key was pressed?
        begin
          if ($43 = lpBuffer.Event.KeyEvent.wVirtualKeyCode) and ((LEFT_CTRL_PRESSED = lpBuffer.Event.KeyEvent.dwControlKeyState) or (RIGHT_CTRL_PRESSED = lpBuffer.Event.KeyEvent.dwControlKeyState))then
            Result := True
        end else
          FlushConsoleInputBuffer(nStdHandle); //flush the buffer
      end
      else
        FlushConsoleInputBuffer(nStdHandle);//flush the buffer
    end;
  end;
end;

var
  FEvent: THandle;
  FEndPoint: TEndPoint;
  FIPAddress: String = '127.0.0.1';
  FPort: WORD = 8080;

function ConsoleEventProc(CtrlType: DWORD): BOOL; stdcall;
begin
  if (CTRL_CLOSE_EVENT = CtrlType) or (CTRL_C_EVENT = CtrlType) then
  begin
    SetEvent(FEvent);
  end;
  Result := True;
end;

begin
  begin
    WriteLn('In Scope');
  end;
  WriteLn('ParamCount = ', ParamCount);
  if 1 = ParamCount then
  begin
    var LParam := ParamStr(1).Split([':']);
    FIPAddress := LParam[0];
    FPort := StrToInt(LParam[1]);
  end;
  WriteLn('Create Event');
  FEvent := CreateEvent(nil, TRUe, FALSE, nil);
  SetConsoleCtrlHandler(@ConsoleEventProc, True);
  WriteLn('Create Endpoint [', FIPAddress, ':', FPort, ']');
  FEndPoint := TEndPoint.Create(FIPAddress, FPort);
  try
    WriteLn('Start Endpoint');
    FEndPoint.Start;
    WaitForSingleObject(FEvent, INFINITE);
    CloseHandle(FEvent);
    WriteLn('Stop Endpoint');
    FEndPoint.Stop;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  WriteLn('Exit App');
end.
