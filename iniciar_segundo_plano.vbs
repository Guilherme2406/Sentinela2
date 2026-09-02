' iniciar_segundo_plano.vbs
' Inicializador 100% silencioso para o Sentinela XDR na Bandeja do Sistema
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

CurrentDir = FSO.GetParentFolderName(WScript.ScriptFullName)
TrayScript = CurrentDir & "\tray_app.pyw"

PythonwExe = "pythonw.exe"
UserAppData = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")

' Procura pythonw.exe nos diretórios de instalação reais do Windows (pythoncore e Programs)
If FSO.FileExists(UserAppData & "\Python\pythoncore-3.14-64\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Python\pythoncore-3.14-64\pythonw.exe" & """"
ElseIf FSO.FileExists(UserAppData & "\Python\pythoncore-3.13-64\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Python\pythoncore-3.13-64\pythonw.exe" & """"
ElseIf FSO.FileExists(UserAppData & "\Python\pythoncore-3.12-64\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Python\pythoncore-3.12-64\pythonw.exe" & """"
ElseIf FSO.FileExists(UserAppData & "\Programs\Python\Python314\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Programs\Python\Python314\pythonw.exe" & """"
ElseIf FSO.FileExists(UserAppData & "\Programs\Python\Python313\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Programs\Python\Python313\pythonw.exe" & """"
ElseIf FSO.FileExists(UserAppData & "\Programs\Python\Python312\pythonw.exe") Then
    PythonwExe = """" & UserAppData & "\Programs\Python\Python312\pythonw.exe" & """"
ElseIf FSO.FileExists("C:\Program Files\Python312\pythonw.exe") Then
    PythonwExe = """C:\Program Files\Python312\pythonw.exe"""
End If

' Executa em modo oculto (WindowStyle = 0)
Command = PythonwExe & " """ & TrayScript & """"
WshShell.CurrentDirectory = CurrentDir
WshShell.Run Command, 0, False
