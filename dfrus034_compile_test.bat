@echo off
REM �࠭���� ���� � �� � ��᫥����� ��������� �� ����� MinGW
REM �⪮�����஢����� ����� �� ࠡ�⠥�, ���頫� ��䨪��� � Euphoria 4.0.6, ����.
set EUDIR=c:\eu4
euc -gcc -con dfrus034.exw
"c:\Program Files (x86)\tools\upx308w\upx.exe" dfrus034.exe
dfrus034.exe debug d:\Games\df_34_11_ironhand_0_73\