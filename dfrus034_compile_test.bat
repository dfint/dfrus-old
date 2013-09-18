@echo off
REM Трансляция патча в Си и последюущая компиляция при помощи MinGW
REM Откомпилированная версия не работает, обещали пофиксить в Euphoria 4.0.6, ждем.
REM Добавил chcp, т.к. "его" в кодировке 808 звучит нецензурно :)
chcp 1251
set EUDIR=c:\eu4
euc -gcc -con dfrus034.exw
"c:\Program Files (x86)\tools\upx308w\upx.exe" dfrus034.exe
dfrus034.exe debug d:\Games\df_34_11_ironhand_0_73\