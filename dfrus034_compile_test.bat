@echo off
REM Трансляция патча в Си и последюущая компиляция при помощи MinGW
REM Откомпилированная версия не работает, обещали пофиксить в Euphoria 4.0.5, ждем.
euc -gcc -con dfrus034.exw
dfrus034.exe debug d:\Games\df_34_09_win\