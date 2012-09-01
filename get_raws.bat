@echo off
chcp 1251
set path=c:\Program Files (x86)\GnuWin32\bin;%path%

del raws
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/raw -O raws
for /f "tokens=2 delims=[|" %%I in (raws) do (
echo %%I
wget http://www.dfwk.ru/User:Insolor/translation/raw%%I -q -O - | ^
iconv -c -f utf-8 -t cp1251 | ^
eui processwiki > "raw\objects%%I.txt"
diff "raw\objects.bak%%I.txt" "raw\objects%%I.txt" --binary > "diffs\%%~nI.diff"
)
