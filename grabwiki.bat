@echo off
chcp 1251
set path=c:\Program Files (x86)\GnuWin32\bin;%path%

echo ===================================== Downloading trans.txt: =====================================
echo Generation started: %date%, %time% > trans.txt
wget -B http://www.dfwk.ru/User:Insolor/translation/ -i transparts.lst -O - | ^
iconv -c -f utf-8 -t cp1251 | ^
eui processwiki >> trans.txt

echo ==================================== Downloading speech files:====================================
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/speech -O - | ^
iconv -c -f utf-8 -t cp1251 | ^
eui procspeech data\speech
