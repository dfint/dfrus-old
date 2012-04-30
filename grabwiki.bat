@echo off
del part*
chcp 1251
set path=c:\Program Files (x86)\GnuWin32\bin;%path%
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/part1
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/part2
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/part3
wget http://www.dfwk.ru/Служебная:Export/User:Insolor/translation/part4
iconv -c -f utf-8 -t cp1251 part1 part2 part3 part4 | eui processwiki > trans.txt
