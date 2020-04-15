
rem loop:
rem x64\Release\ccminer -a mtp -o  http://127.0.0.1:8382   -u djm34 -p password --coinbase-addr aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5 --no-stratum --no-getwork -i 22 

rem x64\Release\ccminer -a mtp -o  stratum+tcp://xzc.2miners.com:8080  -u  aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5 -p 0 
x64\Release\ccminer -a mtp -o stratum+tcp://zcoin.mintpond.com:3000 -u aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5.worker   -p 0,strict,verbose,d=500 
rem x64\Release\ccminer -a mtp -o stratum+tcp://mtp.mine.zergpool.com:3000 -u aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5 -p c=BTC,id=MKVITO2 -d 0,1 -i 26
rem x64\Release\ccminer -a mtp -o stratum+tcp://zcoin-us.mintpond.com:3000  -u  aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5.worker -p 0,strict,sd=1000  -i 20 --donation 5
rem x64\Release\ccminer -a mtp -o   stratum+tcp://pool.bibop.net:4001  -u  aChWVb8CpgajadpLmiwDZvZaKizQgHxfh5 -p 0,c=XZC,d=10 -i 20 -d 0 
rem goto loop
pause
