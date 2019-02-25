
rem x64\Release\ccminer -a mtp -o  http://127.0.0.1:8382   -u djm34 -p password --coinbase-addr aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak -d 1070 --no-getwork -i 18
rem x64\Release\ccminer -a mtp -o  stratum+tcp://xzc.2miners.com:8080  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak -p 0 -i 20 -d 1 
x64\Release\ccminer -a mtp -o  stratum+tcp://zcoin.mintpond.com:3000 -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker  -p 0,strict,verbose,d=100  -i 20 

rem x64\Release\ccminer -a mtp -o   stratum+tcp://pool.bibop.net:4000  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak -p 0,c=XZC -i 20 -d 1 

rem x64\Release\ccminer -a mtp -o  stratum+tcp://mtp.eu.nicehash.com:3374   -u  1NENYmxwZGHsKFmyjTc5WferTn5VTFb7Ze -p x -i 20 -d 1 
pause
