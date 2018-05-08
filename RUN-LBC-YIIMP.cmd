rem Release\ccminer -a argon2 -o http://127.0.0.1:9989 -u dom -p password  --device gtx1070
rem x64\Release\ccminer -a argon2 -o  stratum+tcp://xzc.suprnova.cc:1598   -u djm34.1 -p password    --cpu-priority 4    --device 1070  --debug 
rem x64\Release\ccminer -a mtp -o  http://127.0.0.1:9898   -u djm34 -p password    --cpu-priority 4    --device 1070  
x64\Release\ccminer -a mtp -o   stratum+tcp://xzc.suprnova.cc:1598  -u djm34.1 -p password    --cpu-priority 4    --device 1080
x64\Release\ccminer -a mtp -o stratum+tcp://xmg.minerclaim.net:3333 -u kakaeli.voin -p voin   --device 1080
rem Release\ccminer  -a lbry -o stratum+tcp://yiimp.ccminer.org:3334 -u bK2wcSFJv2nnNjFvTN5Q7VX8X8unJktJsa -p d=128,stats --cpu-priority 4 --protocol-dump --debug
rem Release\ccminer -a m7 -o  stratum+tcp://xcn.suprnova.cc:8008 -u djm34.1 -p password    --cpu-priority 4 -d 1070 
pause
