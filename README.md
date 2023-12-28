# license
头文件： ./include/Donkey_API.h ./include/usb.h
动态库： ./api/api64/libRockeyARM.so.0.3
静态库： ./api/api64/libRockeyARM.a

make install:
cd /base/test/ctest
gcc license.c -o test -I ../../include -L ../../api/api64 -lRockeyARM -lpthread

license校验函数：./base/test/ctest/license.c   checkLicense()
rsa动态验证函数：./base/test/ctest/license.c   rsaAuthentication()
