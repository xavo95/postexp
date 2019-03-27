#!/bin/bash

xcrun -sdk iphoneos clang -c -framework Foundation -framework IOKit -arch arm64 -arch arm64e -I../include -I../patchfinder64 -fobjc-arc ../patchfinder64/*.c *.c *.m *.cpp && ar rcu downloads/jelbrekLib.a *.o && rm *.o

