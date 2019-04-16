#!/bin/bash

xcrun -sdk iphoneos cc -framework Foundation -framework IOKit -arch arm64e -arch arm64 -I../include -I../patchfinder64 -I../offset-cache -I. -Ikernel_call -fobjc-arc ../patchfinder64/*.c ../offset-cache/*.c kernel_call/*.c *.c *.m && rm *.o

