# Makefile 3

# マクロ定義部
TARGET  = sample
CC      = g++
OBJS    = hook_shmXXX.o sample.o

# 生成規則部
all:    $(TARGET)

$(TARGET): sample.cpp
	$(CC) -o libhookShm.so -shared -fPIC -lbfd -ldl Lib_hook.cpp hook_shmXXX.cpp
	$(CC) -o $@ sample.cpp

.cpp.o:
	$(CC) -c $<

clean:
	rm -f ./*.so ./*.o
	rm sample

#sub1.o: header.h
#sub2.o: header.h
