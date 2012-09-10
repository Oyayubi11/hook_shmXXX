# Makefile 3

# マクロ定義部
TARGET  = test
CC      = g++
OBJS    = unit_test.o

# 生成規則部
all:    $(TARGET)

$(TARGET): unit_test.cpp
	$(CC) -o $@ unit_test.cpp -lcppunit

.cpp.o:
	$(CC) -c $<

clean:
	rm -f ./*.so ./*.o
	rm test

#sub1.o: header.h
#sub2.o: header.h
