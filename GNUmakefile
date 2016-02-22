all: dfstream3.so

%.o: %.c
	gcc -g -m32 -shared -std=c99 -I/usr/include/SDL/ -Ilsx/include/ -Ilibtttp/ $< -c -o $@

dfstream3.so: src/dfstream3.o libtttp/tttp_common.o libtttp/tttp_server.o lsx/src/lsx_bzero.o lsx/src/lsx_random.o lsx/src/lsx_sha256.o lsx/src/lsx_twofish.o
	gcc -g -m32 -shared -std=c99 $^ -lpth -lz -lgmp -o $@

clean:
	rm -f *.o */*.o */*/*.o *~ \#*\# *.so
