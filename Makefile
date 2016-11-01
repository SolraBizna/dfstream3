all: dfstream3.so

%.o: %.c
	gcc -g -m32 -fPIC -shared -std=c99 -I/usr/include/SDL/ -Ilsx/include/ -Ilibtttp/ $< -c -o $@

%_64.o: %.c
	gcc -g -m64 -fPIC -shared -std=c99 -I/usr/include/SDL/ -Ilsx/include/ -Ilibtttp/ $< -c -o $@

dfstream3.so: src/dfstream3.o libtttp/tttp_common.o libtttp/tttp_server.o lsx/src/lsx_bzero.o lsx/src/lsx_random.o lsx/src/lsx_sha256.o lsx/src/lsx_twofish.o
	gcc -g -m32 -fPIC -shared -std=c99 $^ -lpth -lz -lgmp -o $@

dfstream3_64.so: src/dfstream3_64.o libtttp/tttp_common_64.o libtttp/tttp_server_64.o lsx/src/lsx_bzero_64.o lsx/src/lsx_random_64.o lsx/src/lsx_sha256_64.o lsx/src/lsx_twofish_64.o
	gcc -g -m64 -fPIC -shared -std=c99 $^ -lpth -lz -lgmp -o $@

clean:
	rm -f *.o */*.o */*/*.o *~ \#*\# *.so
