all:
	make -C src/
	cp ./src/autorule ./autorelu
clean:
	rm autorelu