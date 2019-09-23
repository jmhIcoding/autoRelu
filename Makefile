all:
	make -C /src/
	cp /src/autorelu ./autorelu
clean:
	rm autorelu