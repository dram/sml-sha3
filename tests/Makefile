.PHONY: all clean

all:
	ml-build main.cm Tests.main
	sml @SMLload main.x86-linux

clean:
	rm -r .cm/ main.x86-linux
