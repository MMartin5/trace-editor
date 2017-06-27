CC=gcc
CFLAGS= -I/home/mmartin/Bureau/Poly/Maîtrise/Outils/babeltrace-2.0.0-pre1/include/ `pkg-config --cflags glib-2.0` -g
LDFLAGS= `pkg-config --libs glib-2.0` -L/usr/local/lib/ -lbabeltrace -lbabeltrace-ctf -g
DEPS=
SOURCES=main.c
OBJECTS=$(SOURCES:.c=.o)
TARGET=trace_editor

.PHONY: clean

all: $(SOURCES) $(TARGET)

.ccp.o:
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

clean:
	rm $(OBJECTS) $(TARGET)
