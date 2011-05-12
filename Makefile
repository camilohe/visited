# Makefile for visited
# Copyright (C) 2011 Camilo E. Hidalgo Estevez <camilohe@gmail.com>
# All Rights Reserved
# Under the BSD license (see COPYING)

DEBUG?= -g
CFLAGS?= -O2 -Wall -W
CCOPT= $(CFLAGS)

OBJ = visited.o aht.o antigetopt.o tail.o
PRGNAME = visited

all: visited

visited.o: visited.c blacklist.h
visited: $(OBJ)
	$(CC) -o $(PRGNAME) $(CCOPT) $(DEBUG) $(OBJ)

.c.o:
	$(CC) -c $(CCOPT) $(DEBUG) $(COMPILE_TIME) $<

clean:
	rm -rf $(PRGNAME) *.o
