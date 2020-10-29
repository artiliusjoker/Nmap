#Directory
INDIR = ../include
OBJDIR = objects
# Constants
CC = gcc
PROGS = 1712695
# Flag I
CFLAGS = -I$(INDIR) -pthread
# .h files location
DEPS_LOC = $(wildcard $(INDIR)/*.h)
# .C files
src = $(wildcard *.c)
# Objects files and location
obj = $(src:.c=.o)
OBJ_LOC = $(patsubst %,$(OBJDIR)/%,$(obj))

# Rules
$(OBJDIR)/%.o: %.c $(DEPS_LOC)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJ_LOC)
	$(CC) -o $@ $^ $(CFLAGS)
	rm -f  1712695.txt
	
.PHONY: clean
all: $(PROGS)

clean:
	rm -f $(OBJ_LOC) $(PROGS)
