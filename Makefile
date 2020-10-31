#Directory
INDIR = include
OBJDIR = objects
SRCDIR = src
# Constants
CC = gcc
PROGS = 1712695
# Flag I
CFLAGS = -pthread
# .h files location
DEPS_LOC = $(wildcard $(INDIR)/*.h)
# .C files
source = $(wildcard $(SRCDIR)/*.c)
# Objects files and location
obj = $(source:.c=.o)
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

