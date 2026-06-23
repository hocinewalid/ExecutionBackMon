CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2
LDFLAGS = -ladvapi32 -lwevtapi -lcrypt32 -limagehlp -lwintrust -lole32 -loleaut32 -luuid

SRC = src/main.c \
      src/core/timeline.c \
      src/core/scoring.c \
      src/core/report.c \
      src/core/ioc.c \
      src/core/utils.c \
      src/modules/bam.c \
      src/modules/userassist.c \
      src/modules/shimcache.c \
      src/modules/eventlog.c \
      src/modules/prefetch.c \
      src/modules/amcache.c \
      src/modules/pe.c

OBJ = $(SRC:.c=.o)
EXEC = executebackmon.exe

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
