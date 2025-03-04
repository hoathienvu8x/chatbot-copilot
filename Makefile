CC = gcc
LDFLAGS = -I. -ldl -lpthread -lm
ifeq ($(build),release)
	CFLAGS = -O3
	LDFLAGS += -DNDEBUG=1
else
	CFLAGS = -Og -g
endif
CFLAGS += -std=gnu99 -Wall -Wextra -Werror -pedantic
RM = rm -rf

OBJECTS = b64.o ws.o sha1.o
OBJECTS := $(addprefix objects/,$(OBJECTS))
EXECUTABLE = demo

all: objects $(EXECUTABLE)

objects:
	@echo "Create 'objects' folder ..."
	@mkdir -p objects

$(EXECUTABLE): objects/demo.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/demo.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/demo.o

srv: objects/srv.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/srv.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/srv.o

cli: objects/cli.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/cli.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/cli.o

frm: objects/frm.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/frm.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/frm.o

objects/%.o: %.c
	@echo "Build '$@' object ..."
	@$(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	@echo "Cleanup ..."
	@$(RM) $(OBJECTS) $(EXECUTABLE) srv cli
