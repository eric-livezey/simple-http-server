RM = rm
CC = gcc
INPUT = hashmap.c utils.c http.c server.c
OUTPUT = server
FLAGS =

build:
	${CC} ${INPUT} ${FLAGS} -o ${OUTPUT}

clean:
	$(RM) -rf $(BASENAME) *.o