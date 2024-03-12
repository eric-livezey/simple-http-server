RM = rm
CC = gcc
INPUT = hashmap.c utils.c http.c server.c
OUTPUT = server

build:
	${CC} ${INPUT} -o ${OUTPUT}

clean:
	$(RM) -rf $(BASENAME) *.o
