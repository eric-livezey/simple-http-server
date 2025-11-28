RM = rm
CC = gcc
INPUT = utils.c hashmap.c uri.c http.c server.c
OUTPUT = server

build:
	${CC} ${INPUT} -o ${OUTPUT}

clean:
	$(RM) -rf $(OUTPUT) *.o
