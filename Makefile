RM = rm
CC = gcc
INPUT = types/*.c types/**/*.c utils.c uri.c http.c server.c
OUTPUT = server

build:
	${CC} ${INPUT} -o ${OUTPUT}

clean:
	$(RM) -rf $(OUTPUT) *.o
