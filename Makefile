SRCDIR=src/
OBJDIR=obj/

SRC=$(shell find $(SRCDIR) -name "*.c")
OBJ=$(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

EXEC=rsa_decrypt

encrypt: $(OBJ)
	${CC} rsa_encrypt.c $^ -o $@

decrypt: $(OBJ)
	${CC} rsa_decrypt.c $^ -o $@

${OBJDIR}/%.o: ${SRCDIR}/%.c
	$(CC) -o $@ -c $<

clean:
	-rm encrypt decrypt
