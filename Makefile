PROG =			pipetest
LDADD =			-lutil
DPADD =			${LIBUTIL}
WARNINGS =		yes
CLEANFILES +=		ptypair *.fifo *.sock *.log

# XXX fifo is broken as it does not work correctly if used bidirectionaly

ptypair: ${LIBCRT0} ptypair.o ${LIBC} ${CRTBEGIN} ${CRTEND} ${DPADD}
	${CC} ${LDFLAGS} ${LDSTATIC} -o ${.TARGET} ptypair.o ${LDADD}

.for t in socketpair pipe unix pty
REGRESS_TARGETS +=	run-regress-$t
run-regress-$t: ${PROG} ptypair
	@echo '\n======== $@ ========'
	./pipetest $t >$t.log
	if sed -n 's/.*: //p' $t.log | sort | uniq -u | grep .; then false; fi
.endfor

.include <bsd.regress.mk>
