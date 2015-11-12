PROG =			pipetest
LDADD =			-lutil
DPADD =			${LIBUTIL}
WARNINGS =		yes
CLEANFILES +=		*.fifo *.sock *.log

# XXX fifo is broken as it does not work correctly if used bidirectionaly

.for t in socketpair pipe unix pty
REGRESS_TARGETS +=	run-regress-$t
run-regress-$t: ${PROG}
	@echo '\n======== $@ ========'
	./pipetest $t >$t.log
	if sed -n 's/.*: //p' $t.log | sort | uniq -u | grep .; then false; fi
.endfor

.include <bsd.regress.mk>
