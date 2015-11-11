PROG =			pipetest
WARNINGS =		yes
CLEANFILES +=		*.fifo *.sock

# XXX fifo is broken as it is not bidirectional
.for t in socketpair pipe unix
REGRESS_TARGETS +=	run-regress-$t
run-regress-$t: ${PROG}
	@echo '\n======== $@ ========'
	./pipetest $t
.endfor

.include <bsd.regress.mk>
