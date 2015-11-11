PROG=		pipetest
WARNINGS=	yes
CLEANFILES+=	*.fifo *.sock

regress:
	./pipetest socketpair
	./pipetest pipe
	#./pipetest fifo  broken, fifo is not bidirectional
	./pipetest unix

.include <bsd.regress.mk>
