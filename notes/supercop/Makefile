all: clean curve ed x

clean: clean-curve clean-ed clean-x

clean-curve:
	rm -f ../../src/pk/curve25519/ref10/*

clean-ed:
	rm -f ../../src/pk/ed25519/ref10/*

clean-x:
	rm -f ../../src/pk/x25519/ref10/*

curve: ../../src/pk/curve25519/ref10/curve25519.c

x: ../../src/pk/x25519/ref10/x25519.c

ed: ../../src/pk/ed25519/ref10/ed25519.c

../../src/pk/curve25519/ref10/curve25519.c:
	cat header > $@
	printf '#ifdef LTC_CURVE25519\n\n' >> $@
	cat curve25519/fe_cswap.c >> $@
	printf '\n#endif\n' >> $@
	cat footer >> $@
	sed -i -e '/#include "crypto_[u]*int[2346].\.h"/d' -e '/#include "fe\.h"/d' -e '/#include "crypto_scalarmult\.h"/d' $@
	sed -i -e '/typedef crypto_int32 fe\[10\];/d' -e 's/extern/static/g' $@

X_HEADERS=../../src/pk/x25519/ref10/montgomery.h ../../src/pk/x25519/ref10/pow225521.h

$(X_HEADERS):
	cat header > $@
	cat curve25519/`basename $@` >> $@
	cat footer >> $@

../../src/pk/x25519/ref10/x25519.c: $(X_HEADERS) ../../src/pk/curve25519/ref10/curve25519.c
	cat header > $@
	printf '#ifdef LTC_X25519\n\n' >> $@
	cat curve25519/fe.h >> $@
	find curve25519 -name 'fe_*.c' | grep -v 'fe_cswap.c' | sort | xargs -I {} cat {} >> $@
	cat curve25519/scalarmult.c >> $@
	cat curve25519/base.c >> $@
	printf '\n#endif\n' >> $@
	cat footer >> $@
	sed -i -e '/#include "crypto_[u]*int[2346].\.h"/d' -e '/#include "fe\.h"/d' -e '/#include "crypto_scalarmult\.h"/d' $@
	sed -i -e '/extern void fe_cswap/d' -e '/crypto_scalarmult_curve25519_ref10_fe_cswap/d' $@
	sed -i -e '/typedef crypto_int32 fe\[10\];/d' -e 's/extern/static/g' $@

ed: ../../src/pk/ed25519/ref10/ed25519.c

ED_HEADERS=../../src/pk/ed25519/ref10/base.h ../../src/pk/ed25519/ref10/base2.h \
           ../../src/pk/ed25519/ref10/d.h ../../src/pk/ed25519/ref10/d2.h \
            ../../src/pk/ed25519/ref10/ge_add.h \
            ../../src/pk/ed25519/ref10/ge_madd.h ../../src/pk/ed25519/ref10/ge_msub.h \
            ../../src/pk/ed25519/ref10/ge_p2_dbl.h ../../src/pk/ed25519/ref10/ge_sub.h \
            ../../src/pk/ed25519/ref10/pow22523.h ../../src/pk/ed25519/ref10/pow225521.h \
            ../../src/pk/ed25519/ref10/sqrtm1.h

$(ED_HEADERS):
	cat header > $@
	cat ed25519/`basename $@` >> $@
	cat footer >> $@

../../src/pk/ed25519/ref10/ed25519.c: $(ED_HEADERS) ../../src/pk/curve25519/ref10/curve25519.c
	cat header > $@
	cat ed25519/fe.h >> $@
	cat ed25519/ge.h >> $@
	cat ed25519/sc.h >> $@
	cat ed25519-modified/verify.c >> $@
	find ed25519 -name 'fe_*.c' -o -name 'ge_*.c' -o -name 'sc_*.c' | sort | xargs -I {} cat {} >> $@
	cat ed25519-modified/open.c >> $@
	cat ed25519-modified/sign.c >> $@
	cat ed25519-modified/keypair.c >> $@
	cat footer >> $@
	sed -i -e '/#include "crypto_[a-zA-Z0-9].*\.h"/d' -e '/#include "fe\.h"/d' -e '/#include "ge\.h"/d' -e '/#include "sc\.h"/d' -e '/#include "randombytes\.h"/d' $@
	sed -i -e '/extern void fe_cswap/d' -e '/crypto_sign_ed25519_ref10_fe_cswap/d' $@
	sed -i -e 's/select(/_select(/g' -e 's/memset/XMEMSET/g' -e 's/memmove/XMEMMOVE/g' $@
	sed -i -e '/fe_mul121666/d' -e '/typedef crypto_int32 fe\[10\];/d' -e 's/extern/static/g' $@
