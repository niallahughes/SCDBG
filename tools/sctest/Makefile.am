AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I../../include -I ../../.. -Wall -g
AM_LDFLAGS = -lemu -L../../src 


# if you want to compile without tests, uncomment the following line:
#AM_CPPFLAGS += -D_NO_TESTS


bin_PROGRAMS = scdbg

scdbg_CPPFLAGS = ${LIB_CARGOS_INCDIR}  ${AM_CPPFLAGS}
scdbg_LDFLAGS =  ${LIB_CARGOS} ${LIB_CARGOS_LIBDIR} ${AM_LDFLAGS}
scdbg_LDADD = ../../src/libemu.la
scdbg_SOURCES = dot.c
scdbg_SOURCES += dot.h
scdbg_SOURCES += sctestmain.c
scdbg_SOURCES += tests.c
scdbg_SOURCES += tests.h
scdbg_SOURCES += userhooks.c
scdbg_SOURCES += userhooks.h
scdbg_SOURCES += nanny.c
scdbg_SOURCES += nanny.h
scdbg_SOURCES += options.h

