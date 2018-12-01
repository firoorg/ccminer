EXTRA_DIST = bosjansson.def

include_HEADERS = bosjansson.h
nodist_include_HEADERS = jansson_config.h

noinst_LIBRARIES = libbosjansson.a

###lib_LTLIBRARIES = libbosjansson.la
libbosjansson_a_SOURCES = \
    bos_deserializer.c \
    bos_serializer.c \
	dump.c \
	error.c \
	hashtable.c \
	hashtable.h \
	hashtable_seed.c \
	jansson_private.h \
	load.c \
	lookup3.h \
	memory.c \
	pack_unpack.c \
	strbuffer.c \
	strbuffer.h \
	strconv.c \
	utf.c \
	utf.h \
	value.c
#libbosjansson_a_LDFLAGS = \
#	-no-undefined \
#	-export-symbols-regex '^json_' \
#	-version-info 15:0:11 \
#	@JSON_BSYMBOLIC_LDFLAGS@

