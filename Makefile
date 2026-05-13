#CXX=clang++
CXX = g++

# ---------------- Optional tamper detection / MAC verification ----------------
# Default builds omit tamper-detection support. Add -DTAMPER_DETECT through
# CXXFLAGS to compile the MAC verification code and link its key/hash helpers:
# The eauditd-tamper target below passes this flag for the full build.
TAMPER_SRCS :=
TAMPER_DEPS :=
TAMPER_LIBS :=

ifneq ($(filter -DTAMPER_DETECT,$(CXXFLAGS)),)
  TAMPER_SRCS += computehash.C
  TAMPER_DEPS += libkeygen.so
  TAMPER_LIBS += -L. -lkeygen -lssl -lcrypto -Wl,-rpath=.
endif

# ***************** YOU SHOULD NOT SET CXXFLAGS IN THIS FILE *****************
MCXXFLAGS := -g -std=c++2a -Wall -O2 -DREC_ONLY_HOST $(CXXFLAGS)

IDIR = -I lib/

# ---------------- Sources ----------------
BASE_SRCS = eaudit.C eauditd.C eParser.C prthelper.C \
            eConsumer.C ePrinter.C eRecorder.C RecOnlyHost.C

SRCS = $(BASE_SRCS) $(TAMPER_SRCS)

OBJS  = $(SRCS:%.C=%.o)
POBJS = $(SRCS:%.C=%.po)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) -c
COMPILE.C = $(CXX) $(DEPFLAGS) $(MCXXFLAGS) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@
POSTCOMPILE_PO = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.pd && touch $@

# Disable default rules. It seems hard to ensure that our patterns rules
# fire, instead of the default rules.
.SUFFIXES:

include $(wildcard $(DEPDIR)/*.d) $(wildcard $(DEPDIR)/*.pd)

%.o: %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: %.C cxx_flags $(DEPDIR)/%.d
	$(COMPILE.C) $(IDIR) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.po: %.C cxx_flags $(DEPDIR)/%.pd
	$(COMPILE.C) $(IDIR) -fpic $(OUTPUT_OPTION) $<
	$(POSTCOMPILE_PO)

$(DEPDIR)/%.d: ;
$(DEPDIR)/%.pd: ;
.PRECIOUS: $(DEPDIR)/%.d $(DEPDIR)/%.pd

.PHONY: force tamper

cxx_flags: force
	@echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u | diff -q $@ - || echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u  > $@

# ---------------- Shared libs / binaries ----------------

libkeygen.so: keygen.c keygen.h
	$(CXX) -shared -march=native -fopenmp-simd -fPIC -O3 -maes -mpclmul -pthread -o libkeygen.so keygen.c

ecapd.so: ecapd.po
	$(CXX) -shared -o $@ $<

# Conditional keygen + OpenSSL linkage via $(TAMPER_DEPS) and $(TAMPER_LIBS)
eauditd.so: $(POBJS) $(TAMPER_DEPS)
	$(CXX) -shared -o $@ $(POBJS) $(TAMPER_LIBS) $(IDIR)

eaudit: $(OBJS) $(TAMPER_DEPS)
	$(CXX) -o $@ $^ $(TAMPER_LIBS) $(IDIR)

eauditd-tamper:
	$(MAKE) CXXFLAGS="$(CXXFLAGS) -DTAMPER_DETECT" all

all: ecapd.so eauditd.so eaudit

clean:
	rm -f cxx_flags eaudit eauditc *.o *.so *.po .d/*.d .d/*.pd
	make -s -C eval/postmark clean
	make -s -C eval/rdwr clean
