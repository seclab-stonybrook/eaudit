CXX = g++

# ***************** YOU SHOULD NOT SET CXXFLAGS IN THIS FILE *****************

MCXXFLAGS := -g -std=c++2a -Wall -O2

IDIR = -I lib/
EAUDITSRCS = eaudit.C eParser.C
EAUDITDSRCS = eauditd.C

SRCS = $(EAUDITSRCS)
EAUDITOBJS = $(EAUDITSRCS:%.C=%.o)
EAUDITDOBJS = $(EAUDITDSRCS:%.C=%.o)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) -c
COMPILE.C = $(CXX) $(DEPFLAGS) $(MCXXFLAGS) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

# Disable default rules. It seems hard to ensure that our patterns rules
# fire, instead of the default rules.
.SUFFIXES:

%.o: %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: %.C cxx_flags $(DEPDIR)/%.d 
	$(COMPILE.C)  $(IDIR) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

.PHONY: force

cxx_flags: force
	@echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u | diff -q $@ - || echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u  > $@

eaudit: $(EAUDITOBJS)
	$(CXX) -o $@ $^  $(IDIR)

eauditd.o: eauditd.C
	$(CXX)  $(DEPFLAGS) $(MCXXFLAGS) -fpic -DCAPTURE_ONLY -c eauditd.C

ecapd.so: eauditd.o
	$(CXX) -shared -o ecapd.so eauditd.o

all: ecapd.so eaudit

include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

clean:
	rm -f cxx_flags audit eaudit *.o *.so .d/*.d
	( cd eval/rdwr && make clean )
	( cd eval/postmark && make clean )
