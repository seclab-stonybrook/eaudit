#ifndef EPARSER_H
#define EPARSER_H

#include <sys/socket.h>
#include <asm/types.h>
#include <sys/un.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <vector>
#include "STLutils.h"

using namespace std;

#include "cmdln.h"

void parser_init();

void parse_stream();
void parse_rec(const char *p, size_t len);

int parseCmdLineAndProcInput(int argc, const char* argv[]);
void parser_finish();
#endif
