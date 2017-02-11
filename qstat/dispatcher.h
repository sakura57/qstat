#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include "strings.h"
#include "analysis_all.h"

#define MAX_ANALYZEFUNCS 200

int dispatch_analysis_func(unsigned int, struct analysis_base *);
void dispatch_add_func(int (*)(struct analysis_base *));

#endif