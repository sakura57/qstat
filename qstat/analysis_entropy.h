#ifndef _ANALYSIS_ENTROPY_H
#define _ANALYSIS_ENTROPY_H

#include "analysis_basic.h"

//Sections marked as code are reported as probably packed
//if computed entropy is above this value.
#define ENTROPY_THRESHOLD 7.0f

int analysis_entropy(struct analysis_base *);

#endif
