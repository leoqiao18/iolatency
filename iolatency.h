#ifndef __IOLATENCY_H__
#define __IOLATENCY_H__

#define HISTOGRAM_NCOLUMN 17
#define HISTOGRAM_HEIGHT 40

typedef uint64_t histogram[HISTOGRAM_NCOLUMN + 1];

void print_histogram(histogram);

#endif