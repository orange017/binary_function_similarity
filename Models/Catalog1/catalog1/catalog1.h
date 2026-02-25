#ifndef CATALOG1_H
#define CATALOG1_H

#ifdef _WIN32
#define CATALOG1_API __declspec(dllexport)
#else
#define CATALOG1_API
#endif

// Sign data of length len.
// Put the resulting signature inside the array result. Calculate num_perms
// permutations.
CATALOG1_API int sign(
    unsigned char* data,
    unsigned int len,
    unsigned int *result,
    unsigned int num_perms);

#endif // CATALOG1_H