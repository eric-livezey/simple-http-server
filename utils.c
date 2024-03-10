int numlenul(unsigned long x)
{
    int i = 1;
    while (x >= 10UL)
    {
        x /= 10UL;
        i++;
    }
    return i;
}

int log2floor(int x)
{
    int log = 0;
    if (x <= 0) // invalid logarithm
        return -1;
    while (x >= 2)
    {
        x >>= 1;
        log++;
    }
    return log;
}

int log2ceil(int x)
{
    int log = 0;
    if (x <= 0) // invalid logarithm
        return -1;
    x <<= 1;
    x--;
    while (x >= 2)
    {
        x >>= 1;
        log++;
    }
    return log;
}