
static int crypto_verify_32(const void* x, const void* y)
{
   return mem_neq(x, y, 32) ^ 0x01;
}
