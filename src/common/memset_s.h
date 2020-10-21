/**
 * Compiler optimization save variant of memset
 *
 * See CERT C Coding Standard - MSC06-C MSC06-C.
 * Beware of compiler optimization
 *
 * (www.securecoding.cert.org).
 *
 * @param[in]  v  The buffer to clear
 * @param[in]  c  The character to overwrite the buffer with
 * @param[in]  n  Size of said buffer.
 *
 * @ingroup FEPKCS11
 */

#if !defined(HAVE_MEMSET_S)

#ifdef _WIN32
static _inline void *memset_s(void *v, size_t vmax, int c, size_t n)
#else
static inline void *memset_s(void *v, size_t vmax, int c, size_t n)
#endif
{
	volatile unsigned char *p = v;
	while (n-- && vmax--)
		*p++ = c;

	return v;
}

#endif
