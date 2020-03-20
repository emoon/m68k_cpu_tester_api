#ifndef __MACCESS_H__
#define __MACCESS_H__

#include <stdlib.h>

 /*
  * UAE - The Un*x Amiga Emulator
  *
  * Memory access functions
  *
  * Copyright 1996 Bernd Schmidt
  */

#define ALIGN_POINTER_TO32(p) ((~(unsigned long)(p)) & 3)

STATIC_INLINE uae_u64 do_get_mem_quad(uae_u64 *a)
{
  uae_u64 value = *a;
  return ((value & 0xFF00000000000000u) >> 56u) |
         ((value & 0x00FF000000000000u) >> 40u) |
         ((value & 0x0000FF0000000000u) >> 24u) |
         ((value & 0x000000FF00000000u) >>  8u) |
         ((value & 0x00000000FF000000u) <<  8u) |
         ((value & 0x0000000000FF0000u) << 24u) |
         ((value & 0x000000000000FF00u) << 40u) |
         ((value & 0x00000000000000FFu) << 56u);
}

STATIC_INLINE uae_u32 do_get_mem_long(uae_u32 *a)
{
    uae_u32 val = ((*a << 8) & 0xFF00FF00 ) | ((*a >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

STATIC_INLINE uae_u16 do_get_mem_word(uae_u16 *a)
{
    return (*a << 8) | ((*a >> 8) & 0xFF);
}

#define do_get_mem_byte(a) ((uae_u32)*(uae_u8 *)(a))

STATIC_INLINE void do_put_mem_quad(uae_u64 *a, uae_u64 v)
{
	*a = do_get_mem_quad(&v);
}

STATIC_INLINE void do_put_mem_long(uae_u32 *a, uae_u32 v)
{
	*a = do_get_mem_long(&v);
}

STATIC_INLINE void do_put_mem_word(uae_u16 *a, uae_u16 v)
{
	*a = do_get_mem_word(&v);
}

STATIC_INLINE void do_put_mem_byte(uae_u8 *a, uae_u8 v)
{
    *a = v;
}

#define call_mem_get_func(func, addr) ((*func)(addr))
#define call_mem_put_func(func, addr, v) ((*func)(addr, v))

#endif
