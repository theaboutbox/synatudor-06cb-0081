/*
 * SHA-1 hash implementation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "bcrypt_internal.h"

static DWORD rol( DWORD value, unsigned int count )
{
    return (value << count) | (value >> (32 - count));
}

static void process_block( SHA_CTX *ctx, const UCHAR *buffer )
{
    DWORD words[80], a, b, c, d, e, f, k, temp;
    unsigned int i;

    for (i = 0; i < 16; ++i)
    {
        words[i] = (DWORD)buffer[4 * i] << 24;
        words[i] |= (DWORD)buffer[4 * i + 1] << 16;
        words[i] |= (DWORD)buffer[4 * i + 2] << 8;
        words[i] |= buffer[4 * i + 3];
    }
    for (; i < 80; ++i)
        words[i] = rol( words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1 );

    a = ctx->State[0];
    b = ctx->State[1];
    c = ctx->State[2];
    d = ctx->State[3];
    e = ctx->State[4];

    for (i = 0; i < 80; ++i)
    {
        if (i < 20)
        {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }

        temp = rol( a, 5 ) + f + e + k + words[i];
        e = d;
        d = c;
        c = rol( b, 30 );
        b = a;
        a = temp;
    }

    ctx->State[0] += a;
    ctx->State[1] += b;
    ctx->State[2] += c;
    ctx->State[3] += d;
    ctx->State[4] += e;
}

void WINAPI A_SHAInit( SHA_CTX *ctx )
{
    memset( ctx, 0, sizeof(*ctx) );
    ctx->State[0] = 0x67452301;
    ctx->State[1] = 0xefcdab89;
    ctx->State[2] = 0x98badcfe;
    ctx->State[3] = 0x10325476;
    ctx->State[4] = 0xc3d2e1f0;
}

void WINAPI A_SHAUpdate( SHA_CTX *ctx, const UCHAR *buffer, UINT size )
{
    ULONG64 length = ((ULONG64)ctx->Count[1] << 32) | ctx->Count[0];
    unsigned int remainder = length % sizeof(ctx->Buffer);
    const UCHAR *input = buffer;

    length += size;
    ctx->Count[0] = length;
    ctx->Count[1] = length >> 32;

    if (remainder)
    {
        unsigned int available = sizeof(ctx->Buffer) - remainder;

        if (size < available)
        {
            memcpy( ctx->Buffer + remainder, input, size );
            return;
        }

        memcpy( ctx->Buffer + remainder, input, available );
        process_block( ctx, ctx->Buffer );
        input += available;
        size -= available;
    }

    while (size >= sizeof(ctx->Buffer))
    {
        process_block( ctx, input );
        input += sizeof(ctx->Buffer);
        size -= sizeof(ctx->Buffer);
    }

    if (size) memcpy( ctx->Buffer, input, size );
}

void WINAPI A_SHAFinal( SHA_CTX *ctx, PULONG result )
{
    ULONG64 length = ((ULONG64)ctx->Count[1] << 32) | ctx->Count[0];
    ULONG64 bit_length = length << 3;
    unsigned int remainder = length % sizeof(ctx->Buffer);
    UCHAR *output = (UCHAR *)result;
    unsigned int i;

    ctx->Buffer[remainder++] = 0x80;
    if (remainder > 56)
    {
        memset( ctx->Buffer + remainder, 0, sizeof(ctx->Buffer) - remainder );
        process_block( ctx, ctx->Buffer );
        remainder = 0;
    }

    memset( ctx->Buffer + remainder, 0, 56 - remainder );
    for (i = 0; i < 8; ++i)
        ctx->Buffer[56 + i] = bit_length >> (56 - 8 * i);
    process_block( ctx, ctx->Buffer );

    for (i = 0; i < 5; ++i)
    {
        output[4 * i] = ctx->State[i] >> 24;
        output[4 * i + 1] = ctx->State[i] >> 16;
        output[4 * i + 2] = ctx->State[i] >> 8;
        output[4 * i + 3] = ctx->State[i];
    }
}
