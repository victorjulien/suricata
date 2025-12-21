/* Copyright (C) 2007-2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef SURICATA_UTIL_MEMCMP_SSE2_H
#define SURICATA_UTIL_MEMCMP_SSE2_H

#if defined(__SSE2__)
#include "suricata-common.h"
#include "util-optimize.h"
#include <emmintrin.h> /* for SSE2 */
#define SCMEMCMP_BYTES  16

static inline int SCMemcmpSSE2(const uint8_t *s1, const uint8_t *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, c;

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return memcmp(s1 + offset, s2 + offset , len - offset) ? 1 : 0;
        }

        /* unaligned loads */
        b1 = _mm_loadu_si128((const __m128i *)(s1 + offset));
        b2 = _mm_loadu_si128((const __m128i *)(s2 + offset));
        c = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(c) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif  /* SSE2 */
#endif
