using System;

namespace TorNet.Cryptography
{
    internal class BigInteger
    {
        internal BigInteger()
        {
            _impl = null;
            GlobalInit();
        }

        internal BigInteger(byte[] input)
            : this()
        {
            FromBytes(input);
        }

        internal BigInteger(BigInteger other)
            : this()
        {
            _impl = bigint_ctx.bi_clone(other._impl);
        }

        //internal BigInteger(BigInteger other)
        //    : this()
        //{
        //    Helpers.Swap(ref _impl, ref other._impl);
        //}

        internal BigInteger(bigint impl)
        {
            _impl = impl;
            return;
        }

        ~BigInteger()
        {
            if (null != _impl) {
                bigint_ctx.bi_free(_impl);
            }
        }

        // TODO 
        //        big_integer& big_integer::operator=(
        //  const big_integer& other
        //  )
        //{
        //  _impl = bi_clone(bigint_ctx, other._impl);

        //  return *this;
        //}

        //    big_integer& big_integer::operator=(
        //      big_integer&& other

        //      )
        //    {
        //        swap(_impl, other._impl);

        //        return *this;
        //    }

        //    big_integer& big_integer::operator=(
        //  const byte_buffer_ref input
        //      )
        //    {
        //        from_bytes(input);

        //        return *this;
        //    }

        internal static BigInteger FromBytes(byte[] input)
        {
            return new BigInteger() {
                _impl = bigint_ctx.bi_import(input, (int)input.Length)
            };
        }

        private void GlobalDestroy()
        {
            bigint_ctx.bi_terminate();
            bigint_ctx = null;
        }

        private void GlobalInit()
        {
            if (null == bigint_ctx) {
                bigint_ctx = BI_CTX.bi_initialize();
            }
        }

        internal byte[]  ToBytes()
        {
            byte[] result = new byte[_impl.size * COMP_BYTE_SIZE];
            bigint_ctx.bi_export(_impl, result, (int)result.Length);
            return result;
        }

        internal BigInteger mod_pow(BigInteger modulus, BigInteger exponent)
        {
            BI_CTX tmp_ctx = BI_CTX.bi_initialize();
            tmp_ctx.bi_set_mod(tmp_ctx.bi_clone(modulus._impl),
                BIGINT_M_OFFSET);
            bigint tmp_biR = tmp_ctx.bi_mod_power(tmp_ctx.bi_clone(_impl),
                tmp_ctx.bi_clone(exponent._impl));
            bigint biR = bigint_ctx.bi_clone(tmp_biR);
            tmp_ctx.bi_free(tmp_biR);
            tmp_ctx.bi_free_mod(BIGINT_M_OFFSET);
            tmp_ctx.bi_terminate();
            return new BigInteger(biR);
        }

        //big_integer::operator byte_buffer()
        //{
        //    return to_bytes();
        //}

        private static BI_CTX bigint_ctx = null;
        private bigint _impl;

        /* Maintain a number of precomputed variables when doing reduction */
        private const int BIGINT_M_OFFSET = 0;    /**< Normal modulo offset. */
        private const int BIGINT_NUM_MODS = 1;

        /* Architecture specific functions for big ints */
        private const ulong COMP_RADIX = 4294967296; /**< Max component + 1 */
        private const ulong COMP_MAX = 0xFFFFFFFFFFFFFFFF; /**< (Max dbl comp -1) */
        private const int COMP_BIT_SIZE = 32;  /**< Number of bits in a component. */
        private const int COMP_BYTE_SIZE = 4;   /**< Number of bytes in a component. */
        private const int COMP_NUM_NIBBLES = 8;   /**< Used For diagnostics only. */
        // typedef uint32_t comp;	        /**< A single precision component. */
        // typedef uint64_t long_comp;     /**< A double precision component. */
        // typedef int64_t slong_comp;     /**< A signed double precision component. */

        /* @struct  _bigint
         * @brief A big integer basic object */
        internal class bigint
        {
            /* @brief Increment the number of references to this object.
             * It does not do a full copy.
             * @param bi [in]   The bigint to copy.
             * @return A reference to the same bigint. */
            internal bigint bi_copy()
            {
                if (this.refs != PERMANENT) { this.refs++; }
                return this;
            }

            /* @brief Simply make a bigint object "unfreeable" if bi_free() is called on it.
             * For this object to be freed, bi_depermanent() must be called.
             * @param bi [in]   The bigint to be made permanent. */
            internal void bi_permanent()
            {
                if (this.refs != 1) {
                    throw new InvalidOperationException();
                }
                this.refs = PERMANENT;
            }

            /* Is a particular bit is an exponent 1 or 0? Used when doing sliding-window
             * exponentiation. */
            internal bool exp_bit_is_one(int offset)
            {
                uint test = this.comps[offset / COMP_BIT_SIZE];
                int num_shifts = offset % COMP_BIT_SIZE;
                uint shift = 1;
                for (int i = 0; i < num_shifts; i++) {
                    shift <<= 1;
                }
                return (test & shift) != 0;
            }

            /* Work out the highest '1' bit in an exponent. Used when doing sliding-window
             * exponentiation. */
            internal int find_max_exp_index()
            {
                int i = COMP_BIT_SIZE - 1;
                uint shift = (uint)(COMP_RADIX / 2);
                uint test = this.comps[this.size - 1];    /* assume no leading zeroes */
                do {
                    if (0 != (test & shift)) {
                        return i + (this.size - 1) * COMP_BIT_SIZE;
                    }
                    shift >>= 1;
                } while (i-- != 0);
                return -1;      /* error - must have been a leading 0 */
            }

            /* Allocate and zero more components.  Does not consume bi. */
            internal void more_comps(short n)
            {
                if (n > this.max_comps) {
                    this.max_comps = Math.Max((short)(this.max_comps * 2), n);
                    this.comps = Helpers.Extend(this.comps, this.max_comps * COMP_BYTE_SIZE);
                }
                else {
                    // No need to zeroize on reallocation. Already handled by the
                    // Extend method.
                    if (n > this.size) {
                        this.comps.Zeroize(this.size);
                    }
                }
                this.size = n;
                return;
            }

            /* Delete any leading 0's (and allow for 0). */
            internal bigint trim()
            {
                while (this.comps[this.size - 1] == 0 && this.size > 1) {
                    this.size--;
                }
                return this;
            }

            internal uint V1
            {
                get { return this.comps[this.size - 1]; }
            }

            internal uint V2
            {
                get { return this.comps[this.size - 2]; }
            }
            //#define V1      v->comps[v->size-1]                 /**< v1 for division */
            //#define V2      v->comps[v->size-2]                 /**< v2 for division */

            internal uint U(int j)
            {
                return this.comps[this.size - j - 1];
            }
            //#define U(j)    tmp_u->comps[tmp_u->size-j-1]       /**< uj for division */

            internal uint GetQ(int j)
            {
                return this.comps[this.size - j - 1];
            }

            internal void SetQ(int j, uint value)
            {
                this.comps[this.size - j - 1] = value;
            }

            //#define Q(j)    quotient->comps[quotient->size-j-1] /**< qj for division */
            internal bigint next;       /**< The next bigint in the cache. */
            internal short size;                 /**< The number of components in this bigint. */
            internal short max_comps;            /**< The heapsize allocated for this bigint */
            internal int refs;                   /**< An internal reference count. */
            internal uint[] comps;                /**< A ptr to the actual component data */
        }

        /* Maintains the state of the cache, and a number of variables used in
         * reduction. */
        internal class BI_CTX /**< A big integer "session" context. */
        {
            /* Make a new empty bigint. It may just use an old one if one is available.
             * Otherwise get one off the heap. */
            private bigint Allocate(short size)
            {
                bigint result;

                /* Can we recycle an old bigint? */
                if (null != this.free_list) {
                    result = this.free_list;
                    this.free_list = result.next;
                    this.free_count--;
                    if (0 != result.refs) {
                        throw new InvalidOperationException();
                    }
                    result.more_comps(size);
                }
                else {
                    /* No free bigints available - create a new one. */
                    result = new bigint();
                    result.comps = new uint[size];
                    result.max_comps = size;  /* give some space to spare */
                }
                result.size = (short)size;
                result.refs = 1;
                result.next = null;
                this.active_count++;
                return result;
            }

            /* @brief Start a new bigint context.
             * @return A bigint context. */
            internal static BI_CTX bi_initialize()
            {
                /* calloc() sets everything to zero */
                BI_CTX ctx = new BI_CTX();
                /* the radix */
                ctx.bi_radix = ctx.Allocate(2);
                ctx.bi_radix.comps[0] = 0;
                ctx.bi_radix.comps[1] = 1;
                ctx.bi_radix.bi_permanent();
                return ctx;
            }

            /* @brief Close the bigint context and free any resources.
             * Free up any used memory - a check is done if all objects were not
             * properly freed.
             * @param ctx [in]   The bigint session context. */
            internal void bi_terminate()
            {
                bi_depermanent(this.bi_radix);
                this.bi_free(this.bi_radix);
                if (0 != this.active_count) {
                    throw new InvalidOperationException();
                }
                this.bi_clear_cache();
            }

            /*@brief Clear the memory cache. */
            internal void bi_clear_cache()
            {
                bigint pn;

                if (null == this.free_list) { return; }
                for (bigint p = this.free_list; null != p; p = pn) {
                    pn = p.next;
                    p.comps = null;
                }
                this.free_count = 0;
                this.free_list = null;
            }

            /* @brief Take a permanent object and make it eligible for freedom.
             * @param bi [in]   The bigint to be made back to temporary. */
            internal void bi_depermanent(bigint bi)
            {
                if (bi.refs != PERMANENT) {
                    throw new InvalidOperationException();
                }
                bi.refs = 1;
            }

            /* @brief Free a bigint object so it can be used again.
             * The memory itself it not actually freed, just tagged as being available
             * @param ctx [in]   The bigint session context.
             * @param bi [in]    The bigint to be freed. */
            internal void bi_free(bigint bi)
            {
                if (bi.refs == PERMANENT) { return; }
                if (--bi.refs > 0) { return; }
                bi.next = this.free_list;
                this.free_list = bi;
                this.free_count++;
                if (--this.active_count < 0) {
                    throw new InvalidOperationException();
                }
            }

            /* @brief Convert an (unsigned) integer into a bigint.
             * @param ctx [in]   The bigint session context.
             * @param i [in]     The (unsigned) integer to be converted. */
            internal bigint int_to_bi(uint i)
            {
                bigint biR = this.Allocate(1);
                biR.comps[0] = i;
                return biR;
            }

            /* @brief Do a full copy of the bigint object.
             * @param ctx [in]   The bigint session context.
             * @param bi  [in]   The bigint object to be copied. */
            internal bigint bi_clone(bigint bi)
            {
                bigint result = this.Allocate(bi.size);
                Buffer.BlockCopy(bi.comps, 0, result.comps, 0, bi.size);
                return result;
            }

            /* @brief Perform an addition operation between two bigints.
             * @param ctx [in]  The bigint session context.
             * @param bia [in]  A bigint.
             * @param bib [in]  Another bigint.
             * @return The result of the addition. */
            internal bigint bi_add(bigint bia, bigint bib)
            {
                short n = Math.Max(bia.size, bib.size);
                bia.more_comps((short)(n + 1));
                bib.more_comps(n);
                uint[] pa = bia.comps;
                uint[] pb = bib.comps;

                int aIndex = 0;
                int bIndex = 0;
                uint carry = 0;
                do {
                    uint sl = pa[aIndex] + pb[bIndex++];
                    uint rl = sl + carry;
                    carry = (uint)(((sl < pa[aIndex]) | (rl < sl)) ? 1 : 0);
                    pa[aIndex++] = rl;
                } while (--n != 0);

                pa[aIndex] = carry;                  /* do overflow */
                this.bi_free(bib);
                return bia.trim();
            }

            /* @brief Perform a subtraction operation between two bigints.
             * @param ctx [in]  The bigint session context.
             * @param bia [in]  A bigint.
             * @param bib [in]  Another bigint.
             * @param is_negative [out] If defined, indicates that the result was negative.
             * is_negative may be null.
             * @return The result of the subtraction. The result is always positive. */
            internal bigint bi_subtract(bigint bia, bigint bib, out bool is_negative)
            {
                short n = bia.size;
                bib.more_comps(n);

                uint carry = 0;
                uint[] pa = bia.comps;
                uint[] pb = bib.comps;
                int aIndex = 0;
                int bIndex = 0;
                do {
                    uint sl = pa[aIndex] - pb[bIndex++];
                    uint rl = sl - carry;
                    carry = (uint)((sl > pa[aIndex]) | (rl > sl) ? 1 : 0);
                    pa[aIndex++] = rl;
                } while (--n != 0);
                is_negative = (0 != carry);
                bi_free(bib.trim());    /* put bib back to the way it was */
                return bia.trim();
            }

            /* Perform a multiply between a bigint an an (unsigned) integer */
            internal bigint bi_int_multiply(bigint bia, uint b)
            {
                int j = 0;
                int n = bia.size;
                bigint result = this.Allocate((short)(n + 1));
                uint carry = 0;
                uint[] r = result.comps;
                uint[] a = bia.comps;
                /* clear things to start with */
                r.Zeroize(0, ((n + 1) * COMP_BYTE_SIZE));
                int rIndex = 0;
                do {
                    ulong tmp = r[rIndex] + (ulong)a[j] * b + carry;
                    r[rIndex++] = (uint)tmp;              /* downsize */
                    carry = (uint)(tmp >> COMP_BIT_SIZE);
                } while (++j < n);
                r[rIndex] = carry;
                bi_free(bia);
                return result.trim();
            }

            /* @brief Does both division and modulo calculations.
             * Used extensively when doing classical reduction.
             * @param ctx [in]  The bigint session context.
             * @param u [in]    A bigint which is the numerator.
             * @param v [in]    Either the denominator or the modulus depending on the mode.
             * @param is_mod [n] Determines if this is a normal division (0) or a reduction
             * (1).
             * @return  The result of the division/reduction. */
            internal bigint bi_divide(bigint u, bigint v, bool is_mod)
            {
                int n = v.size;
                int m = u.size - n;
                int j = 0;
                int orig_u_size = u.size;
                byte mod_offset = this.mod_offset;
                uint d;
                uint q_dash;

                /* if doing reduction and we are < mod, then return mod */
                if (is_mod && bi_compare(v, u) > 0) {
                    bi_free(v);
                    return u;
                }
                bigint quotient = this.Allocate((short)(m + 1));
                bigint tmp_u = this.Allocate((short)(n + 1));
                v = v.trim();        /* make sure we have no leading 0's */
                d = (uint)((ulong)COMP_RADIX / ((ulong)v.V1 + 1));
                /* clear things to start with */
                quotient.comps.Zeroize();
                /* normalise */
                if (d > 1) {
                    u = bi_int_multiply(u, d);
                    if (is_mod) {
                        v = bi_normalised_mod[mod_offset];
                    }
                    else {
                        v = bi_int_multiply(v, d);
                    }
                }
                if (orig_u_size == u.size) { /* new digit position u0 */
                    u.more_comps((short)(orig_u_size + 1));
                }

                do {
                    /* get a temporary short version of u */
                    Buffer.BlockCopy(u.comps, u.size - n - 1 - j, tmp_u.comps,
                        0, sizeof(uint) * (n + 1));
                    /* calculate q' */
                    if (tmp_u.U(0) == v.V1) {
                        q_dash = (uint)(COMP_RADIX - 1);
                    }
                    else {
                        q_dash = (uint)(((ulong)tmp_u.U(0) * COMP_RADIX + tmp_u.U(1)) / v.V1);

                        if ((v.size > 1) && (0 != v.V2))
                        {
                            /* we are implementing the following:
                            if (V2*q_dash > (((U(0)*COMP_RADIX + U(1) -
                                    q_dash*V1)*COMP_RADIX) + U(2))) ... */
                            uint inner = (uint)((ulong)COMP_RADIX * tmp_u.U(0) + tmp_u.U(1) - (ulong)q_dash * v.V1);
                            if ((ulong)v.V2 * q_dash > (ulong)inner * COMP_RADIX + tmp_u.U(2)) {
                                q_dash--;
                            }
                        }
                    }

                    /* multiply and subtract */
                    if (0 != q_dash) {
                        bool is_negative;
                        tmp_u = bi_subtract(tmp_u, bi_int_multiply(v.bi_copy(), q_dash), out is_negative);
                        tmp_u.more_comps((short)(n + 1));
                        quotient.SetQ(j, q_dash);

                        /* add back */
                        if (is_negative) {
                            quotient.SetQ(j, quotient.GetQ(j) - 1);
                            tmp_u = bi_add(tmp_u, v.bi_copy());
                            /* lop off the carry */
                            tmp_u.size--;
                            v.size--;
                        }
                    }
                    else {
                        quotient.SetQ(j, 0);
                    }
                    /* copy back to u */
                    Buffer.BlockCopy(tmp_u.comps, 0, u.comps, u.size - n - 1 - j,
                        sizeof(uint) * (n + 1));
                } while (++j <= m);
                bi_free(tmp_u);
                bi_free(v);

                if (is_mod) { /* get the remainder */
                    bi_free(quotient);
                    return bi_int_divide(u.trim(), d);
                }
                else { /* get the quotient */
                    bi_free(u);
                    return quotient.trim();
                }
            }

            /* Perform an integer divide on a bigint. */
            internal bigint bi_int_divide(bigint biR, uint denom)
            {
                int i = biR.size - 1;
                ulong r = 0;
                do {
                    r = (r << COMP_BIT_SIZE) + biR.comps[i];
                    biR.comps[i] = (uint)(r / denom);
                    r %= denom;
                } while (--i >= 0);
                return biR.trim();
            }

            /* @brief Allow a binary sequence to be imported as a bigint.
             * @param ctx [in]  The bigint session context.
             * @param data [in] The data to be converted.
             * @param size [in] The number of bytes of data.
             * @return A bigint representing this data. */
            internal bigint bi_import(byte[] data, int size)
            {
                bigint result = this.Allocate((short)((size + COMP_BYTE_SIZE - 1) / COMP_BYTE_SIZE));
                int j = 0;
                int offset = 0;
                result.comps.Zeroize();
                for (int i = size-1; i >= 0; i--) {
                    result.comps[offset] += (uint)(data[i] << (j * 8));
                    if (++j == COMP_BYTE_SIZE) {
                        j = 0;
                        offset ++;
                    }
                }
                return result.trim();
            }

            /* @brief Take a bigint and convert it into a byte sequence.
             * This is useful after a decrypt operation.
             * @param ctx [in]  The bigint session context.
             * @param x [in]  The bigint to be converted.
             * @param data [out] The converted data as a byte stream.
             * @param size [in] The maximum size of the byte stream. Unused bytes will be
             * zeroed. */
            internal void bi_export(bigint x, byte[] data, int size)
            {
                int i, j, k = size - 1;
                data.Zeroize(0, size);  /* ensure all leading 0's are cleared */

                for (i = 0; i < x.size; i++) {
                    for (j = 0; j < COMP_BYTE_SIZE; j++) {
                        uint mask = (uint)(0xff << (j * 8));
                        int num = (int)(x.comps[i] & mask) >> (j * 8);
                        data[k--] = (byte)num;
                        if (k < 0) {
                            return;
                        }
                    }
                }
            }

            /* @brief Pre-calculate some of the expensive steps in reduction.
             * This function should only be called once (normally when a session starts).
             * When the session is over, bi_free_mod() should be called. bi_mod_power()
             * relies on this function being called.
             * @param ctx [in]  The bigint session context.
             * @param bim [in]  The bigint modulus that will be used.
             * @param mod_offset [in] There are three moduluii that can be stored - the
             * standard modulus, and its two primes p and q. This offset refers to which
             * modulus we are referring to.
             * @see bi_free_mod(), bi_mod_power(). */
            internal void bi_set_mod(bigint bim, int mod_offset)
            {
                int k = bim.size;
                uint d = (uint)((ulong)COMP_RADIX / ((ulong)bim.comps[k - 1] + 1));

                this.bi_mod[mod_offset] = bim;
                this.bi_mod[mod_offset].bi_permanent();
                this.bi_normalised_mod[mod_offset] = bi_int_multiply(bim, d);
                this.bi_normalised_mod[mod_offset].bi_permanent();
            }

            /* @brief Used when cleaning various bigints at the end of a session.
             * @param ctx [in]  The bigint session context.
             * @param mod_offset [in] The offset to use.
             * @see bi_set_mod(). */
            internal void bi_free_mod(int mod_offset)
            {
                bi_depermanent(this.bi_mod[mod_offset]);
                bi_free(this.bi_mod[mod_offset]);
                bi_depermanent(this.bi_normalised_mod[mod_offset]);
                bi_free(this.bi_normalised_mod[mod_offset]);
            }

            /* Perform a standard multiplication between two bigints.
             * Barrett reduction has no need for some parts of the product, so ignore bits
             * of the multiply. This routine gives Barrett its big performance
             * improvements over Classical/Montgomery reduction methods. */
            internal bigint regular_multiply(bigint bia, bigint bib, int inner_partial,
                int outer_partial)
            {
                int i = 0, j;
                int n = bia.size;
                int t = bib.size;
                bigint result = this.Allocate((short)(n + t));
                uint[] sr = result.comps;
                uint[] sa = bia.comps;
                uint[] sb = bib.comps;

                /* clear things to start with */
                result.comps.Zeroize();
                do {
                    ulong tmp;
                    uint carry = 0;
                    int r_index = i;
                    j = 0;
                    if (   (0 != outer_partial)
                        && ((outer_partial - i) > 0)
                        && (outer_partial < n))
                    {
                        r_index = outer_partial - 1;
                        j = outer_partial - i - 1;
                    }
                    do {
                        if (   (0 != inner_partial)
                            && (r_index >= inner_partial))
                        {
                            break;
                        }
                        tmp = sr[r_index] + ((ulong)sa[j]) * sb[i] + carry;
                        sr[r_index++] = (uint)tmp;              /* downsize */
                        carry = (uint)(tmp >> COMP_BIT_SIZE);
                    } while (++j < n);
                    sr[r_index] = carry;
                } while (++i < t);
                bi_free(bia);
                bi_free(bib);
                return result.trim();
            }

            /* @brief Perform a multiplication operation between two bigints.
             * @param ctx [in]  The bigint session context.
             * @param bia [in]  A bigint.
             * @param bib [in]  Another bigint.
             * @return The result of the multiplication. */
            internal bigint bi_multiply(bigint bia, bigint bib)
            {
                return regular_multiply(bia, bib, 0, 0);
            }

            /* @brief Compare two bigints.
             * @param bia [in]  A bigint.
             * @param bib [in]  Another bigint.
             * @return -1 if smaller, 1 if larger and 0 if equal. */
            internal int bi_compare(bigint bia, bigint bib)
            {
                if (bia.size > bib.size) { return 1; }
                if (bia.size < bib.size) { return -1; }
                uint[] a = bia.comps;
                uint[] b = bib.comps;

                /* Same number of components.  Compare starting from the high end
                 * and working down. */
                int i = bia.size - 1;
                do {
                    if (a[i] > b[i]) { return 1; }
                    if (a[i] < b[i]) { return -1; }
                } while (--i >= 0);
                return 0;
            }

            /* @brief Perform a modular exponentiation.
             * This function requires bi_set_mod() to have been called previously. This is
             * one of the optimisations used for performance.
             * @param ctx [in]  The bigint session context.
             * @param bi  [in]  The bigint on which to perform the mod power operation.
             * @param biexp [in] The bigint exponent.
             * @return The result of the mod exponentiation operation
             * @see bi_set_mod(). */
            internal bigint bi_mod_power(bigint bi, bigint biexp)
            {
                int i = biexp.find_max_exp_index();
                int window_size = 1;
                bigint biR = this.int_to_bi(1);

                this.g = new bigint[] { this.bi_clone(bi) };
                this.window = 1;
                this.g[0].bi_permanent();

                /* if sliding-window is off, then only one bit will be done at a time and
                 * will reduce to standard left-to-right exponentiation */
                do {
                    if (biexp.exp_bit_is_one(i)) {
                        int l = i - window_size + 1;
                        int part_exp = 0;
                        if (l < 0) {
                            /* LSB of exponent will always be 1 */
                            l = 0;
                        }
                        else {
                            while (!biexp.exp_bit_is_one(l)) {
                                l++;    /* go back up */
                            }
                        }

                        /* build up the section of the exponent */
                        for (int j = i; j >= l; j--)
                        {
                            biR = this.bi_Modulo(this.bi_square(biR));
                            if (biexp.exp_bit_is_one(j)) {
                                part_exp++;
                            }
                            if (j != l) {
                                part_exp <<= 1;
                            }
                        }

                        part_exp = (part_exp - 1) / 2;  /* adjust for array */
                        biR = this.bi_Modulo(this.bi_multiply(biR, this.g[part_exp]));
                        i = l - 1;
                    }
                    else {   /* square it */
                        biR = this.bi_Modulo(this.bi_square(biR));
                        i--;
                    }
                } while (i >= 0);
                /* cleanup */
                for (i = 0; i < this.window; i++) {
                    bi_depermanent(this.g[i]);
                    this.bi_free(this.g[i]);
                }
                this.g = null;
                this.bi_free(bi);
                this.bi_free(biexp);
                return biR;
            }

            ///* @def bi_mod
            // * Find the residue of B. bi_set_mod() must be called before hand. */
            internal bigint bi_Modulo(bigint B)
            {
                return bi_divide(B, this.bi_mod[this.mod_offset], true);
            }

            /* bi_residue() is technically the same as bi_mod(), but it uses the
             * appropriate reduction technique (which is bi_mod() when doing classical
             * reduction). */
            // #define bi_residue(A, B)         bi_mod(A, B)

            internal bigint bi_square(bigint B)
            {
                return this.bi_multiply(B.bi_copy(), B);
            }

            internal bigint active_list;                    /**< Bigints currently used. */
            internal bigint free_list;                      /**< Bigints not used. */
            internal bigint bi_radix;                       /**< The radix used. */
            internal bigint[] bi_mod = new bigint[BIGINT_NUM_MODS];        /**< modulus */

            internal bigint[] bi_normalised_mod = new bigint[BIGINT_NUM_MODS]; /**< Normalised mod storage. */
            internal bigint[] g;                 /**< Used by sliding-window. */
            internal int window;                 /**< The size of the sliding window */
            internal int active_count;           /**< Number of active bigints. */
            internal int free_count;             /**< Number of free bigints. */
            internal byte mod_offset;         /**< The mod offset we are using */
        }
        private const int PERMANENT = 0x7FFF55AA;  /**< A magic number for permanents. */
    }
}
