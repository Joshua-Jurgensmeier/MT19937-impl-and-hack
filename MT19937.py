# File:     MT19937.py
# Author:   Joshua Jurgensmeier
# Class:    CS 399 Cyptography
# Prof.:    Dan Kurfis

import math


class MersenneTwister19937:
    # All these parameters come from the original paper.
    # http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf
    w = 32           # Word size in bits
    n = 624          # State size-1 in words
    m = 397          # Word offset for computing twist
    r = 31           # Determines masks for computing twist
    a = 0x9908B0DF   # Bottom row of matrix A for computing twist
    u = 11           # Shift for tempering (outputting a byte from state)
    s = 7            # Shift for tempering
    b = 0x9D2C5680   # Mask for tempering
    t = 15           # Shift for tempering
    c = 0xEFC60000   # Mask for tempering
    l = 18           # Shift for tempering

    # Masks used in initialization and twist
    # Bitmask to only keep w bits (python int is arbitrarily sized)
    w_mask = (1 << w) - 1
    lower_mask = (1 << r) - 1   # Bitmask for lower r bits
    upper_mask = ~lower_mask    # Bitmask for upper w-r bits
    upper_mask &= w_mask

    def __init__(self, seed):
        self.state = [0] * self.n  # Current state of generator (an n length list of words)
        self.index = self.n+1    # Index into state

        self._initialize_state(seed)

    # Improved initialization algorithm, published after original paper
    # http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html
    # Note: an underscore before a method name is a Python idiom indicating it is private
    def _initialize_state(self, seed):
        f = 1812433253  # Constant for initalization iteration
        self.state[0] = seed
        for i in range(1, self.n):
            # Perform initialization recurrence
            self.state[i] = f * (self.state[i-1] ^ (self.state[i-1] >> (self.w-2))) + i
            # Truncate to word
            self.state[i] &= self.w_mask

    # Generate next n pseudo-random words and store in self.state
    def _twist(self):
        for i in range(0, self.n):
            # Concatenate upper bits of i with lower bits of i+1
            self.state[i] &= self.upper_mask
            self.state[i] |= self.state[(i+1) % self.n]

            # Multiply by A matrix
            self.state[i] >>= 1
            if self.state[i] % 2:
                self.state[i] ^= self.a

            # XOR with m-offset word
            self.state[i] ^= self.state[(i+self.m) % self.n]

    def _temper(self):
        # Grab word to be tempered and output
        y = self.state[self.index]
        # Increment index for next word
        self.index += 1

        # Multiply by tempering matrix
        y = y ^ (y >> self.u)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        return y

    def next_word(self):
        if self.index >= self.n:
            self.index = 0
            self._twist()
        return self._temper()

class StreamCipher:
    def __init__(self, key):
        self.source_mt = MersenneTwister19937(key)

    # Take in bytes plaintext, encrypt by XORing with key stream from MT, and return bytes ciphertext.
    def encrypt(self, plaintext):
        char_mask = (1 << 8) - 1  # Bitmask to only keep 8 bits
        # Initialize ciphertext to 0 bytes
        ciphertext = ["0"] * len(plaintext)

        # Encrypt plaintext. This is unfortunately very ugly.
        for i in range(len(plaintext)):
            if i % 4 == 0:
                # Get next 32-bit word of keystream
                key_word = self.source_mt.next_word()

            # XOR appropriate byte of keystream with ciphertext byte
            shift = (3 - (i % 4)) * 8
            ciphertext[i] = chr(ord(plaintext[i]) ^ ((key_word >> shift) & char_mask))

        return ''.join(ciphertext)


class MThacker:
    # Create 4 * 624 byte known plaintext
    payload = "hack" * MersenneTwister19937.n

    def __init__(self):
        self.hkd_mt = MersenneTwister19937(1234)

    # Multiply by inverse of tempering matrix
    # I wasn't able to figure this part out myself
    # https://occasionallycogent.com/inverting_the_mersenne_temper/index.html
    def _untemper(self, word):
        y = word ^ (word >> self.hkd_mt.l)
        y = y ^ ((y << self.hkd_mt.t) & self.hkd_mt.c)
        y = y ^ ((y << self.hkd_mt.s) & 0x00001680)
        y = y ^ ((y << self.hkd_mt.s) & 0x000c4000)
        y = y ^ ((y << self.hkd_mt.s) & 0x0d200000)
        y = y ^ ((y << self.hkd_mt.s) & 0x90000000)
        y = y ^ ((y >> self.hkd_mt.u) & 0xffc00000)
        y = y ^ ((y >> self.hkd_mt.u) & 0x003ff800)
        y = y ^ ((y >> self.hkd_mt.u) & 0x000007ff)

        return y

    # Use known plaintext and untempering to duplicate state of stream_cipher's MT
    def hack_stream(self, stream_cipher):
        # Inject known plaintext into stream cipher
        ciphertext = stream_cipher.encrypt(self.payload)

        # Get keystream
        # Fancy python for XORing ciphertext with plaintext
        byte_keystream = [ord(c) ^ ord(p) for (c, p) in zip(ciphertext, self.payload)]

        # Bitwise concatenate keystream bytes to form words
        word_keystream = [0] * (len(byte_keystream) // 4)
        for i in range(len(word_keystream)):
            for j in range(4):
                word_keystream[i] |= byte_keystream[(i*4) + j] << ((3-j) * 8)

        # Untemper keystream and copy into MT state
        for i in range(len(word_keystream)):
            self.hkd_mt.state[i] = self._untemper(word_keystream[i])

        # My MT and stream_cipher's MT now have the same state
        # print(self.hkd_mt.state == stream_cipher.source_mt.state)

    # Precondition: My MT and stream_cipher's MT had the same state when ciphertext was encrypted
    # (hack_stream was called immediately preceeding the encryption)
    def decrypt(self, ciphertext):
        char_mask = (1 << 8) - 1  # Bitmask to only keep 8 bits
        # Initialize plaintext to 0 bytes
        plaintext = ["0"] * len(ciphertext)

        # Decrypt ciphertext. This is unfortunately very ugly.
        for i in range(len(ciphertext)):
            if i % 4 == 0:
                # Get next 32-bit word of keystream
                key_word = self.hkd_mt.next_word()

            # XOR appropriate byte of keystream with ciphertext byte
            shift = (3 - (i % 4)) * 8
            plaintext[i] = chr(ord(ciphertext[i]) ^ ((key_word >> shift) & char_mask))

        return ''.join(plaintext)


def main():
    # Instantiate objects
    sc = StreamCipher(129784)
    mth = MThacker()

    # Perform known-plaintext attack on stream cipher to capture its
    # MT state vector
    mth.hack_stream(sc)

    # Attacker's MT state is equal to stream cipher's

    # User requests encryption of their plaintext
    plaintext = input("Enter plaintext message to be encrypted: ")
    ciphertext = sc.encrypt(plaintext)

    # Attacker takes ciphertext and decrypts it, using the
    # previously captured MT state vector
    hacked_plaintext = mth.decrypt(ciphertext)

    # Display
    print()
    print("Plaintext:\n", plaintext)
    print()
    print("Ciphertext:\n", ciphertext.encode(encoding="utf-8", errors="replace"))
    print()
    print("Hacked Plaintext:\n", hacked_plaintext)
    print()
    input("Press the any key to quit...")


if __name__ == "__main__":
    main()
