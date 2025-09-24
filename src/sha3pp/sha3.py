import math

class NIST_SHA3_Error(Exception):
    """ Custom error Class used in the NIST SHA3 implementation """
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class NIST_SHA3:
    RC = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ]

    r = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]

    def __init__(self, r, c, n, data=None):
        self.r = r
        self.c = c
        self.n = n
        self.b = r + c
        self.w = self.b // 25
        self.l = int(math.log(self.w, 2))
        self.n_r = 12 + 2 * self.l
        self.block_size = r
        self.digest_size = n
        self.S = [[0, 0, 0, 0, 0] for _ in range(5)]
        self.buffered_data = ""
        self.last_digest = None
        if data:
            self.update(data)

    def update(self, arg):
        self.last_digest = None
        if isinstance(arg, str):
            arg_bytes = arg.encode('utf-8')
        else:
            arg_bytes = arg
        self.buffered_data += arg_bytes.hex()
        while len(self.buffered_data) * 4 >= self.r:
            block = self.buffered_data[:2 * self.r // 8]
            self.buffered_data = self.buffered_data[2 * self.r // 8:]
            block += '00' * (self.c // 8)
            P_i = _convertStrToTable(block, self.w, self.b)
            for y in range(5):
                for x in range(5):
                    self.S[x][y] ^= P_i[x][y]
            self.S = NIST_SHA3.sha3_f(self.S, self.n_r, self.w)

    def digest(self):
        if self.last_digest:
            return self.last_digest
        M = _build_message_pair(bytes.fromhex(self.buffered_data))
        self.buffered_data = NIST_SHA3.pad10star1(M, self.r)
        self.update("")
        assert len(self.buffered_data) == 0
        Z = b''
        while len(Z) < self.digest_size:
            for y in range(5):
                for x in range(5):
                    if (5 * y + x) < (self.r // 64):
                        Z += self.S[x][y].to_bytes(8, 'little')
            if len(Z) >= self.digest_size:
                break
            self.S = NIST_SHA3.sha3_f(self.S, self.n_r, self.w)
        self.last_digest = Z[:self.digest_size]
        return self.last_digest

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        duplicate = NIST_SHA3(c=self.c, r=self.r, n=self.n)
        for i in range(5):
            for j in range(5):
                duplicate.S[i][j] = self.S[i][j]
        duplicate.buffered_data = self.buffered_data
        duplicate.last_digest = self.last_digest
        return duplicate

    @staticmethod
    def Round(A, RCfixed, w):
        B = [[0, 0, 0, 0, 0] for _ in range(5)]
        C = [0] * 5
        D = [0] * 5
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ _rot(C[(x + 1) % 5], 1, w)
        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y] ^ D[x]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rot(A[x][y], NIST_SHA3.r[x][y], w)
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        A[0][0] = A[0][0] ^ RCfixed
        return A

    @staticmethod
    def sha3_f(A, n_r, w):
        for i in range(n_r):
            A = NIST_SHA3.Round(A, NIST_SHA3.RC[i] % (1 << w), w)
        return A

# Add top-level SHA3 functions
def sha3_224(data=None):
    return NIST_SHA3(c=448, r=1152, n=224, data=data)

def sha3_256(data=None):
    return NIST_SHA3(c=512, r=1088, n=256, data=data)

def sha3_384(data=None):
    return NIST_SHA3(c=768, r=832, n=384, data=data)

def sha3_512(data=None):
    return NIST_SHA3(c=1024, r=576, n=512, data=data)

    @staticmethod
    def pad10star1(M, n):
        my_string_length, my_string = M
        if n % 8 != 0:
            raise NIST_SHA3_Error("n must be a multiple of 8")
        if len(my_string) % 2 != 0:
            my_string += '0'
        if my_string_length > (len(my_string) // 2 * 8):
            raise NIST_SHA3_Error("the string is too short to contain the number of bits announced")
        nr_bytes_filled = my_string_length // 8
        nbr_bits_filled = my_string_length % 8
        if nbr_bits_filled == 0:
            pad_byte = 0x06
        else:
            pad_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            pad_byte = (pad_byte >> (8 - nbr_bits_filled))
            pad_byte = pad_byte + (0x06 << nbr_bits_filled)
        pad_byte = f"{pad_byte:02X}"
        my_string = my_string[0:nr_bytes_filled * 2] + pad_byte
        while (8 * len(my_string) // 2) % n < (n - 8):
            my_string = my_string + '00'
        my_string = my_string + '80'
        return my_string

    def update(self, arg):
        """
        Update the hash object with the string arg. Repeated calls are equivalent to a single
        call with the concatenation of all the arguments: m.update(a); m.update(b) is equivalent
        to m.update(a+b). arg is a normal bytestring.
        """

        self.last_digest = None
        if isinstance(arg, str):
            arg_bytes = arg.encode('utf-8')
        else:
            arg_bytes = arg
        self.buffered_data += arg_bytes.hex()
        print(f"[update] buffered_data: {self.buffered_data}")

        # Absorb any blocks we can:
        if len(self.buffered_data) * 4 >= self.r:
            extra_bits = len(self.buffered_data) * 4 % self.r
            if extra_bits == 0:
                P = self.buffered_data
                self.buffered_data = ""
            else:
                P = self.buffered_data[:-extra_bits // 4]
                self.buffered_data = self.buffered_data[-extra_bits // 4:]
            for i in range((len(P) * 8 // 2) // self.r):
                to_convert = P[i * (2 * self.r // 8):(i + 1) * (2 * self.r // 8)] + '00' * (self.c // 8)
                print(f"[update] to_convert: {to_convert}")
                P_i = _convertStrToTable(to_convert, self.w, self.b)
                print(f"[update] P_i: {P_i}")
                for y in range(5):
                    for x in range(5):
                        self.S[x][y] = self.S[x][y] ^ P_i[x][y]
                print(f"[update] S before KeccakF: {self.S}")
                self.S = Keccak.KeccakF(self.S, self.n_r, self.w)
                print(f"[update] S after KeccakF: {self.S}")

    def digest(self):
        """
        Return the digest of the strings passed to the update() method so far.
        This is a string of digest_size bytes which may contain non-ASCII
        characters, including null bytes.
        """
        if self.last_digest:
            return self.last_digest
        M = _build_message_pair(bytes.fromhex(self.buffered_data))
        print(f"[digest] M: {M}")
        self.buffered_data = Keccak.pad10star1(M, self.r)
        print(f"[digest] padded buffered_data: {self.buffered_data}")
        self.update("")
        assert len(self.buffered_data) == 0, (
            f"Why is there data left in the buffer? {self.buffered_data} with length {len(self.buffered_data) * 4}"
        )
        Z = ""
        output_length = self.n
        while output_length > 0:
            string = _convertTableToStr(self.S, self.w)
            print(f"[digest] squeezing string: {string}")
            Z = Z + string[:self.r * 2 // 8]
            output_length -= self.r
            # NOTE: Squeezing phase incomplete in original code, left as is
        print(f"[digest] final Z: {Z}")
        self.last_digest = bytes.fromhex(Z[:2 * self.n // 8])
        print(f"[digest] final digest: {self.last_digest.hex()}")
        return self.last_digest

    def hexdigest(self):
        """ Like digest() except the digest is returned as a string of hex digits. """
        return self.digest().hex()

    def copy(self):
        """ Return a copy of the current NIST_SHA3 object. """
        duplicate = NIST_SHA3(c=self.c, r=self.r, n=self.n)
        for i in range(5):
            for j in range(5):
                duplicate.S[i][j] = self.S[i][j]
        duplicate.buffered_data = self.buffered_data
        duplicate.last_digest = self.last_digest
        return duplicate


## Generic utility functions

def _build_message_pair(data):
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    hex_data = data_bytes.hex()
    size = len(hex_data) * 4
    return size, hex_data


def _rot(x, shift_amount, length):
    """ Rotate x shift_amount bits to the left, considering the string of bits is length bits long """
    shift_amount = shift_amount % length
    return ((x >> (length - shift_amount)) + (x << shift_amount)) % (1 << length)

### Conversion functions String <-> Table (and vice-versa)


def _fromHexStringToLane(string):
    """ Convert a string of bytes written in hexadecimal to a lane value """
    if len(string) % 2 != 0:
        raise KeccakError.KeccakError("The provided string does not end with a full byte")
    temp = ''
    nr_bytes = len(string) // 2
    for i in range(nr_bytes):
        offset = (nr_bytes - i - 1) * 2
        temp += string[offset:offset + 2]
    return int(temp, 16)


def _fromLaneToHexString(lane, w):
    """ Convert a lane value to a string of bytes written in hexadecimal """
    lane_hex_be = (f"{lane:0{w // 4}X}")
    temp = ''
    nr_bytes = len(lane_hex_be) // 2
    for i in range(nr_bytes):
        offset = (nr_bytes - i - 1) * 2
        temp += lane_hex_be[offset:offset + 2]
    return temp.upper()


def _convertStrToTable(string, w, b):
    if w % 8 != 0:
        raise NIST_SHA3_Error("w is not a multiple of 8")
    if len(string) * 4 != b:
        raise NIST_SHA3_Error(
            "string can't be divided in 25 blocks of w bits i.e. string must have exactly b bits"
        )
    output = [[0, 0, 0, 0, 0] for _ in range(5)]
    bits_per_char = 2 * w // 8
    for x in range(5):
        for y in range(5):
            offset = (5 * y + x) * bits_per_char
            hexstring = string[offset:offset + bits_per_char]
            output[x][y] = _fromHexStringToLane(hexstring)
    return output


def _convertTableToStr(table, w):
    """ Convert a 5x5 matrix representation to its string representation """
    if w % 8 != 0:
        raise NIST_SHA3_Error("w is not a multiple of 8")
    if (len(table) != 5) or any(len(row) != 5 for row in table):
        raise NIST_SHA3_Error("table must be 5x5")
    output = [''] * 25
    for x in range(5):
        for y in range(5):
            output[5 * y + x] = _fromLaneToHexString(table[x][y], w)
    output = ''.join(output).upper()
    return output