class Packet:
    @staticmethod
    def calc_checksum(msg):
        s = 0  # Binary Sum
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            a = msg[i]
            b = msg[i + 1]
            s = s + (a + (b << 8))
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s