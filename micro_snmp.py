import uselect
import usocket
import uasyncio
import uio as io
import struct
import utime


# ASN.1 tags
from micropython import const

ASN1_BOOLEAN = const(0x01)
ASN1_INTEGER = const(0x02)
ASN1_BIT_STRING = const(0x03)
ASN1_OCTET_STRING = const(0x04)
ASN1_NULL = const(0x05)
ASN1_OBJECT_IDENTIFIER = const(0x06)
ASN1_UTF8_STRING = const(0x0c)
ASN1_PRINTABLE_STRING = const(0x13)
ASN1_IA5_STRING = const(0x16)
ASN1_BMP_STRING = const(0x1e)
ASN1_SEQUENCE = const(0x30)
ASN1_SET = const(0x31)
ASN1_IPADDRESS = const(0x40)
ASN1_COUNTER32 = const(0x41)
ASN1_GAUGE32 = const(0x42)
ASN1_TIMETICKS = const(0x43)
ASN1_OPAQUE = const(0x44)
ASN1_COUNTER64 = const(0x46)
ASN1_NO_SUCH_OBJECT = const(0x80)
ASN1_NO_SUCH_INSTANCE = const(0x81)
ASN1_END_OF_MIB_VIEW = const(0x82)
ASN1_GET_REQUEST_PDU = const(0xA0)
ASN1_GET_NEXT_REQUEST_PDU = const(0xA1)
ASN1_GET_RESPONSE_PDU = const(0xA2)
ASN1_SET_REQUEST_PDU = const(0xA3)
ASN1_TRAP_REQUEST_PDU = const(0xA4)
ASN1_GET_BULK_REQUEST_PDU = const(0xA5)
ASN1_INFORM_REQUEST_PDU = const(0xA6)
ASN1_SNMPv2_TRAP_REQUEST_PDU = const(0xA7)
ASN1_REPORT_REQUEST_PDU = const(0xA8)

# error statuses
ASN1_ERROR_STATUS_NO_ERROR = const(0x00)
ASN1_ERROR_STATUS_TOO_BIG = const(0x01)
ASN1_ERROR_STATUS_NO_SUCH_NAME = const(0x02)
ASN1_ERROR_STATUS_BAD_VALUE = const(0x03)
ASN1_ERROR_STATUS_READ_ONLY = const(0x04)
ASN1_ERROR_STATUS_GEN_ERR = const(0x05)
ASN1_ERROR_STATUS_WRONG_VALUE = const(0x0A)

# some ASN.1 opaque special types
ASN1_CONTEXT = const(0x80)  # context-specific
ASN1_EXTENSION_ID = const(0x1F)  # 0b11111 (fill tag in first octet)
ASN1_OPAQUE_TAG1 = const(ASN1_CONTEXT | ASN1_EXTENSION_ID)  # 0x9f
ASN1_OPAQUE_TAG2 = const(0x30)  # base tag value
ASN1_APPLICATION = const(0x40)
# application-specific type 0x08
ASN1_APP_FLOAT = const(ASN1_APPLICATION | 0x08)
# application-specific type 0x09
ASN1_APP_DOUBLE = const(ASN1_APPLICATION | 0x09)
# application-specific type 0x0A
ASN1_APP_INT64 = const(ASN1_APPLICATION | 0x0A)
# application-specific type 0x0B
ASN1_APP_UINT64 = const(ASN1_APPLICATION | 0x0B)
ASN1_OPAQUE_FLOAT = const(ASN1_OPAQUE_TAG2 | ASN1_APP_FLOAT)
ASN1_OPAQUE_DOUBLE = const(ASN1_OPAQUE_TAG2 | ASN1_APP_DOUBLE)
ASN1_OPAQUE_INT64 = const(ASN1_OPAQUE_TAG2 | ASN1_APP_INT64)
ASN1_OPAQUE_UINT64 = const(ASN1_OPAQUE_TAG2 | ASN1_APP_UINT64)
ASN1_OPAQUE_FLOAT_BER_LEN = const(7)
ASN1_OPAQUE_DOUBLE_BER_LEN = const(11)
ASN1_OPAQUE_INT64_BER_LEN = const(4)
ASN1_OPAQUE_UINT64_BER_LEN = const(4)


SNMP_VERSIONS = {
    1: 'v1',
    2: 'v2c',
    3: 'v3',
}

SNMP_PDUS = (
    'version',
    'community',
    'PDU-type',
    'request-id',
    'error-status',
    'error-index',
    'variable bindings',
)


def info(*msg):
    print("[INFO] ", *msg)


def debug(*msg):
    print("[DEBUG] ", *msg)


def error(*msg):
    print("[ERROR] ", *msg)


class ProtocolError(Exception):
    """Raise when SNMP protocol error occurred"""


class UDPServer:
    """
    A simple UDP server class for handling asynchronous communication.
    Attributes:
        polltimeout (int): The timeout value for polling in seconds. Default is 1 second.
        max_packet (int): The maximum size of the packet to be received. Default is 4096 bytes.
    Methods:
        __init__(polltimeout=1, max_packet=4096):
            Initializes the UDP server with the given poll timeout and maximum packet size.
        close():
            Closes the UDP socket.
        serve(cb, host, port):
            Asynchronously serves the UDP server, calling the provided callback function
            when data is received. Binds the server to the specified host and port.
            Args:
                cb (function): The callback function to handle received data.
                host (str): The host address to bind the server to.
                port (int): The port number to bind the server to.
    """

    def __init__(self, polltimeout=1, max_packet=4096):
        self.polltimeout = polltimeout
        self.max_packet = max_packet

        info("Init server polltimeout:", self.polltimeout,
             ", max_packet:", self.max_packet)

    def close(self):
        self.sock.close()

    async def serve(self, cb, host, port):
        ai = usocket.getaddrinfo(host, port)[0]  # blocking!
        s = usocket.socket(usocket.AF_INET, usocket.SOCK_DGRAM)
        self.sock = s
        s.setblocking(False)
        s.bind(ai[-1])
        info("UDP server listening on port: ", port)

        p = uselect.poll()
        p.register(s, uselect.POLLIN)
        to = self.polltimeout
        while True:
            try:
                if p.poll(to):
                    buf, addr = s.recvfrom(self.max_packet)
                    ret = cb(buf, addr)
                    await uasyncio.sleep(0)
                    if ret:
                        s.sendto(ret, addr)  # blocking
                await uasyncio.sleep(0)
            except uasyncio.CancelledError:
                # Shutdown server
                s.close()
                return


def _is_trap_request(result):
    """Checks if it is Trap-PDU request."""
    return len(result) > 2 and result[2][1] == ASN1_TRAP_REQUEST_PDU


def _validate_protocol(pdu_index, tag, result):
    """
    Validates the protocol based on the PDU (Protocol Data Unit) index and tag.

    Args:
        pdu_index (int): The index of the PDU to validate.
        tag (int): The ASN.1 tag associated with the PDU.
        result (object): The result object containing the PDU data.

    Returns:
        bool: True if the protocol is valid, False otherwise.

    The function checks the validity of the protocol based on the PDU index and tag.
    It handles both trap requests and other types of requests by comparing the PDU index
    and tag against expected values defined by ASN.1 constants.
    """
    """Validates the protocol and returns True if valid, or False otherwise."""
    if _is_trap_request(result):
        if (
                pdu_index == 4 and tag != ASN1_OBJECT_IDENTIFIER or
                pdu_index == 5 and tag != ASN1_IPADDRESS or
                pdu_index in [6, 7] and tag != ASN1_INTEGER or
                pdu_index == 8 and tag != ASN1_TIMETICKS
        ):
            return False
    elif (
            pdu_index in [1, 4, 5, 6] and tag != ASN1_INTEGER or
            pdu_index == 2 and tag != ASN1_OCTET_STRING or
            pdu_index == 3 and tag not in [
                ASN1_GET_REQUEST_PDU,
                ASN1_GET_NEXT_REQUEST_PDU,
                ASN1_SET_REQUEST_PDU,
                ASN1_GET_BULK_REQUEST_PDU,
                ASN1_TRAP_REQUEST_PDU,
                ASN1_INFORM_REQUEST_PDU,
                ASN1_SNMPv2_TRAP_REQUEST_PDU,
            ]
    ):
        return False
    return True


def _read_byte(stream: io.StringIO):
    """
    Read a single byte from the given stream.

    Args:
        stream (io.StringIO): The input stream to read from.

    Returns:
        int: The ASCII value of the read byte.

    Raises:
        Exception: If no more bytes are available to read.
    """
    """Read byte from stream"""
    read_byte = stream.read(1)
    if not read_byte:
        raise Exception('No more bytes!')
    return ord(read_byte)


def _parse_asn1_length(stream: io.StringIO):
    """
    Parse the length of an ASN.1 encoded element from the given stream.

    Args:
        stream (io.StringIO): The input stream to read the ASN.1 length from.

    Returns:
        int: The parsed length of the ASN.1 element.

    Raises:
        Exception: If the data length is not within the range [1..4] for long lengths.
    """
    """Parse ASN.1 length"""
    length = _read_byte(stream)
    # handle long length
    if length > 0x7f:
        data_length = length - 0x80
        if not 0 < data_length <= 4:
            raise Exception('Data length must be in [1..4]')
        length = _read_int_len(stream, data_length)
    return length


def _read_int_len(stream, length, signed=False):
    """
    Reads an integer of a specified length from a stream.

    Args:
        stream (io.BytesIO): The input stream to read from.
        length (int): The number of bytes to read.
        signed (bool, optional): Whether the integer is signed. Defaults to False.

    Returns:
        int: The integer value read from the stream.
    """
    """Read int with length"""
    result = 0
    sign = None
    for _ in range(length):
        value = _read_byte(stream)
        if sign is None:
            sign = value & 0x80
        result = (result << 8) + value
    if signed and sign:
        result = twos_complement(result, 8 * length)
    return result


def twos_complement(value, bits):
    """
    Calculate the two's complement of an integer.

    Args:
        value (int): The integer value to be converted.
        bits (int): The number of bits representing the integer.

    Returns:
        int: The two's complement of the given integer.
    """
    """Calculate two's complement"""
    mask = 2 ** (bits - 1)
    return -(value & mask) + (value & ~mask)


def is_printable(char):
    """
    Check if a character is printable.

    Args:
        char (str): A single character to check.

    Returns:
        bool: True if the character is printable (ASCII 32-126), False otherwise.
    """
    """Returns True if the character is printable (ASCII 32-126)."""
    return 32 <= ord(char) <= 126


def _parse_asn1_octet_string(stream):
    """
    Parse an ASN.1 octet string from the given stream.

    Args:
        stream (io.BytesIO): The input stream to read the octet string from.

    Returns:
        str: The parsed octet string. If any character in the string is not printable,
             the string is converted to a space-separated hexadecimal representation.
    """
    """Parse ASN.1 octet string"""
    length = _parse_asn1_length(stream)
    value = stream.read(length)
    # if any char is not printable - convert string to hex
    if any(c for c in value if not is_printable(c)):
        return ' '.join(['%02X' % ord(x) for x in value])
    return value


def bytes_to_oid(data):
    """
    Convert a sequence of bytes to an OID (Object Identifier) string.

    Args:
        data (bytes): A sequence of bytes representing the OID.

    Returns:
        str: The OID string in dot-separated format.

    Example:
        >>> bytes_to_oid(b'\x2b\x06\x01\x02\x01')
        '1.3.6.1.2.1'
    """
    """Convert bytes to OID str"""
    values = [ord(x) for x in data]
    first_val = values.pop(0)
    res = []
    res += divmod(first_val, 40)
    while values:
        val = values.pop(0)
        if val > 0x7f:
            huge_vals = [val]
            while True:
                next_val = values.pop(0)
                huge_vals.append(next_val)
                if next_val < 0x80:
                    break
            huge = 0
            for i, huge_byte in enumerate(huge_vals):
                huge += (huge_byte & 0x7f) << (7 * (len(huge_vals) - i - 1))
            res.append(huge)
        else:
            res.append(val)
    return '.'.join(str(x) for x in res)


def timeticks_to_str(ticks):
    """
    Convert time ticks to a formatted string.

    This function takes an integer representing time ticks and converts it into a 
    human-readable string format of "days, hours, minutes, seconds and milliseconds".

    Args:
        ticks (int): The number of time ticks to convert.

    Returns:
        str: A string representing the time in "days, hours, minutes, seconds and milliseconds" format.
    """
    """Return "days, hours, minutes, seconds and ms" string from ticks"""
    days, rem1 = divmod(ticks, 24 * 60 * 60 * 100)
    hours, rem2 = divmod(rem1, 60 * 60 * 100)
    minutes, rem3 = divmod(rem2, 60 * 100)
    seconds, milliseconds = divmod(rem3, 100)
    ending = 's' if days > 1 else ''
    days_fmt = '{} day{}, '.format(days, ending) if days > 0 else ''
    return '{}{:-02}:{:-02}:{:-02}.{:-02}'.format(days_fmt, hours, minutes, seconds, milliseconds)


def int_to_ip(value):
    """
    Convert an integer to an IP address string.

    Args:
        value (int): The integer representation of the IP address.

    Returns:
        str: The IP address in dotted-decimal notation.
    """
    """Int to IP"""
    return usocket.inet_ntoa(struct.pack("!I", value))


def _parse_asn1_opaque_float(stream):
    """
    Parse an ASN.1 encoded opaque float from the given stream.

    Args:
        stream (io.BytesIO): The input stream containing the ASN.1 encoded data.

    Returns:
        tuple: A tuple containing the string 'FLOAT' and the parsed float value rounded to 5 decimal places.

    Raises:
        ValueError: If the length of the ASN.1 encoded data is invalid or if the float conversion fails.
    """
    """Parse ASN.1 opaque float"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    # convert int to float
    float_value = struct.unpack('>f', struct.pack('>l', value))[0]
    debug('ASN1_OPAQUE_FLOAT: %s', round(float_value, 5))
    return 'FLOAT', round(float_value, 5)


def _parse_asn1_opaque_double(stream):
    """
    Parse an ASN.1 encoded opaque double from the given stream.

    Args:
        stream (io.BytesIO): The input stream containing the ASN.1 encoded data.

    Returns:
        tuple: A tuple containing the string 'DOUBLE' and the parsed double value rounded to 5 decimal places.

    Raises:
        ValueError: If the length of the ASN.1 encoded data is invalid or if the data cannot be unpacked as a double.
    """
    """Parse ASN.1 opaque double"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    # convert long long to double
    double_value = struct.unpack('>d', struct.pack('>q', value))[0]
    debug('ASN1_OPAQUE_DOUBLE: %s', round(double_value, 5))
    return 'DOUBLE', round(double_value, 5)


def _parse_asn1_opaque_int64(stream):
    """
    Parse an ASN.1 opaque int64 value from the given stream.

    Args:
        stream (io.BytesIO): The input stream to read the ASN.1 encoded data from.

    Returns:
        tuple: A tuple containing the string 'INT64' and the parsed int64 value.

    Raises:
        ValueError: If the length of the data is invalid or if the data cannot be parsed as an int64.
    """
    """Parse ASN.1 opaque int64"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    debug('ASN1_OPAQUE_INT64: %s', value)
    return 'INT64', value


def _parse_asn1_opaque_uint64(stream):
    """
    Parse an ASN.1 opaque uint64 value from the given stream.

    Args:
        stream (bytes): The byte stream to parse the uint64 value from.

    Returns:
        tuple: A tuple containing the string 'UINT64' and the parsed uint64 value.

    Raises:
        ValueError: If the length of the stream is invalid or if the stream cannot be parsed as an integer.
    """
    """Parse ASN.1 opaque uint64"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length)
    debug('ASN1_OPAQUE_UINT64: %s', value)
    return 'UINT64', value


def _parse_asn1_opaque(stream):
    """
    Parse ASN.1 opaque data from the given stream.

    This function reads the length, tag, and type of the ASN.1 opaque data
    and delegates the parsing to the appropriate function based on the type.
    If the type is not recognized, it rewinds the stream by 2 bytes and reads
    the opaque data as a simple byte sequence.

    Args:
        stream (io.BytesIO): The input stream containing the ASN.1 opaque data.

    Returns:
        The parsed ASN.1 opaque data, which can be a float, double, int64, uint64,
        or a simple byte sequence.
    """
    """Parse ASN.1 opaque"""
    length = _parse_asn1_length(stream)
    opaque_tag = _read_byte(stream)
    opaque_type = _read_byte(stream)
    if (length == ASN1_OPAQUE_FLOAT_BER_LEN and
            opaque_tag == ASN1_OPAQUE_TAG1 and
            opaque_type == ASN1_OPAQUE_FLOAT):
        return _parse_asn1_opaque_float(stream)
    elif (length == ASN1_OPAQUE_DOUBLE_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_DOUBLE):
        return _parse_asn1_opaque_double(stream)
    elif (length >= ASN1_OPAQUE_INT64_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_INT64):
        return _parse_asn1_opaque_int64(stream)
    elif (length >= ASN1_OPAQUE_UINT64_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_UINT64):
        return _parse_asn1_opaque_uint64(stream)
    # for simple opaque - rewind 2 bytes back (opaque tag and type)
    stream.seek(stream.tell() - 2)
    return stream.read(length)


def write_tv(tag, value):
    """
    Write a Tag-Value (TV) pair and calculate the length from the value.

    Args:
        tag (int): The tag identifier.
        value (bytes): The value associated with the tag.

    Returns:
        bytes: The encoded Tag-Length-Value (TLV) data.
    """
    """Write TV (Tag-Value) and calculate length from value"""
    return write_tlv(tag, len(value), value)


def _write_int(value, strip_leading_zeros=True):
    """
    Write an integer to a byte representation while ensuring correct sign representation.
    Args:
        value (int): The integer value to be converted to bytes. Must be in the range [0..18446744073709551615].
        strip_leading_zeros (bool): If True, leading zeros will be stripped from the byte representation unless it 
                                    causes misinterpretation of the sign. Defaults to True.
    Returns:
        bytes: The byte representation of the integer.
    Raises:
        Exception: If the integer value is outside the allowed range or if the minimum signed integer value is exceeded.
    """
    """Write int while ensuring correct sign representation."""
    if abs(value) > 0xffffffffffffffff:
        raise Exception('Int value must be in [0..18446744073709551615]')

    # Determine the correct format specifier based on the value's magnitude and sign.
    if value < 0:
        if abs(value) <= 0x7f:
            result = struct.pack('>b', value)
        elif abs(value) <= 0x7fff:
            result = struct.pack('>h', value)
        elif abs(value) <= 0x7fffffff:
            result = struct.pack('>i', value)
        elif abs(value) <= 0x7fffffffffffffff:
            result = struct.pack('>q', value)
        else:
            raise Exception('Min signed int value')
    else:
        if not strip_leading_zeros:
            # Always pack as the largest size to simplify leading zero handling.
            if value <= 0x7fffffff:
                result = struct.pack('>I', value)
            else:
                result = struct.pack('>Q', value)
        else:
            # Always pack as the largest size to simplify leading zero handling.
            result = struct.pack('>Q', value)
            # Check if the first relevant byte (ignoring leading zeros for now) would be misinterpreted as negative.
            if (result[0] == 0x00 and (result[1] & 0x80) != 0):
                # If not stripping leading zeros, or if stripping them would cause a misinterpretation,
                # leave the result as is. This branch might need revisiting based on specific needs.
                pass
            else:
                # Here's the core of the adjustment: only strip leading zeros if it does not lead to misinterpretation.
                # This means checking if the first byte would make it look negative and adjusting accordingly.
                first_non_zero_byte = len(result) - 1
                for i, byte in enumerate(result):
                    if byte != 0:
                        first_non_zero_byte = i
                        break
                if result[first_non_zero_byte] & 0x80:
                    # If the first non-zero byte's MSB is set, prepend a 0x00 to keep it positive.
                    result = b'\x00' + result[first_non_zero_byte:]
                else:
                    # Otherwise, strip all leading zeros except the last one, if all are zeros.
                    result = result[first_non_zero_byte:]

    return result or b'\x00'


def _write_asn1_length(length):
    """
    Write ASN.1 length.

    This function encodes the length of an ASN.1 element according to the 
    Basic Encoding Rules (BER). If the length is greater than 127 (0x7f), 
    it uses a multi-byte length encoding.

    Args:
        length (int): The length to encode.

    Returns:
        bytes: The encoded length as a byte string.

    Raises:
        Exception: If the length is too big to encode (greater than 0xffffffff).
    """
    """Write ASN.1 length"""
    if length > 0x7f:
        if length <= 0xff:
            packed_length = 0x81
        elif length <= 0xffff:
            packed_length = 0x82
        elif length <= 0xffffff:
            packed_length = 0x83
        elif length <= 0xffffffff:
            packed_length = 0x84
        else:
            raise Exception('Length is too big!')
        return struct.pack('B', packed_length) + _write_int(length)
    return struct.pack('B', length)


def write_tlv(tag, length, value):
    """
    Write TLV (Tag-Length-Value)

    Args:
        tag (int): The tag value representing the type of the data.
        length (int): The length of the value.
        value (bytes): The actual value in bytes.

    Returns:
        bytes: The encoded TLV as a byte string.
    """
    """Write TLV (Tag-Length-Value)"""
    return struct.pack('B', tag) + _write_asn1_length(length) + value


def encode_to_7bit(value):
    """
    Encodes an integer value to a list of bytes using 7-bit encoding.

    This function takes an integer value and encodes it into a list of bytes,
    where each byte contains 7 bits of the original value. If the value is
    greater than 0x7f (127), it will be split into multiple bytes, with each
    byte containing 7 bits of the value and the most significant bit (MSB) set
    to 1, except for the last byte which has the MSB set to 0.

    Args:
        value (int): The integer value to encode.

    Returns:
        list: A list of bytes representing the 7-bit encoded value.
    """
    """Encode to 7 bit"""
    if value > 0x7f:
        res = []
        res.insert(0, value & 0x7f)
        while value > 0x7f:
            value >>= 7
            res.insert(0, (value & 0x7f) | 0x80)
        return res
    return [value]


def oid_to_bytes_list(oid):
    """
    Convert an OID string to a list of bytes.

    This function takes an Object Identifier (OID) string, converts it to a list of integers,
    and then encodes these integers into a list of bytes according to the ASN.1 BER encoding rules.

    Parameters:
    oid (str): The OID string to be converted. The OID string can start with 'iso' or a number.

    Returns:
    list: A list of integers representing the encoded OID in bytes.

    Raises:
    Exception: If the OID string cannot be parsed into integers.
    """
    """Convert OID str to bytes list"""
    if oid.startswith('iso'):
        oid = oid.replace('iso', '1')
    try:
        oid_values = [int(x) for x in oid.split('.') if x]
        first_val = 40 * oid_values[0] + oid_values[1]
    except (ValueError, IndexError):
        raise Exception('Could not parse OID value "{}"'.format(oid))
    result_values = [first_val]
    for node_num in oid_values[2:]:
        result_values += encode_to_7bit(node_num)
    return result_values


def oid_to_bytes(oid):
    """
    Convert an Object Identifier (OID) string to a byte string.

    Args:
        oid (str): The OID string to be converted.

    Returns:
        str: The byte string representation of the OID.
    """
    """Convert OID str to bytes"""
    return ''.join([chr(x) for x in oid_to_bytes_list(oid)])


def handle_get_request(oids, oid):
    """
    Handle GetRequest PDU.

    This function processes a GetRequest PDU by checking if the requested OID
    is present in the provided OIDs dictionary. It returns the appropriate
    error status, error index, and the value associated with the OID.

    Args:
        oids (dict): A dictionary containing OID-value pairs.
        oid (str): The OID to be retrieved.

    Returns:
        tuple: A tuple containing:
            - error_status (int): The error status code.
            - error_index (int): The index of the error.
            - oid_value (bytes): The value associated with the OID or an error indication.
    """
    """Handle GetRequest PDU"""
    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    oid_value = null()
    found = oid in oids
    if found:
        # TODO: check this
        oid_value = oids[oid]
        if not oid_value:
            oid_value = struct.pack('BB', ASN1_NO_SUCH_OBJECT, 0)
    else:
        error_status = ASN1_ERROR_STATUS_NO_SUCH_NAME
        error_index = 1
        # TODO: check this
        oid_value = struct.pack('BB', ASN1_NO_SUCH_INSTANCE, 0)
    return error_status, error_index, oid_value


def oid_cmp(oid1: str, oid2: str):
    """
    Compare two Object Identifiers (OIDs) in string format.

    This function compares two OIDs by converting them into lists of integers
    and then performing a lexicographical comparison.

    Args:
        oid1 (str): The first OID to compare, in string format.
        oid2 (str): The second OID to compare, in string format.

    Returns:
        int: -1 if oid1 is less than oid2, 1 if oid1 is greater than oid2, 
             and 0 if they are equal.
    """
    """OIDs comparator function"""
    oid1_t = [int(x) for x in oid1.replace('iso', '1').strip('.').split('.')]
    oid2_t = [int(x) for x in oid2.replace('iso', '1').strip('.').split('.')]
    if oid1_t < oid2_t:
        return -1
    elif oid1_t > oid2_t:
        return 1
    return 0


def oid_key(oid: str):
    """
    Convert an OID string to a list of integers.

    This function takes an OID (Object Identifier) string, replaces the 'iso' prefix with '1',
    removes any leading or trailing dots, splits the string by dots, and converts each segment
    to an integer.

    Args:
        oid (str): The OID string to be converted.

    Returns:
        list: A list of integers representing the OID.
    """
    return [int(x) for x in oid.replace('iso', '1').strip('.').split('.')]


def get_next(oids: dict[str, object], oid: str):
    """
    Get the next OID from the list of OIDs.

    This function takes a list of OIDs and a specific OID, and returns the next OID in the list that is greater than the given OID. 
    If the given OID is empty, it returns the first OID in the sorted list.

    Args:
        oids (list): A list of OIDs.
        oid (str): The OID to compare against.

    Returns:
        str: The next OID in the list that is greater than the given OID, or an empty string if no such OID exists.
    """
    """Get next OID from the OIDs list"""
    for val in sorted(oids, key=oid_key):
        # return first if compared with empty oid
        if not oid:
            return val
        # if oid < val, return val (i.e. first oid value after oid)
        elif oid_cmp(oid, val) < 0:
            return val
    # return empty when no more oids available
    return ''


def get_next_oid(oid: str):
    """
    Get the next OID parent's node.

    This function takes an OID (Object Identifier) string as input and returns the next OID in sequence by incrementing the 
    second-to-last node and resetting the last node to '1'. If the OID has only one node, it simply increments that node.

    Args:
        oid (str): The OID string to be incremented.

    Returns:
        str: The next OID in sequence.
    """
    """Get the next OID parent's node"""
    # increment pre last node, e.g.: "1.3.6.1.1" -> "1.3.6.2.1"
    oid_vals = oid.rsplit('.', 2)
    if len(oid_vals) < 2:
        oid_vals[-1] = str(int(oid_vals[-1]) + 1)
    else:
        oid_vals[-2] = str(int(oid_vals[-2]) + 1)
        oid_vals[-1] = '1'
    oid_next = '.'.join(oid_vals)
    return oid_next


def handle_get_next_request(oids: dict[str, object], oid: str, limit_to_last_in_config=True):
    """
    Handle a GetNextRequest for SNMP.
    This function processes a GetNextRequest by finding the next OID in the 
    provided list of OIDs. If the OID is found, it retrieves the next OID 
    and its value. If the OID is not found, it returns a null value. The 
    function also ensures that the OID does not exceed the last OID in the 
    configuration if the limit_to_last_in_config flag is set.
    Args:
        oids (dict): A dictionary of OIDs and their corresponding values.
        oid (str): The OID to process.
        limit_to_last_in_config (bool, optional): Flag to limit the OID to the 
            last one in the configuration. Defaults to True.
    Returns:
        tuple: A tuple containing:
            - error_status (int): The error status code.
            - error_index (int): The error index.
            - final_oid (str): The final OID after processing.
            - oid_value (bytes): The value of the OID.
    """
    """Handle GetNextRequest"""
    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    if oid in oids:
        new_oid = get_next(oids, oid)
        if not new_oid:
            oid_value = struct.pack('BB', ASN1_END_OF_MIB_VIEW, 0)
        else:
            oid_value = oids.get(new_oid)

    else:
        oid_value = null()
    # if new oid is found - get it, otherwise calculate possible next one
    if new_oid:
        oid = new_oid
    else:
        oid = get_next_oid(oid.rstrip('.0')) + '.0'
    # if wildcards are used in oid - replace them
    final_oid = oid
    # to prevent loop - check a new oid and if it is more than the last in config - stop
    if oids and limit_to_last_in_config:
        last_oid_in_config = sorted(
            oids, key=oid_key)[-1]
        if oid_cmp(final_oid, last_oid_in_config) > 0:
            oid_value = struct.pack('BB', ASN1_END_OF_MIB_VIEW, 0)
    return error_status, error_index, final_oid, oid_value


def boolean(value: bool):
    """
    Convert a boolean value to its ASN.1 encoded representation.

    Args:
        value (bool): The boolean value to encode.

    Returns:
        bytes: The ASN.1 encoded representation of the boolean value.
    """
    """Get Boolean"""
    return write_tlv(ASN1_BOOLEAN, 1, b'\xff' if value else b'\x00')


def integer(value: int):
    """
    Encodes an integer value in ASN.1 format.

    Args:
        value (int): The integer value to be encoded.

    Returns:
        bytes: The encoded integer in ASN.1 format.
    """
    return write_tv(ASN1_INTEGER, _write_int(value, False))


def bit_string(value: str):
    '''
    Convert a string value to a BitString for SNMP response.
    Args:
        value (str): The input string value to be converted. For example, '\xF0\xF0'.
    Returns:
        bytes: The encoded BitString in TLV (Type-Length-Value) format.
    Example:
        If the input value is '\xF0\xF0', the binary representation is:
        F0 F0 in hex = 11110000 11110000 in binary.
        The bits 0, 1, 2, 3, 8, 9, 10, 11 are set, so these bits are added to the output.
        Therefore, the SNMP response is: F0 F0 0 1 2 3 8 9 10 11.
    '''

    return write_tlv(ASN1_BIT_STRING, len(value), value.encode('latin'))


def octet_string(value: str):
    """
    Convert a given string to an ASN.1 OctetString.

    Args:
        value (str): The string to be converted.

    Returns:
        bytes: The encoded OctetString in bytes.
    """
    """Get OctetString"""
    return write_tv(ASN1_OCTET_STRING, value.encode('latin'))


def null():
    """
    Get a Null ASN.1 type.

    Returns:
        bytes: The encoded ASN.1 NULL type.
    """
    """Get Null"""
    return write_tv(ASN1_NULL, b'')


def object_identifier(value: str):
    """
    Convert an OID value to its byte representation and encode it as an ASN.1 OBJECT IDENTIFIER.

    Args:
        value (str): The OID value to be converted.

    Returns:
        bytes: The encoded ASN.1 OBJECT IDENTIFIER.
    """
    """Get OID"""
    value = oid_to_bytes(value)
    return write_tv(ASN1_OBJECT_IDENTIFIER, value.encode('latin'))


def real(value: float):
    """
    Encodes a floating-point number into an ASN.1 opaque type.

    Args:
        value (float): The floating-point number to encode.

    Returns:
        bytes: The ASN.1 encoded opaque type containing the floating-point number.
    """
    """Get real"""
    # opaque tag | len | tag1 | tag2 | len | data
    float_value = struct.pack('>f', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_FLOAT
    ) + _write_asn1_length(len(float_value)) + float_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def double(value: float):
    """
    Encodes a double precision floating point number into an ASN.1 opaque type.

    Args:
        value (float): The double precision floating point number to encode.

    Returns:
        bytes: The encoded ASN.1 opaque type containing the double precision floating point number.
    """
    """Get double"""
    # opaque tag | len | tag1 | tag2 | len | data
    double_value = struct.pack('>d', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_DOUBLE
    ) + _write_asn1_length(len(double_value)) + double_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def int64(value: int):
    """
    Encodes a given integer value as an ASN.1 opaque int64.

    Args:
        value (int): The integer value to be encoded.

    Returns:
        bytes: The encoded ASN.1 opaque int64 value.
    """
    """Get int64"""
    # opaque tag | len | tag1 | tag2 | len | data
    int64_value = struct.pack('>q', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_INT64
    ) + _write_asn1_length(len(int64_value)) + int64_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def uint64(value: int):
    """
    Encodes a given integer value as a uint64 in ASN.1 format.

    Args:
        value (int): The integer value to be encoded.

    Returns:
        bytes: The encoded uint64 value in ASN.1 format.
    """
    """Get uint64"""
    # opaque tag | len | tag1 | tag2 | len | data
    uint64_value = struct.pack('>Q', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_UINT64
    ) + _write_asn1_length(len(uint64_value)) + uint64_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def utf8_string(value: str):
    """
    Convert a given string to a UTF-8 encoded ASN.1 string.

    Args:
        value (str): The string to be encoded.

    Returns:
        bytes: The encoded string in UTF-8 format with ASN.1 type identifier.
    """
    """Get UTF8String"""
    return write_tv(ASN1_UTF8_STRING, value.encode('latin'))


def printable_string(value: str):
    """
    Convert a given string to an ASN.1 PrintableString.

    Args:
        value (str): The string to be converted.

    Returns:
        bytes: The encoded ASN.1 PrintableString.
    """
    """Get PrintableString"""
    return write_tv(ASN1_PRINTABLE_STRING, value.encode('latin'))


def ia5_string(value: str):
    """
    Convert a given string to an IA5String encoded in ASN.1 format.

    Args:
        value (str): The string to be encoded.

    Returns:
        bytes: The IA5String encoded in ASN.1 format.
    """
    """Get IA5String"""
    return write_tv(ASN1_IA5_STRING, value.encode('latin'))


def bmp_string(value: str):
    """
    Convert a given string to a BMPString encoded in UTF-16-BE and return its ASN.1 representation.

    Args:
        value (str): The string to be converted to BMPString.

    Returns:
        bytes: The ASN.1 encoded BMPString.
    """
    """Get BMPString"""
    return write_tv(ASN1_BMP_STRING, value.encode('utf-16-be'))


def ip_address(value):
    """
    Convert an IP address string to its binary representation and write it with ASN.1 IPAddress type.

    Args:
        value (str): The IP address in string format (e.g., '192.168.1.1').

    Returns:
        bytes: The binary representation of the IP address with ASN.1 IPAddress type.
    """
    """Get IPAddress"""
    return write_tv(ASN1_IPADDRESS, usocket.inet_aton(value))


def timeticks(value: int) -> bytes:
    """
    Convert an integer value to SNMP Timeticks format.

    Timeticks is a non-negative integer that represents the time in hundredths of a second since some epoch.

    Args:
        value (int): The integer value to be converted. Must be in the range [0..4294967295].

    Returns:
        bytes: The encoded Timeticks value in ASN.1 format.

    Raises:
        Exception: If the value is not in the range [0..4294967295].
    """
    """Get Timeticks"""
    if value > 0xffffffff:
        raise Exception('Timeticks value must be in [0..4294967295]')
    return write_tv(ASN1_TIMETICKS, _write_int(value))


def gauge32(value: int):
    """
    Convert an integer value to a Gauge32 type for SNMP.

    A Gauge32 is an unsigned 32-bit integer that can range from 0 to 4294967295.

    Args:
        value (int): The integer value to be converted. Must be in the range [0..4294967295].

    Returns:
        bytes: The encoded Gauge32 value in ASN.1 format.

    Raises:
        Exception: If the value is outside the allowable range.
    """
    """Get Gauge32"""
    if value > 0xffffffff:
        raise Exception('Gauge32 value must be in [0..4294967295]')
    return write_tv(ASN1_GAUGE32, _write_int(value, strip_leading_zeros=False))


def counter32(value: int):
    """
    Get Counter32

    Args:
        value (int): The value to be converted to Counter32. Must be in the range [0..4294967295].

    Returns:
        bytes: The encoded Counter32 value.

    Raises:
        Exception: If the value is greater than 0xffffffff (4294967295).
    """
    """Get Counter32"""
    if value > 0xffffffff:
        raise Exception('Counter32 value must be in [0..4294967295]')
    return write_tv(ASN1_COUNTER32, _write_int(value))


def counter64(value: int):
    """
    Get Counter64

    Args:
        value (int): The value to be converted to Counter64. Must be in the range [0..18446744073709551615].

    Returns:
        bytes: The encoded Counter64 value.

    Raises:
        Exception: If the value is greater than 18446744073709551615.
    """
    """Get Counter64"""
    if value > 0xffffffffffffffff:
        raise Exception('Counter64 value must be in [0..18446744073709551615]')
    return write_tv(ASN1_COUNTER64, _write_int(value))


def craft_response(version, community, request_id, error_status, error_index, oid_items):
    """
    Craft an SNMP response message.

    Parameters:
    version (int): SNMP version number.
    community (str): Community string.
    request_id (int): Request identifier.
    error_status (int): Error status code.
    error_index (int): Error index.
    oid_items (list of tuples): List of OID items, where each item is a tuple containing an OID key (str) and an OID value (bytes).

    Returns:
    bytes: The crafted SNMP response message.
    """
    """Craft SNMP response"""
    response = write_tv(
        ASN1_SEQUENCE,
        # add version and community from request
        write_tv(ASN1_INTEGER, _write_int(version)) +
        write_tv(ASN1_OCTET_STRING, community.encode('latin')) +
        # add GetResponse PDU with get response fields
        write_tv(
            ASN1_GET_RESPONSE_PDU,
            # add response id, error status and error index
            write_tv(ASN1_INTEGER, _write_int(request_id)) +
            write_tlv(ASN1_INTEGER, 1, _write_int(error_status)) +
            write_tlv(ASN1_INTEGER, 1, _write_int(error_index)) +
            # add variable bindings
            write_tv(
                ASN1_SEQUENCE,
                b''.join(
                    # add OID and OID value
                    write_tv(
                        ASN1_SEQUENCE,
                        write_tv(
                            ASN1_OBJECT_IDENTIFIER,
                            oid_key.encode('latin')
                        ) +
                        oid_value
                    ) for (oid_key, oid_value) in oid_items
                )
            )
        )
    )
    return response


def callback(request_data: bytes, addr: bytes):
    """
    Handles SNMP requests and generates appropriate responses.
    Args:
        request_data (bytes): The raw SNMP request data.
        addr (bytes): The address from which the request originated.
    Returns:
        bytes: The crafted SNMP response.
    Raises:
        Exception: If the parsed request length is invalid.
    The function processes different types of SNMP Protocol Data Units (PDUs):
    - GET_REQUEST_PDU: Retrieves the value of the requested OIDs.
    - GET_NEXT_REQUEST_PDU: Retrieves the value of the next OID in the MIB.
    - GET_BULK_REQUEST_PDU: Retrieves multiple values based on the requested OIDs and max repetitions.
    The function uses helper functions to handle specific PDU types and to craft the response.
    """
    request_result = _parse_snmp_asn1(request_data, addr)

    version = request_result[0][1]
    debug('Version:', SNMP_VERSIONS.get(int(version)))
    community = request_result[1][1]
    debug('Community:', community)
    pdu_type = request_result[2][1]
    debug('PDU type:', pdu_type)
    request_id = request_result[3][1]
    debug('Request ID:', request_id)

    info("Version:", version, ", Community:", community,
         ", PDU type:", pdu_type, ", Request ID:", request_id)

    expected_length = 8 if pdu_type == ASN1_TRAP_REQUEST_PDU else 7
    if len(request_result) < expected_length:
        raise Exception(
            'Invalid ASN.1 parsed request length! %s' % str(request_result))

    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    oid_items = []
    oid_value = null()

    # handle protocol data units
    if pdu_type == ASN1_GET_REQUEST_PDU:
        requested_oids = request_result[6:]
        for _, oid in requested_oids:
            _, _, oid_value = handle_get_request(OIDS, oid)
            # if oid value is a function - call it to get the value
            if callable(oid_value):
                oid_value = oid_value(oid)
            if isinstance(oid_value, tuple):
                oid_value = oid_value[0]
            oid_items.append((oid_to_bytes(oid), oid_value))
    elif pdu_type == ASN1_GET_NEXT_REQUEST_PDU:
        oid = request_result[6][1]
        error_status, error_index, oid, oid_value = handle_get_next_request(
            OIDS, oid)
        if callable(oid_value):
            oid_value = oid_value(oid)
        if isinstance(oid_value, tuple):
            oid_value = oid_value[0]
        oid_items.append((oid_to_bytes(oid), oid_value))
    elif pdu_type == ASN1_GET_BULK_REQUEST_PDU:
        max_repetitions = request_result[5][1]
        info('max_repetitions: %i', max_repetitions)
        requested_oids = request_result[6:]
        for _ in range(0, max_repetitions):
            for idx, val in enumerate(requested_oids):
                oid = val[1]
                error_status, error_index, oid, oid_value = handle_get_next_request(
                    OIDS, oid)
                if callable(oid_value):
                    oid_value = oid_value(oid)
                if isinstance(oid_value, tuple):
                    oid_value = oid_value[0]
                oid_items.append((oid_to_bytes(oid), oid_value))
                requested_oids[idx] = ('OID', oid)
    response = craft_response(
        version, community, request_id, error_status, error_index, oid_items)
    return response


OIDS = {
    '1.3.6.1.2.1.1.1.0': octet_string('SNMPv2-MIB::sysDescr.0')
}


def _parse_snmp_asn1(request_data: bytes, addr: bytes) -> list:
    """
    Parses SNMP ASN.1 encoded request data.
    Args:
        request_data (bytes): The SNMP request data in bytes.
        addr (bytes): The address from which the request was received.
    Returns:
        list: A list of tuples representing the parsed SNMP data.
    Raises:
        ProtocolError: If the SNMP protocol data units are not read correctly or if an invalid tag is encountered.
        Exception: If unsupported PDU types are encountered or if certain PDU types are used in unsupported SNMP versions.
    The function decodes the request data, reads through the stream byte by byte, and parses various ASN.1 tags such as 
    INTEGER, OCTET STRING, OBJECT IDENTIFIER, and different PDU types. It validates the protocol and appends the parsed 
    values to the result list. The function also handles specific SNMP versions and raises exceptions for unsupported 
    PDUs or invalid protocol data.
    """
    info("Received :", len(request_data), " bytes.")
    result = []
    wait_oid_value: bool = False
    pdu_index: int = 0

    decoded = "".join(chr(b) for b in request_data)
    info("Decoded:", decoded)

    stream = io.StringIO(decoded)
    while True:
        read_byte = stream.read(1)
        info("Read byte:", read_byte)
        if not read_byte:
            if pdu_index < 7:
                raise ProtocolError(
                    'Not all SNMP protocol data units are read!')
            return result

        tag = ord(read_byte)
        if not _validate_protocol(pdu_index, tag, result):
            raise ProtocolError(
                'Invalid tag for PDU unit "{}"'.format(SNMP_PDUS[pdu_index]))
        if tag == ASN1_SEQUENCE:
            length = _parse_asn1_length(stream)
            info('ASN1_SEQUENCE: %s', 'length = {}'.format(length))
        elif tag == ASN1_INTEGER:
            length = _read_byte(stream)
            value = _read_int_len(stream, length, True)
            info('ASN1_INTEGER: %s', value)
            # pdu_index is version, request-id, error-status, error-index
            if wait_oid_value or pdu_index in [1, 4, 5, 6] or _is_trap_request(result):
                result.append(('INTEGER', value))
                wait_oid_value = False
        elif tag == ASN1_OCTET_STRING:
            value = _parse_asn1_octet_string(stream)
            info('ASN1_OCTET_STRING: %s', value)
            if wait_oid_value or pdu_index == 2:  # community
                result.append(('STRING', value))
                wait_oid_value = False
        elif tag == ASN1_OBJECT_IDENTIFIER:
            length = _read_byte(stream)
            value = stream.read(length)
            info('ASN1_OBJECT_IDENTIFIER: %s', bytes_to_oid(value))
            result.append(('OID', bytes_to_oid(value)))
            wait_oid_value = True
        elif tag == ASN1_PRINTABLE_STRING:
            length = _parse_asn1_length(stream)
            value = stream.read(length)
            info('ASN1_PRINTABLE_STRING: %s', value)
        elif tag == ASN1_GET_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_GET_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_REQUEST_PDU', tag))
        elif tag == ASN1_GET_NEXT_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_GET_NEXT_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_NEXT_REQUEST_PDU', tag))
        elif tag == ASN1_GET_BULK_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_GET_BULK_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_BULK_REQUEST_PDU', tag))
        elif tag == ASN1_GET_RESPONSE_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_GET_RESPONSE_PDU: %s',
                 'length = {}'.format(length))
        elif tag == ASN1_SET_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_SET_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_SET_REQUEST_PDU', tag))
        elif tag == ASN1_TRAP_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            info('ASN1_TRAP_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_TRAP_REQUEST_PDU', tag))
        elif tag == ASN1_INFORM_REQUEST_PDU:
            if result and result[0][1] == 0:
                raise Exception(
                    'INFORM request PDU is not supported in SNMPv1!')
            length = _parse_asn1_length(stream)
            info('ASN1_INFORM_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_INFORM_REQUEST_PDU', tag))
        elif tag == ASN1_SNMPv2_TRAP_REQUEST_PDU:
            if result and result[0][1] == 0:
                raise Exception(
                    'SNMPv2 TRAP PDU request is not supported in SNMPv1!')
            length = _parse_asn1_length(stream)
            info('ASN1_SNMPv2_TRAP_REQUEST_PDU: %s',
                 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_SNMPv2_TRAP_REQUEST_PDU', tag))
        elif tag == ASN1_REPORT_REQUEST_PDU:
            raise Exception('Report request PDU is not supported!')
        elif tag == ASN1_TIMETICKS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            info('ASN1_TIMETICKS: %s (%s)',
                 value, timeticks_to_str(value))
            if wait_oid_value or _is_trap_request(result):
                result.append(('TIMETICKS', value))
                wait_oid_value = False
        elif tag == ASN1_IPADDRESS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            info('ASN1_IPADDRESS: %s (%s)', value, int_to_ip(value))
            if wait_oid_value or _is_trap_request(result):
                result.append(('IPADDRESS', int_to_ip(value)))
                wait_oid_value = False
        elif tag == ASN1_COUNTER32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            info('ASN1_COUNTER32: %s', value)
            if wait_oid_value:
                result.append(('COUNTER32', value))
                wait_oid_value = False
        elif tag == ASN1_GAUGE32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            info('ASN1_GAUGE32: %s', value)
            if wait_oid_value:
                result.append(('GAUGE32', value))
                wait_oid_value = False
        elif tag == ASN1_OPAQUE:
            value = _parse_asn1_opaque(stream)
            info('ASN1_OPAQUE: %r', value)
            if wait_oid_value:
                result.append(('OPAQUE', value))
                wait_oid_value = False
        elif tag == ASN1_COUNTER64:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            info('ASN1_COUNTER64: %s', value)
            if wait_oid_value:
                result.append(('COUNTER64', value))
                wait_oid_value = False
        elif tag == ASN1_NULL:
            value = _read_byte(stream)
            info('ASN1_NULL: %s', value)
        elif tag == ASN1_NO_SUCH_OBJECT:
            value = _read_byte(stream)
            info('ASN1_NO_SUCH_OBJECT: %s', value)
            result.append('No Such Object')
        elif tag == ASN1_NO_SUCH_INSTANCE:
            value = _read_byte(stream)
            info('ASN1_NO_SUCH_INSTANCE: %s', value)
            result.append('No Such Instance with OID')
        elif tag == ASN1_END_OF_MIB_VIEW:
            value = _read_byte(stream)
            info('ASN1_END_OF_MIB_VIEW: %s', value)
            return [('', ''), ('', '')]
        else:
            info('?: %s', hex(ord(read_byte)))
        pdu_index += 1
        info("PDU index:", pdu_index)


def get_time(oid):
    return timeticks(utime.ticks_ms())


if __name__ == '__main__':

    OIDS.update(
        {
            '1.3.6.1.2.1.1.1.0': octet_string('Micropython SNMP Agent'),
            '1.3.6.1.2.1.1.2.0': object_identifier('1.3.6.1.4.1.8072.3.2.10'),
            '1.3.6.1.2.1.1.3.0': get_time,
            '1.3.6.1.2.1.1.4.0': octet_string('admin@example.com'),
            '1.3.6.1.2.1.1.5.0': octet_string('My SNMP Agent'),
            '1.3.6.1.2.1.1.6.0': octet_string('Server Room'),
            '1.3.6.1.2.1.1.7.0': integer(72),
        })

    udp_server = UDPServer()
    uasyncio.run(udp_server.serve(callback, "0.0.0.0", 188))
