class InvalidIPv4Address(Exception):
    pass

class InvalidFormat(InvalidIPv4Address):
    pass

class NonNumericField(InvalidIPv4Address):
    pass

class OutOfRangeField(InvalidIPv4Address):
    pass

class LeadingZeroField(InvalidIPv4Address):
    pass