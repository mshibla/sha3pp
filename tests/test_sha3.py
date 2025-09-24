#! usr/bin/env python

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/sha3pp')))
import sha3
import hashlib
import pytest

sha3_functions = [
    sha3.sha3_224,
    sha3.sha3_256,
    sha3.sha3_384,
    sha3.sha3_512,
]

pysha3_hashes = [
    hashlib.sha3_224,
    hashlib.sha3_256,
    hashlib.sha3_384,
    hashlib.sha3_512,
]

@pytest.mark.parametrize(
    "myfunc, stdfunc",
    list(
        zip(
            sha3_functions,
            pysha3_hashes,
        ),
    ),
)


def test_sha3_compatibility(myfunc, stdfunc):
    # Only debug the first input for clarity
    s = b'0'
    my_digest = myfunc(s).hexdigest()
    std_digest = stdfunc(s).hexdigest()
    print(f"Input: {s}")
    print(f"My digest:   {my_digest}")
    print(f"Std digest:  {std_digest}")
    assert my_digest == std_digest, (
        f"Mismatch for input: {s}\nMy digest:  {my_digest}\nStd digest: {std_digest}"
    )