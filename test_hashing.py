import pytest
import phpass


def test_blowfish_hashing():
    hasher = phpass.PasswordHash(iteration_count_log2=8, portable_hashes=False, algorithm='blowfish')
    secret = 'test12345'
    hx = hasher.hash_password(secret)
    assert hasher.check_password(secret, hx)
    assert not hasher.check_password(secret+'incorrect', hx)


def test_ext_des_hashing():
    hasher = phpass.PasswordHash(iteration_count_log2=8, portable_hashes=False, algorithm='ext-des')
    secret = 'test12345'
    hx = hasher.hash_password(secret)
    assert hasher.check_password(secret, hx)
    assert not hasher.check_password(secret+'incorrect', hx)


def test_portable_hashing():
    hasher = phpass.PasswordHash(iteration_count_log2=8, portable_hashes=True)
    secret = 'test12345'
    hx = hasher.hash_password(secret)
    assert hasher.check_password(secret, hx)
    assert not hasher.check_password(secret+'incorrect', hx)


def test_portable_hashing_cross_compatible():
    hasher = phpass.PasswordHash(iteration_count_log2=8, portable_hashes=True)
    secret = 'test12345'
    # A correct portable hash for 'test12345'.
    hx = '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'
    assert hasher.check_password(secret, hx)
    assert not hasher.check_password(secret+'incorrect', hx)
