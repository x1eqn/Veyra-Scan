from xien_control.string_decode import decoded_variants


def test_hex_single_byte_xor_decoder_exposes_feature_text():
    payload = bytes(ord(char) ^ 0x5A for char in "triggerbot")
    variants = decoded_variants(payload.hex())
    assert "triggerbot" in variants


def test_plain_text_does_not_gain_unrelated_decoder_hits():
    variants = decoded_variants("sodium performance renderer")
    assert "triggerbot" not in variants
