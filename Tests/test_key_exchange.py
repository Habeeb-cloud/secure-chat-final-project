from client.key_exchange import (
    generate_keypair,
    derive_shared_key,
    serialize_public_key,
    load_public_key,
)


def test_ecdh_key_agreement():
    a = generate_keypair()
    b = generate_keypair()

    # simulate sending public keys over the network
    a_pub_bytes = serialize_public_key(a.public_key)
    b_pub_bytes = serialize_public_key(b.public_key)

    a_peer_pub = load_public_key(b_pub_bytes)
    b_peer_pub = load_public_key(a_pub_bytes)

    key_a = derive_shared_key(a.private_key, a_peer_pub)
    key_b = derive_shared_key(b.private_key, b_peer_pub)

    assert key_a == key_b
    assert len(key_a) == 32
