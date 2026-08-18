import pytest
from aioquic.quic.connection import QuicConnection
from aioquic.quic.connection import QuicConnectionError

from mitmproxy.proxy.layers.quic import _client_hello_parser
from mitmproxy.proxy.layers.quic._client_hello_parser import (
    quic_parse_client_hello_from_datagrams,
)
from test.mitmproxy.proxy.layers.quic.test__stream_layers import client_hello


# A Firefox ClientHello that does not fit into one datagram. Firefox pads the
# datagram after the Initial packet, which aioquic reports as a dropped header.
firefox_partial_client_hello = bytes.fromhex(
    "c60000000108cc2383ff0d7aaf0703fb64140043b52032654688919cb384bd02849a80d9a80a5e13cc3bd682b266"
    "0a373fe1085fa89bb83118f57303d13814f43fb949d1a58bee2851e46043224b841d128692128110f302dd337a9f"
    "e233f31d6e8ca19c8420adb6356ef65e08cf9d5f8fb32fa5c5ad1797ede4afcfddad8160756d23bff2774fbe465b"
    "aa67722ec787166ed0b1cfe53639ba9041565be09e663ea948ea96aeb385e0ae832dc919c7dccd0752361dd39ab4"
    "79efe3c339cfac383d2f8716b4d981ba040d412280d383aedf8548142d167d225ab9db5feb37977214669b6d4015"
    "939b14e7547dcd0bff6c6bcb655bc195e8b9421a2e181aba583856403100e888d3b311a96b1b16a80187ad77569f"
    "d14fea32024b09c5ed087782fbec74ec3ccfa1e3ed0fe155499ca7dcc4d385e6635226dd760a050bc22020f95c1b"
    "0119cbb929c85ad9e83899de867bbb8cc56bedf3b6fd058b59a38a23d765e80727f5a6acb48c16acb37d1bde0313"
    "64ba82fc23aecfcec9f5f7a577a824ac869186135508f183ee05d8db5abb77e250855f5f872c1866a47736003b77"
    "4c58f5ec486ed91bd1b275abab8934de876211a9d3fbacd79c75ff705c73c62e5aadf30981d40460424bd62cdb9b"
    "a808e78b7921b07a86b8c849bb5f12027a4c5de3e3c0e24f8d6d07ae76a253ee1c2a7423de3cad3f13c3c411a3cd"
    "17cea4e8ede3227439430c8a4f8a96c64873f77e202f51448da3cd9001cf5909d1f97f339f01c36db18938ac6df9"
    "0c9a3e948c21e3815d17eae493906d262aa65b11c8434b20aa4fc362190fb65b2a44fb2823e462cdfb23ffc1a34f"
    "01dea1999aea5889a44d005d1278fbec6dba25a1268d43f275caeb52db6069954ee6661d8c7b7c5c762e6a114094"
    "2337c2b365dbc0aee2e655a6f456f0cde44861b1ff11890a0dbac7858800a82306706020f4f253d2745acb5efd53"
    "5d7d1ee356999bff42773e5ce7cfa73c89ec23569481cbc69819886d76e450f29bf8afb20eceaaf4d7addb3548a1"
    "712489a587ddaabbd0e900e67f607f45408b71f5fbeac607feaa5af52b4102fcdd13be668c6ce0efc527e53dae83"
    "ea51c1b6cf6805a8c7795a22e29b31c11c5378c0159d9c8b5299aebe858ab4cae4b98c3bca492ddfea408bf966c1"
    "d24e005d7d8bec75cab022af35c07efabfe41cf6cd829a57c276f38a343ab039c067baf8ae0154824e62016e5a57"
    "284e86ba6fe0de58371c7c21c3e85a12942d872085ccb0351acde3c8b82c27e03b5fe85831c2dea48b1e0aed9d80"
    "1ac94e0b32dd02899940ddd6873ff05c4b1c1467bbde580453bdd25204345394a70850459430e044a4d952be2630"
    "92a3e6a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000"
)


class TestParseClientHello:
    def test_input(self):
        assert (
            quic_parse_client_hello_from_datagrams([client_hello]).sni == "example.com"
        )
        with pytest.raises(ValueError):
            quic_parse_client_hello_from_datagrams(
                [client_hello[:183] + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"]
            )
        with pytest.raises(ValueError, match="not initial"):
            quic_parse_client_hello_from_datagrams(
                [
                    b"\\s\xd8\xd8\xa5dT\x8bc\xd3\xae\x1c\xb2\x8a7-\x1d\x19j\x85\xb0~\x8c\x80\xa5\x8cY\xac\x0ecK\x7fC2f\xbcm\x1b\xac~"
                ]
            )

    def test_invalid(self, monkeypatch):
        # XXX: This test is terrible, it should use actual invalid data.
        class InvalidClientHello(Exception):
            @property
            def data(self):
                raise EOFError()

        monkeypatch.setattr(_client_hello_parser, "QuicClientHello", InvalidClientHello)
        with pytest.raises(ValueError, match="Invalid ClientHello"):
            quic_parse_client_hello_from_datagrams([client_hello])

    def test_connection_error(self, monkeypatch):
        def raise_conn_err(self, data, addr, now):
            raise QuicConnectionError(0, 0, "Conn err")

        monkeypatch.setattr(QuicConnection, "receive_datagram", raise_conn_err)
        with pytest.raises(ValueError, match="Conn err"):
            quic_parse_client_hello_from_datagrams([client_hello])

    def test_no_return(self):
        with pytest.raises(
            ValueError, match="Invalid ClientHello packet: payload_decrypt_error"
        ):
            quic_parse_client_hello_from_datagrams(
                [client_hello[0:1200] + b"\x00" + client_hello[1200:]]
            )

    def test_padding_after_initial(self):
        # The ClientHello is incomplete, but the padding must not make it invalid.
        assert quic_parse_client_hello_from_datagrams(
            [firefox_partial_client_hello]
        ) is None
