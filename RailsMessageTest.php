<?php
/**
 * Created by PhpStorm.
 * User: herop
 * Date: 21/11/2014
 * Time: 10:27
 */
include 'railsmessage.php';

class RailsMessageTest extends PHPUnit_Framework_TestCase {
    public function testDecrypt()
    {
        $secret_key_base = 'f29c9a958b8c01f428fdc3559378df5ea81dabae61d93c317c4c3d5734b0c158a1ce9cc07b6ecf66862a61492b8c458c653198ab87d2141e5e1a3d80724918cc';
        $signed_session = 'WUJ1dk5Kb3hPTXdBSzM1a3AzQzBDQk1ybm05c0poQ0VncUNYTk1FTjloTnZtVVdib3dPS2tnemg5STR4MDdzeXU1VUR3c0E1YlEyTGgwM3E0VTdjVjdJVmp2VURxclJlNDFuVGxSNFhOeHVTaUhqbTFoZlFtdGRhS2kveXFVZXhoQjhjL2ZLOFB6SnhTNjBzRHNSY0ZtNDhTQWJMNXFqRjhsQXJIdXVrRC9rZDJQS2c4MXo0RXJld1U1NlJNT3ZJcTBNQ0dYd1d2SWk1ZXd3WW9CVE1hdDNTMTd5R1JVV1IyQU5Ia00wZTFETHJ4cTJlOStLK29Kd3I4dkhKc1pGa0liME8zUGFmMVhKTnQrYitPUzhDWERxV29RRlkyK3FJNkEzY0xMRTZRR21HTVkzQTVXT0NHeUFpZ0FSSkEwV1dpeTF5ZmNqNy9GUWN3ZzZReS9nQmlhQUhwUnF1R2lwRnBiYlhDdjRpTkVyemt6S3NnT0VpVGJMQlVTV0s1bE5SLS1SblhRaHJCa2x5dEZqVFFzKzhHbkVnPT0%3D--2a83aeee323ad664101c3ff99d6d138e26474bdc';
        $message = new RailsMessage($secret_key_base, $signed_session);
        $decrypted_session = $message->decrypt();

        $this->assertEquals('{"session_id":"b0008cc2b659c8bc644ca15e6b9cfa39","user_return_to":"/admin/","warden.user.user.key":["546ad8f56865720b61100000","$2a$10$6.o7x4Em.BKBoAR60R.1Pe"],"_csrf_token":"saZC3hsTaN8E8TZ+ZHSPbRvj2p0usElUF9/pIu5GPG8=","flash":{"discard":["alert"],"flashes":{"alert":""}}}', $decrypted_session);
    }

    public function testStaticDecrypt()
    {
        $secret_key_base = 'f29c9a958b8c01f428fdc3559378df5ea81dabae61d93c317c4c3d5734b0c158a1ce9cc07b6ecf66862a61492b8c458c653198ab87d2141e5e1a3d80724918cc';
        $signed_session = 'WUJ1dk5Kb3hPTXdBSzM1a3AzQzBDQk1ybm05c0poQ0VncUNYTk1FTjloTnZtVVdib3dPS2tnemg5STR4MDdzeXU1VUR3c0E1YlEyTGgwM3E0VTdjVjdJVmp2VURxclJlNDFuVGxSNFhOeHVTaUhqbTFoZlFtdGRhS2kveXFVZXhoQjhjL2ZLOFB6SnhTNjBzRHNSY0ZtNDhTQWJMNXFqRjhsQXJIdXVrRC9rZDJQS2c4MXo0RXJld1U1NlJNT3ZJcTBNQ0dYd1d2SWk1ZXd3WW9CVE1hdDNTMTd5R1JVV1IyQU5Ia00wZTFETHJ4cTJlOStLK29Kd3I4dkhKc1pGa0liME8zUGFmMVhKTnQrYitPUzhDWERxV29RRlkyK3FJNkEzY0xMRTZRR21HTVkzQTVXT0NHeUFpZ0FSSkEwV1dpeTF5ZmNqNy9GUWN3ZzZReS9nQmlhQUhwUnF1R2lwRnBiYlhDdjRpTkVyemt6S3NnT0VpVGJMQlVTV0s1bE5SLS1SblhRaHJCa2x5dEZqVFFzKzhHbkVnPT0%3D--2a83aeee323ad664101c3ff99d6d138e26474bdc';
        $decrypted_session = RailsMessage::decryptMessage($signed_session, $secret_key_base);

        $this->assertEquals('{"session_id":"b0008cc2b659c8bc644ca15e6b9cfa39","user_return_to":"/admin/","warden.user.user.key":["546ad8f56865720b61100000","$2a$10$6.o7x4Em.BKBoAR60R.1Pe"],"_csrf_token":"saZC3hsTaN8E8TZ+ZHSPbRvj2p0usElUF9/pIu5GPG8=","flash":{"discard":["alert"],"flashes":{"alert":""}}}', $decrypted_session);
    }

    /**
     * @expectedException InvalidMessageException
     */
    public function testInvalidMessageDecrypt()
    {
        $secret_key_base = 'f29c9a958b8c01f428fdc3559378df5ea81dabae61d93c317c4c3d5734b0c158a1ce9cc07b6ecf66862a61492b8c458c653198ab87d2141e5e1a3d80724918cc';
        $message = new RailsMessage($secret_key_base);
        $message->decrypt();
    }
}
 