<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Tests\Provider;

use ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider\XAuthConnect;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class XAuthConnectTest extends TestCase
{
    protected XAuthConnect $provider;

    protected function setUp() : void
    {
        $discoveryDoc = [
            'authorization_endpoint' => 'http://127.0.0.1:8010/xauth/authorize',
            'token_endpoint' => 'http://127.0.0.1:8010/xauth/token',
            'userinfo_endpoint' => 'http://127.0.0.1:8010/xauth/user',
            'introspection_endpoint' => 'http://127.0.0.1:8010/xauth/introspect',
            'revocation_endpoint' => 'http://127.0.0.1:8010/xauth/revoke',
            'jwks_uri' => 'http://127.0.0.1:8010/xauth/jwks',
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($discoveryDoc)),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        $this->provider = new XAuthConnect([
            'clientId'                => 'test_client_123',
            'clientSecret'            => 'test_secret_key',
            'redirectUri'             => 'http://127.0.0.1:8081/client.php',
            'issuer'                  => 'http://127.0.0.1:8010',
        ], ['httpClient' => $client]);
    }

    public function tearDown() : void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testGetBaseAccessTokenUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $this->assertEquals('http://127.0.0.1:8010/xauth/token', $url);
    }

    public function testGetResourceOwnerDetailsUrl()
    {
        $token = new AccessToken(['access_token' => 'test_token']);
        $url = $this->provider->getResourceOwnerDetailsUrl($token);
        $this->assertEquals('http://127.0.0.1:8010/xauth/user', $url);
    }

    public function testGetDefaultScopes()
    {
        $reflection = new \ReflectionClass($this->provider);
        $method = $reflection->getMethod('getDefaultScopes');
        $method->setAccessible(true);
        $this->assertEquals(['openid', 'profile:nickname', 'profile:uuid'], $method->invoke($this->provider));
    }

    public function testGetScopeSeparator()
    {
        $reflection = new \ReflectionClass($this->provider);
        $method = $reflection->getMethod('getScopeSeparator');
        $method->setAccessible(true);
        $this->assertEquals(' ', $method->invoke($this->provider));
    }

    public function testGetPkceMethod()
    {
        $reflection = new \ReflectionClass($this->provider);
        $method = $reflection->getMethod('getPkceMethod');
        $method->setAccessible(true);
        $this->assertEquals('S256', $method->invoke($this->provider));
    }

    public function testCheckResponseThrowsException()
    {
        $this->expectException(IdentityProviderException::class);

        $mock = new MockHandler([
            new Response(401, [], json_encode(['error' => 'invalid_client', 'error_description' => 'Client authentication failed']))
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    public function testCheckResponseSuccess()
    {
        $reflection = new \ReflectionClass($this->provider);
        $method = $reflection->getMethod('checkResponse');
        $method->setAccessible(true);

        $response = new Response(200, [], json_encode(['ok' => true]));
        $data = json_decode($response->getBody(), true);

        // No exception should be thrown
        $method->invokeArgs($this->provider, [$response, $data]);
        $this->assertTrue(true);
    }

    public function testGetResourceOwner()
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'sub' => '12345',
                'nickname' => 'test_user'
            ]))
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $token = new AccessToken(['access_token' => 'test_token']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals('12345', $user->getId());
        $this->assertEquals('test_user', $user->getNickname());
        $this->assertEquals([
            'sub' => '12345',
            'nickname' => 'test_user'
        ], $user->toArray());
    }

    public function testConstructorThrowsExceptionForMissingOption()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("The 'baseAuthorizationUrl' option is required or must be discoverable from the 'issuer' URL.");

        new XAuthConnect([
            // 'issuer' is intentionally omitted
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
            // 'baseAuthorizationUrl' is intentionally omitted
        ]);
    }

    public function testConstructorWithAllOptions()
    {
        $discoveryDoc = [
            'authorization_endpoint' => 'http://127.0.0.1:8010/xauth/authorize',
            'token_endpoint' => 'http://127.0.0.1:8010/xauth/token',
            'userinfo_endpoint' => 'http://127.0.0.1:8010/xauth/user',
            'introspection_endpoint' => 'http://127.0.0.1:8010/xauth/introspect',
            'revocation_endpoint' => 'http://127.0.0.1:8010/xauth/revoke',
            'jwks_uri' => 'http://127.0.0.1:8010/xauth/jwks',
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($discoveryDoc)),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        $options = [
            'clientId'                => 'test_client_123',
            'clientSecret'            => 'test_secret_key',
            'redirectUri'             => 'http://127.0.0.1:8081/client.php',
            'baseAuthorizationUrl'    => 'http://127.0.0.1:8010/xauth/authorize',
            'baseAccessTokenUrl'      => 'http://127.0.0.1:8010/xauth/token',
            'resourceOwnerDetailsUrl' => 'http://127.0.0.1:8010/xauth/user',
            'introspectUrl'           => 'http://127.0.0.1:8010/xauth/introspect',
            'revokeUrl'               => 'http://127.0.0.1:8010/xauth/revoke',
            'jwksUrl'                 => 'http://127.0.0.1:8010/xauth/jwks',
            'issuer'                  => 'http://127.0.0.1:8010',
        ];

        $provider = new XAuthConnect($options, ['httpClient' => $client]);

        $this->assertEquals($options['baseAuthorizationUrl'], $provider->baseAuthorizationUrl);
        $this->assertEquals($options['baseAccessTokenUrl'], $provider->baseAccessTokenUrl);
        $this->assertEquals($options['resourceOwnerDetailsUrl'], $provider->resourceOwnerDetailsUrl);
        $this->assertEquals($options['introspectUrl'], $provider->introspectUrl);
        $this->assertEquals($options['revokeUrl'], $provider->revokeUrl);
        $this->assertEquals($options['jwksUrl'], $provider->jwksUrl);
    }

    public function testDiscoverySuccess()
    {
        $discoveryDoc = [
            'authorization_endpoint' => 'http://discovered.com/auth',
            'token_endpoint' => 'http://discovered.com/token',
            'userinfo_endpoint' => 'http://discovered.com/user',
            'introspection_endpoint' => 'http://discovered.0.0.1:8010/xauth/introspect',
            'revocation_endpoint' => 'http://discovered.0.0.1:8010/xauth/revoke',
            'jwks_uri' => 'http://discovered.com/jwks',
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($discoveryDoc)),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        $provider = new XAuthConnect([
            'issuer'       => 'http://discovered.com',
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
        ], ['httpClient' => $client]);

        $this->assertEquals('http://discovered.com/auth', $provider->getBaseAuthorizationUrl([]));
        $this->assertEquals('http://discovered.com/token', $provider->getBaseAccessTokenUrl([]));
        $this->assertEquals('http://discovered.com/user', $provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'test'])));
    }

    public function testDiscoveryThrowsExceptionForInvalidJson()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to parse discovery document: Syntax error');

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], 'invalid json'),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        new XAuthConnect([
            'issuer'       => 'http://discovered.com',
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
        ], ['httpClient' => $client]);
    }

    public function testDiscoveryThrowsExceptionForNetworkError()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^Failed to discover endpoints: .*/');

        $mock = new MockHandler([
            new \GuzzleHttp\Exception\RequestException('Connection refused', new \GuzzleHttp\Psr7\Request('GET', 'test'))
        ]);

        $client = new HttpClient(['handler' => $mock]);

        new XAuthConnect([
            'issuer'       => 'http://discovered.com',
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
        ], ['httpClient' => $client]);
    }

    public function testIntrospectToken()
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['active' => true, 'scope' => 'openid']))
        ]);
        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $result = $this->provider->introspectToken('test-token');

        $this->assertTrue($result['active']);
        $this->assertEquals('openid', $result['scope']);
    }

    public function testRevokeToken()
    {
        $mock = new MockHandler([
            new Response(200)
        ]);
        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        // No exception should be thrown
        $this->provider->revokeToken('test-token');
        $this->assertTrue(true);
    }

    public function testRequireUrlThrowsExceptionWhenEndpointIsNull()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("The 'baseAuthorizationUrl' endpoint is not configured.");

        $this->provider->baseAuthorizationUrl = null;
        $this->provider->getBaseAuthorizationUrl();
    }

    public function testGetAccessTokenThrowsExceptionWhenIdTokenIsNotString()
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token must be a string');

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'mock_access_token',
                'id_token' => ['invalid_id_token_array'],
            ])),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
    }

    public function testGetAccessTokenThrowsExceptionWhenSessionNonceIsNotScalar()
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid nonce stored in session');

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'mock_access_token',
                'id_token' => 'mock_id_token_string',
            ])),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $_SESSION['oauth2nonce'] = ['invalid_nonce_array'];

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
    }

    public function testGetAccessTokenThrowsExceptionWhenJwksIsNotArray()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to parse JWKS document.');

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'mock_access_token',
                'id_token' => 'header.payload.signature',
            ])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode('not_an_array')),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
    }

    public function testGetAccessTokenThrowsExceptionWhenIssuerOptionIsMissingForIdToken()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("The 'issuer' option is required to validate the ID token.");

        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $publicKeyDetails = openssl_pkey_get_details($privateKey);

        $kid = 'test-key-id';
        $idToken = JWT::encode([
            'iss' => 'http://127.0.0.1:8010',
            'aud' => 'test_client_123',
            'exp' => time() + 3600,
            'sub' => 'test-sub',
        ], $privateKey, 'RS256', $kid);

        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'kid' => $kid,
                    'n' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['n']), '+/', '-_'), '='),
                    'e' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['e']), '+/', '-_'), '='),
                ]
            ]
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'mock_access_token',
                'id_token' => $idToken
            ])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($jwks)),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        $provider = new XAuthConnect([
            'clientId'                => 'test_client_123',
            'clientSecret'            => 'test_secret_key',
            'redirectUri'             => 'http://127.0.0.1:8081/client.php',
            'baseAuthorizationUrl'    => 'http://127.0.0.1:8010/xauth/authorize',
            'baseAccessTokenUrl'      => 'http://127.0.0.1:8010/xauth/token',
            'resourceOwnerDetailsUrl' => 'http://127.0.0.1:8010/xauth/user',
            'introspectUrl'           => 'http://127.0.0.1:8010/xauth/introspect',
            'revokeUrl'               => 'http://127.0.0.1:8010/xauth/revoke',
            'jwksUrl'                 => 'http://127.0.0.1:8010/xauth/jwks',
        ], ['httpClient' => $client]);

        $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
    }

    public function testIntrospectTokenThrowsExceptionForNonArrayResponse()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid introspection response.');

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode('not an array'))
        ]);
        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->introspectToken('test-token');
    }

    #[DataProvider('idTokenValidationProvider')]
    public function testIdTokenValidation(array $payload, ?string $nonce, ?string $exception, ?string $exceptionMessage)
    {
        if ($exception) {
            $this->expectException($exception);
            $this->expectExceptionMessage($exceptionMessage);
        }

        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $publicKeyDetails = openssl_pkey_get_details($privateKey);

        $kid = 'test-key-id';
        $idToken = JWT::encode($payload, $privateKey, 'RS256', $kid);

        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'kid' => $kid,
                    'n' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['n']), '+/', '-_'), '='),
                    'e' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['e']), '+/', '-_'), '='),
                ]
            ]
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'mock_access_token', 'id_token' => $idToken])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($jwks)),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        if ($nonce) {
            $_SESSION['oauth2nonce'] = $nonce;
        }

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);

        $this->assertNotNull($token->getValues()['id_token_claims']);
    }

    public static function idTokenValidationProvider() : array
    {
        $basePayload = [
            'iss' => 'http://127.0.0.1:8010',
            'aud' => 'test_client_123',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => 'test-sub',
            'nonce' => 'test-nonce'
        ];

        return [
            'valid token' => [$basePayload, 'test-nonce', null, null],
            'invalid issuer' => [array_merge($basePayload, ['iss' => 'http://invalid-issuer']), 'test-nonce', IdentityProviderException::class, 'Invalid issuer claim'],
            'invalid audience' => [array_merge($basePayload, ['aud' => 'invalid-aud']), 'test-nonce', IdentityProviderException::class, 'Invalid audience claim'],
            'missing nonce in token' => [array_merge($basePayload, ['nonce' => null]), 'test-nonce', IdentityProviderException::class, 'ID token is missing nonce claim'],
            'invalid nonce' => [array_merge($basePayload, ['nonce' => 'invalid-nonce']), 'test-nonce', IdentityProviderException::class, 'Invalid nonce'],
        ];
    }
}
