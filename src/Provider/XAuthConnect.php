<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

/**
 * Represents an XAuthConnect provider for the league/oauth2-client.
 * This provider implements the OpenID Connect flow, including discovery and ID token validation.
 */
class XAuthConnect extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public ?string $baseAuthorizationUrl = null;

    public ?string $baseAccessTokenUrl = null;

    public ?string $resourceOwnerDetailsUrl = null;

    public ?string $introspectUrl = null;

    public ?string $revokeUrl = null;

    public ?string $jwksUrl = null;

    /**
     * @var array<string, mixed>
     */
    protected array $options = [];

    /**
     * Initializes the provider with options.
     *
     * @param  array<string, mixed>      $options       Provider options, including 'issuer', 'clientId', 'clientSecret', and 'redirectUri'.
     * @param  array<string, mixed>      $collaborators An array of collaborators that may be used to override this provider's default behavior.
     * @throws \InvalidArgumentException If required options are missing.
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        $this->options = array_merge($this->options, $options);

        $issuer = $this->options['issuer'] ?? null;

        if (is_string($issuer) && '' !== $issuer) {
            $this->discoverEndpoints($issuer);
        }

        $urlOptions = [
            'baseAuthorizationUrl',
            'baseAccessTokenUrl',
            'resourceOwnerDetailsUrl',
            'introspectUrl',
            'revokeUrl',
            'jwksUrl',
        ];

        foreach ($urlOptions as $option) {
            $value = $this->options[$option] ?? null;

            if (is_string($value) && '' !== $value) {
                $this->{$option} = $value;
            }
        }

        foreach ($urlOptions as $option) {
            if (empty($this->{$option})) {
                throw new \InvalidArgumentException("The '{$option}' option is required or must be discoverable from the 'issuer' URL.");
            }
        }
    }

    /**
     * Populates OIDC endpoint properties by discovering them from the issuer's .well-known configuration.
     *
     * @param  string            $issuer The issuer URL.
     * @return void
     * @throws \RuntimeException If discovery fails or the document is invalid.
     */
    protected function discoverEndpoints(string $issuer) : void
    {
        $wellKnownUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $httpClient = $this->getHttpClient();
            $response = $httpClient->request('GET', $wellKnownUrl);
            $data = json_decode((string) $response->getBody(), true);

            if (JSON_ERROR_NONE !== json_last_error()) {
                throw new \RuntimeException('Failed to parse discovery document: ' . json_last_error_msg());
            }

            // A valid JSON value that is not an object contains no endpoints.
            $endpoints = is_array($data) ? $data : [];

            $this->baseAuthorizationUrl = self::stringOrNull($endpoints['authorization_endpoint'] ?? null);
            $this->baseAccessTokenUrl = self::stringOrNull($endpoints['token_endpoint'] ?? null);
            $this->resourceOwnerDetailsUrl = self::stringOrNull($endpoints['userinfo_endpoint'] ?? null);
            $this->introspectUrl = self::stringOrNull($endpoints['introspection_endpoint'] ?? null);
            $this->revokeUrl = self::stringOrNull($endpoints['revocation_endpoint'] ?? null);
            $this->jwksUrl = self::stringOrNull($endpoints['jwks_uri'] ?? null);

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to discover endpoints: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Returns the value when it is a string, or null otherwise.
     *
     * @param  mixed       $value The value to check.
     * @return string|null The value as a string or null.
     */
    private static function stringOrNull(mixed $value) : ?string
    {
        return is_string($value) ? $value : null;
    }

    /**
     * Returns the endpoint URL, or throws when the endpoint is not configured.
     *
     * @param  string|null       $url  The configured endpoint URL.
     * @param  string            $name The name of the endpoint option, used in the error message.
     * @return string            The configured endpoint URL.
     * @throws \RuntimeException If the endpoint URL is not configured.
     */
    private static function requireUrl(?string $url, string $name) : string
    {
        if (null === $url) {
            throw new \RuntimeException("The '{$name}' endpoint is not configured.");
        }

        return $url;
    }

    /**
     * Requests an access token and automatically validates the ID token if received.
     *
     * @param  mixed                     $grant   The grant type to use.
     * @param  array<string, mixed>      $options Additional options for the grant.
     * @return AccessTokenInterface      The access token, including validated ID token claims.
     * @throws IdentityProviderException If the ID token validation fails.
     */
    public function getAccessToken($grant, array $options = []) : AccessTokenInterface
    {
        $accessToken = parent::getAccessToken($grant, $options);

        $idToken = $accessToken->getValues()['id_token'] ?? null;

        if ($idToken) {
            if (! is_string($idToken)) {
                throw new IdentityProviderException('ID token must be a string', 0, $idToken);
            }

            $nonce = $_SESSION['oauth2nonce'] ?? null;
            unset($_SESSION['oauth2nonce']);

            if (null !== $nonce && ! is_scalar($nonce)) {
                throw new IdentityProviderException('Invalid nonce stored in session', 0, $nonce);
            }

            $validatedClaims = $this->getValidatedClaims($idToken, null === $nonce ? null : (string) $nonce);
            $values = array_merge($accessToken->getValues(), ['id_token_claims' => $validatedClaims]);
            $accessToken = new AccessToken(array_merge($accessToken->jsonSerialize(), $values));
        }

        return $accessToken;
    }

    /**
     * Performs cryptographic validation of the ID token's signature and claims.
     *
     * @param  string                    $idToken       The ID token string.
     * @param  string|null               $expectedNonce The nonce sent in the authorization request to mitigate replay attacks.
     * @return array<mixed>               The decoded and validated claims as an array.
     * @throws IdentityProviderException If any part of the validation fails.
     */
    private function getValidatedClaims(string $idToken, ?string $expectedNonce) : array
    {
        $jwks = $this->fetchJwks();
        $keys = JWK::parseKeySet($jwks);

        $decoded = JWT::decode($idToken, $keys);

        if ($decoded->iss !== $this->getConfiguredIssuer()) {
            throw new IdentityProviderException('Invalid issuer claim', 0, $idToken);
        }

        $aud = is_array($decoded->aud) ? $decoded->aud : [$decoded->aud];
        if (! in_array($this->options['clientId'], $aud, true)) {
            throw new IdentityProviderException('Invalid audience claim', 0, $idToken);
        }

        if (null !== $expectedNonce) {
            if (empty($decoded->nonce)) {
                throw new IdentityProviderException('ID token is missing nonce claim', 0, $idToken);
            }
            if ($decoded->nonce !== $expectedNonce) {
                throw new IdentityProviderException('Invalid nonce', 0, $idToken);
            }
        }

        return get_object_vars($decoded);
    }

    /**
     * Fetches the JSON Web Key Set (JWKS) from the provider's jwks_uri.
     *
     * @return array<string, mixed> The full JWKS structure as an array.
     * @throws \RuntimeException    If the JWKS document is invalid.
     */
    private function fetchJwks() : array
    {
        $response = $this->getHttpClient()->request('GET', self::requireUrl($this->jwksUrl, 'jwksUrl'));
        $data = json_decode((string) $response->getBody(), true);

        if (! is_array($data)) {
            throw new \RuntimeException('Failed to parse JWKS document.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Gets the configured issuer URL from the provider options.
     *
     * @return string                    The issuer URL.
     * @throws \InvalidArgumentException If the issuer option is missing.
     */
    private function getConfiguredIssuer() : string
    {
        $issuer = $this->options['issuer'] ?? null;

        if (! is_string($issuer) || '' === $issuer) {
            throw new \InvalidArgumentException("The 'issuer' option is required to validate the ID token.");
        }

        return $issuer;
    }

    /**
     * Gets the base URL for provider authorization.
     *
     * @return string            The authorization URL.
     * @throws \RuntimeException If the endpoint URL is not configured.
     */
    public function getBaseAuthorizationUrl() : string
    {
        return self::requireUrl($this->baseAuthorizationUrl, 'baseAuthorizationUrl');
    }

    /**
     * Gets the base URL for requesting an access token.
     *
     * @param  array<string, mixed> $params Query parameters for the token URL.
     * @return string            The access token URL.
     * @throws \RuntimeException If the endpoint URL is not configured.
     */
    public function getBaseAccessTokenUrl(array $params) : string
    {
        return self::requireUrl($this->baseAccessTokenUrl, 'baseAccessTokenUrl');
    }

    /**
     * Gets the URL for requesting the resource owner's details.
     *
     * @param  AccessToken $token The access token to use for the request.
     * @return string           The resource owner details URL.
     * @throws \RuntimeException If the endpoint URL is not configured.
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token) : string
    {
        return self::requireUrl($this->resourceOwnerDetailsUrl, 'resourceOwnerDetailsUrl');
    }

    /**
     * Gets the PKCE (Proof Key for Code Exchange) method used by the provider.
     *
     * @return string The PKCE method name.
     */
    protected function getPkceMethod() : string
    {
        return 'S256';
    }

    /**
     * Sends a request to the introspection endpoint to validate a token.
     *
     * @param  string $token The token to introspect.
     * @return array<string, mixed> The introspection result as an array.
     * @throws \RuntimeException    If the endpoint URL is not configured.
     * @throws \UnexpectedValueException If the response is not a JSON object.
     */
    public function introspectToken(string $token) : array
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, self::requireUrl($this->introspectUrl, 'introspectUrl'), null, [
            'body' => $this->buildQueryString($params)
        ]);

        $result = $this->getParsedResponse($request);

        if (! is_array($result)) {
            throw new \UnexpectedValueException('Invalid introspection response.');
        }

        /** @var array<string, mixed> $result */
        return $result;
    }

    /**
     * Sends a request to the revocation endpoint to invalidate a token.
     *
     * @param  string            $token The token to revoke.
     * @return void
     * @throws \RuntimeException If the endpoint URL is not configured.
     */
    public function revokeToken(string $token) : void
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, self::requireUrl($this->revokeUrl, 'revokeUrl'), null, [
            'body' => $this->buildQueryString($params)
        ]);

        $this->getParsedResponse($request);
    }

    /**
     * Gets the default scopes used by this provider.
     *
     * @return list<string> A list of default scopes.
     */
    protected function getDefaultScopes() : array
    {
        return ['openid', 'profile:nickname', 'profile:uuid'];
    }

    /**
     * Gets the string used to separate scopes.
     *
     * @return string The scope separator.
     */
    protected function getScopeSeparator() : string
    {
        return ' ';
    }

    /**
     * Checks the provider response for errors.
     *
     * @param  ResponseInterface         $response The provider's response.
     * @param  array<string, mixed>|string $data   The decoded response data.
     * @return void
     * @throws IdentityProviderException If the response contains an error.
     */
    protected function checkResponse(ResponseInterface $response, $data) : void
    {
        if (! empty($data['error'])) {
            $code = $response->getStatusCode();
            $error = $data['error_description'] ?? $data['error'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    /**
     * Creates a resource owner object from a successful user details request.
     *
     * @param  array<string, mixed> $response The response from the resource owner details endpoint.
     * @param  AccessToken      $token    The access token used for the request.
     * @return XAuthConnectUser The created resource owner.
     */
    protected function createResourceOwner(array $response, AccessToken $token) : XAuthConnectUser
    {
        return new XAuthConnectUser($response);
    }
}
